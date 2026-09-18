//! Windows Cloud Files provider host.
//!
//! Recovery-capable provider-state storage is intentionally not part of the public API:
//!
//! ```compile_fail
//! use hybridcipher_windows_cloud_provider::CloudStateStore;
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use fs2::FileExt;
pub use hybridcipher_provider_core::{
    local_provider_bridge, local_provider_bridge_with_compatibility, ClientMountCrypto,
    ExpectedProviderVersion, LocalProviderBridge, LocalProviderClient, MountSafetyReason,
    MountSyncRuntimeStatus, ProviderBridge, ProviderContentVersion, ProviderEntryKind,
    VaultCompatibility, VaultCompatibilityStatus,
};
use hybridcipher_provider_core::{
    EncryptedInventory, FileIdentityV1, ProviderCoreError, ProviderEntry, Result as ProviderResult,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(any(test, target_os = "windows"))]
use std::sync::atomic::{AtomicU64, AtomicU8};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    future::Future,
    io::Write,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;

mod journal_schema2;
mod pending;
mod state;
#[cfg(all(target_os = "windows", feature = "native-verification"))]
pub mod verification;
pub use pending::{PendingOperationResolution, PendingOperationState};
pub use state::{
    versioned_cache_path, CloudConflictRecord, CloudItemState, CloudRootPersistentState,
    DurableInspectionSource,
};
use state::{CloudStateStore, DurableInspection};

#[derive(Debug, Error)]
pub enum CloudProviderError {
    #[error("Windows Cloud Files API is only supported on Windows")]
    UnsupportedPlatform,
    #[error(
        "Windows Cloud Files API host is scaffolded but native callbacks are not implemented yet"
    )]
    NativeCallbacksNotImplemented,
    #[error("invalid command line: {0}")]
    InvalidCommand(String),
    #[error("invalid provider path: {0}")]
    InvalidPath(String),
    #[error("placeholder identity for {path} is {length} bytes; Windows limit is {max} bytes")]
    IdentityTooLarge {
        path: String,
        length: usize,
        max: u32,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("provider-core error: {0}")]
    ProviderCore(#[from] hybridcipher_provider_core::ProviderCoreError),
    #[error("Cloud Files callback failed: {0}")]
    Callback(String),
    #[error("Cloud Files connection is not accepting provider work during startup or shutdown")]
    StartupRecoveryUnavailable,
    #[error("Cloud Files hydration request was cancelled")]
    HydrationCancelled,
    #[error("Cloud Files hydration request exceeded its callback deadline")]
    HydrationTimedOut,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[cfg(target_os = "windows")]
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
}

pub type Result<T> = std::result::Result<T, CloudProviderError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupCleanupDisposition {
    NeverConnected,
    DisconnectConfirmed,
    DisconnectUnconfirmed,
}

#[derive(Debug, Error)]
#[error("{source}")]
pub struct CloudRootStartError {
    #[source]
    source: CloudProviderError,
    cleanup_disposition: StartupCleanupDisposition,
}

impl CloudRootStartError {
    fn new(source: CloudProviderError, cleanup_disposition: StartupCleanupDisposition) -> Self {
        Self {
            source,
            cleanup_disposition,
        }
    }

    pub fn cleanup_disposition(&self) -> StartupCleanupDisposition {
        self.cleanup_disposition
    }

    pub fn into_source(self) -> CloudProviderError {
        self.source
    }
}

impl From<CloudProviderError> for CloudRootStartError {
    fn from(source: CloudProviderError) -> Self {
        Self::new(source, StartupCleanupDisposition::NeverConnected)
    }
}

pub type CloudRootStartResult<T> = std::result::Result<T, CloudRootStartError>;

fn startup_error_after_disconnect(
    startup_error: CloudProviderError,
    disconnect_result: Result<()>,
) -> CloudRootStartError {
    match disconnect_result {
        Ok(()) => CloudRootStartError::new(
            startup_error,
            StartupCleanupDisposition::DisconnectConfirmed,
        ),
        Err(disconnect_error) => CloudRootStartError::new(
            CloudProviderError::Callback(format!(
                "{startup_error}; startup cleanup disconnect failed: {disconnect_error}"
            )),
            StartupCleanupDisposition::DisconnectUnconfirmed,
        ),
    }
}

fn orchestrate_failed_start_cleanup<Cleanup>(
    primary_error: String,
    cleanup_disposition: StartupCleanupDisposition,
    registration_preexisted: bool,
    cleanup: Cleanup,
) -> String
where
    Cleanup: FnOnce() -> Result<()>,
{
    if cleanup_disposition == StartupCleanupDisposition::DisconnectUnconfirmed {
        return format!("{primary_error}; recovery state was preserved");
    }
    if let Err(cleanup_error) = cleanup() {
        return format!(
            "{primary_error}; Cloud Files startup cleanup also failed: {cleanup_error}; \
             recovery state was preserved"
        );
    }
    if registration_preexisted {
        format!("{primary_error}; existing recovery state was preserved")
    } else {
        primary_error
    }
}

async fn orchestrate_failed_root_readiness_cleanup<Stop, StopFuture, Cleanup>(
    primary_error: String,
    registration_preexisted: bool,
    stop: Stop,
    cleanup: Cleanup,
) -> String
where
    Stop: FnOnce() -> StopFuture,
    StopFuture: Future<Output = Result<()>>,
    Cleanup: FnOnce() -> Result<()>,
{
    if let Err(stop_error) = stop().await {
        return format!(
            "{primary_error}; stopping the started Cloud Files root also failed: \
             {stop_error}; recovery state was preserved"
        );
    }
    if let Err(cleanup_error) = cleanup() {
        return format!(
            "{primary_error}; Cloud Files startup cleanup also failed: {cleanup_error}; \
             recovery state was preserved"
        );
    }
    if registration_preexisted {
        format!("{primary_error}; existing recovery state was preserved")
    } else {
        primary_error
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CloudRootConnectionState {
    Disconnected,
    Starting,
    Running,
    ShuttingDown,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CloudCallbackClass {
    Actionable,
    Notification,
    Cancellation,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum CloudCallbackKind {
    FetchData,
    ValidateData,
    FetchPlaceholders,
    Close,
    Dehydrate,
    Delete,
    Rename,
    CancelFetchData,
    CancelFetchPlaceholders,
}

impl CloudCallbackKind {
    const ALL: [Self; 9] = [
        Self::FetchData,
        Self::ValidateData,
        Self::FetchPlaceholders,
        Self::Close,
        Self::Dehydrate,
        Self::Delete,
        Self::Rename,
        Self::CancelFetchData,
        Self::CancelFetchPlaceholders,
    ];

    pub fn class(self) -> CloudCallbackClass {
        match self {
            Self::Close => CloudCallbackClass::Notification,
            Self::CancelFetchData | Self::CancelFetchPlaceholders => {
                CloudCallbackClass::Cancellation
            }
            Self::FetchData
            | Self::ValidateData
            | Self::FetchPlaceholders
            | Self::Dehydrate
            | Self::Delete
            | Self::Rename => CloudCallbackClass::Actionable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudCallbackHealth {
    pub kind: CloudCallbackKind,
    pub class: CloudCallbackClass,
    pub connection_generation: u64,
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub in_flight_count: u64,
    pub overdue_in_flight_count: u64,
    pub last_attempt_at: Option<DateTime<Utc>>,
    pub last_success_at: Option<DateTime<Utc>>,
    pub last_failure_at: Option<DateTime<Utc>>,
    pub last_failure: Option<String>,
    pub unresolved_failure: Option<String>,
    pub oldest_in_flight_started_at: Option<DateTime<Utc>>,
    pub earliest_in_flight_deadline_at: Option<DateTime<Utc>>,
    pub callback_success_observed: bool,
}

impl CloudCallbackHealth {
    fn empty(kind: CloudCallbackKind, connection_generation: u64) -> Self {
        Self {
            kind,
            class: kind.class(),
            connection_generation,
            attempt_count: 0,
            success_count: 0,
            failure_count: 0,
            in_flight_count: 0,
            overdue_in_flight_count: 0,
            last_attempt_at: None,
            last_success_at: None,
            last_failure_at: None,
            last_failure: None,
            unresolved_failure: None,
            oldest_in_flight_started_at: None,
            earliest_in_flight_deadline_at: None,
            callback_success_observed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudRootProbeKind {
    Namespace,
    Hydration,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct CloudRootProbeHealth {
    pub attempt_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub in_flight: bool,
    pub success_observed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_kind: Option<CloudRootProbeKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<String>,
}

impl CloudRootProbeHealth {
    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudTransferHealthState {
    #[default]
    NamespaceReady,
    HydrationNotObserved,
    TransferHealthy,
    TransferDegraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudHydrationExecuteResult {
    pub offset: i64,
    pub length: i64,
    pub completion_status: i32,
    pub cf_execute_succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudHydrationTransferTelemetry {
    pub requested_offset: i64,
    pub requested_length: i64,
    pub transferred_bytes: u64,
    pub elapsed_millis: u64,
    pub cancellation_observed: bool,
    pub completed_at: DateTime<Utc>,
    pub execute_results: Vec<CloudHydrationExecuteResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudRootProbeResult {
    pub root_id: Uuid,
    pub kind: CloudRootProbeKind,
    pub completed_at: DateTime<Utc>,
}

/// Serializable per-root operational state.
///
/// Native callbacks with null callback information cannot be attributed to a root and therefore
/// cannot appear here. An abrupt process abort can also prevent the final in-memory observation
/// from being captured; durable persistence is deliberately left to the persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudRootOperationalHealth {
    pub root_id: Uuid,
    pub owner_instance_id: Uuid,
    pub owner_process_id: u32,
    pub connection_generation: u64,
    pub snapshot_revision: u64,
    pub lifecycle: CloudRootConnectionState,
    pub lifecycle_changed_at: DateTime<Utc>,
    pub last_start_attempt_at: Option<DateTime<Utc>>,
    pub last_start_success_at: Option<DateTime<Utc>>,
    pub last_start_failure_at: Option<DateTime<Utc>>,
    pub last_start_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_disconnect_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_disconnect_failure: Option<String>,
    pub stop_count: u64,
    pub last_stopped_at: Option<DateTime<Utc>>,
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default = "default_health_heartbeat_stale_after_millis")]
    pub heartbeat_stale_after_millis: u64,
    pub callback_health: Vec<CloudCallbackHealth>,
    #[serde(default, skip_serializing_if = "CloudRootProbeHealth::is_empty")]
    pub active_probe: CloudRootProbeHealth,
    pub hydration_success_observed: bool,
    pub last_hydration_success_at: Option<DateTime<Utc>>,
    pub hydration_failure: Option<String>,
    pub last_hydration_failure_at: Option<DateTime<Utc>>,
    pub transfer_health_state: CloudTransferHealthState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hydration_transfer: Option<CloudHydrationTransferTelemetry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence_error: Option<String>,
    pub assessed_at: DateTime<Utc>,
    pub healthy: bool,
    pub unhealthy_evidence: Vec<String>,
}

impl CloudRootOperationalHealth {
    pub fn callback(&self, kind: CloudCallbackKind) -> Option<&CloudCallbackHealth> {
        self.callback_health
            .iter()
            .find(|health| health.kind == kind)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudRootHealthResponse {
    pub root_id: Uuid,
    pub registered: bool,
    pub operational: Option<CloudRootOperationalHealth>,
    pub lifecycle_healthy: bool,
    pub heartbeat_fresh: bool,
    pub durable_state_readable: bool,
    pub safe_to_unmount: bool,
    pub pending_mutation_count: Option<usize>,
    pub pending_refresh_count: Option<usize>,
    pub conflict_count: Option<usize>,
    pub durable_observed_at: DateTime<Utc>,
    pub registration_source: Option<DurableInspectionSource>,
    pub registration_generation: Option<u64>,
    pub health_snapshot_source: Option<DurableInspectionSource>,
    pub health_snapshot_generation: Option<u64>,
    pub health_snapshot_revision: Option<u64>,
    pub mutation_journal_source: Option<DurableInspectionSource>,
    pub mutation_journal_generation: Option<u64>,
    pub provider_state_source: Option<DurableInspectionSource>,
    pub provider_state_generation: Option<u64>,
    pub unhealthy_evidence: Vec<String>,
}

#[derive(Debug, Clone)]
struct InFlightCallbackHealth {
    started_at: DateTime<Utc>,
    deadline_at: DateTime<Utc>,
    deadline_monotonic: Option<Instant>,
}

#[derive(Debug)]
struct CallbackHealthRecord {
    health: CloudCallbackHealth,
    in_flight: BTreeMap<u64, InFlightCallbackHealth>,
    last_outcome_observation_id: Option<u64>,
}

impl CallbackHealthRecord {
    fn empty(kind: CloudCallbackKind, connection_generation: u64) -> Self {
        Self {
            health: CloudCallbackHealth::empty(kind, connection_generation),
            in_flight: BTreeMap::new(),
            last_outcome_observation_id: None,
        }
    }
}

#[derive(Debug)]
struct RootHealthTelemetryState {
    root_id: Uuid,
    owner_instance_id: Uuid,
    owner_process_id: u32,
    connection_generation: u64,
    snapshot_revision: u64,
    lifecycle: CloudRootConnectionState,
    lifecycle_changed_at: DateTime<Utc>,
    last_start_attempt_at: Option<DateTime<Utc>>,
    last_start_success_at: Option<DateTime<Utc>>,
    last_start_failure_at: Option<DateTime<Utc>>,
    last_start_failure: Option<String>,
    last_disconnect_failure_at: Option<DateTime<Utc>>,
    last_disconnect_failure: Option<String>,
    stop_count: u64,
    last_stopped_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    last_heartbeat_monotonic: Option<Instant>,
    heartbeat_stale_after: Duration,
    callbacks: BTreeMap<CloudCallbackKind, CallbackHealthRecord>,
    active_probe: CloudRootProbeHealth,
    next_observation_id: u64,
    hydration_success_observed: bool,
    last_hydration_success_at: Option<DateTime<Utc>>,
    hydration_failure: Option<String>,
    last_hydration_failure_at: Option<DateTime<Utc>>,
    last_hydration_transfer: Option<CloudHydrationTransferTelemetry>,
    health_path: Option<PathBuf>,
    persistence_error: Option<String>,
}

struct PublishedHealthMutation<T> {
    value: Option<T>,
    persistence_error: Option<CloudProviderError>,
}

impl RootHealthTelemetryState {
    fn update_latest(slot: &mut Option<DateTime<Utc>>, value: DateTime<Utc>) -> bool {
        if slot.as_ref().is_some_and(|current| *current > value) {
            false
        } else {
            *slot = Some(value);
            true
        }
    }

    fn reset_generation_observations(&mut self) {
        self.callbacks = CloudCallbackKind::ALL
            .into_iter()
            .map(|kind| {
                (
                    kind,
                    CallbackHealthRecord::empty(kind, self.connection_generation),
                )
            })
            .collect();
        self.active_probe = CloudRootProbeHealth::default();
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct RootHealthTelemetry {
    state: Arc<Mutex<RootHealthTelemetryState>>,
    _writer_claim: Option<Arc<HealthWriterClaim>>,
}

#[allow(dead_code)]
impl RootHealthTelemetry {
    fn lock_state(&self) -> std::sync::MutexGuard<'_, RootHealthTelemetryState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn new(
        root_id: Uuid,
        owner_instance_id: Uuid,
        owner_process_id: u32,
        now: DateTime<Utc>,
    ) -> Self {
        let mut state = RootHealthTelemetryState {
            root_id,
            owner_instance_id,
            owner_process_id,
            connection_generation: 0,
            snapshot_revision: 0,
            lifecycle: CloudRootConnectionState::Disconnected,
            lifecycle_changed_at: now,
            last_start_attempt_at: None,
            last_start_success_at: None,
            last_start_failure_at: None,
            last_start_failure: None,
            last_disconnect_failure_at: None,
            last_disconnect_failure: None,
            stop_count: 0,
            last_stopped_at: None,
            last_heartbeat_at: None,
            last_heartbeat_monotonic: None,
            heartbeat_stale_after: Duration::from_secs(30),
            callbacks: BTreeMap::new(),
            active_probe: CloudRootProbeHealth::default(),
            next_observation_id: 0,
            hydration_success_observed: false,
            last_hydration_success_at: None,
            hydration_failure: None,
            last_hydration_failure_at: None,
            last_hydration_transfer: None,
            health_path: None,
            persistence_error: None,
        };
        state.reset_generation_observations();
        Self {
            state: Arc::new(Mutex::new(state)),
            _writer_claim: None,
        }
    }

    fn registry_handle(&self) -> Self {
        Self {
            state: self.state.clone(),
            _writer_claim: None,
        }
    }

    fn new_persisted_starting(
        root_id: Uuid,
        owner_instance_id: Uuid,
        owner_process_id: u32,
        now: DateTime<Utc>,
        heartbeat_stale_after: Duration,
        health_path: PathBuf,
        writer_lease: &Arc<RootWriterLease>,
    ) -> Result<(Self, u64)> {
        let writer_claim = Arc::new(writer_lease.claim_health_writer(root_id, &health_path)?);
        let prior = select_newest_valid_health_snapshot(&health_path, root_id)?;
        let mut state = match prior {
            Some(prior) => RootHealthTelemetryState {
                root_id,
                owner_instance_id,
                owner_process_id,
                connection_generation: prior.connection_generation,
                snapshot_revision: prior.snapshot_revision,
                lifecycle: prior.lifecycle,
                lifecycle_changed_at: prior.lifecycle_changed_at,
                last_start_attempt_at: prior.last_start_attempt_at,
                last_start_success_at: prior.last_start_success_at,
                last_start_failure_at: prior.last_start_failure_at,
                last_start_failure: prior.last_start_failure,
                last_disconnect_failure_at: prior.last_disconnect_failure_at,
                last_disconnect_failure: prior.last_disconnect_failure,
                stop_count: prior.stop_count,
                last_stopped_at: prior.last_stopped_at,
                last_heartbeat_at: prior.last_heartbeat_at,
                last_heartbeat_monotonic: None,
                heartbeat_stale_after,
                callbacks: BTreeMap::new(),
                active_probe: CloudRootProbeHealth::default(),
                next_observation_id: 0,
                hydration_success_observed: prior.hydration_success_observed,
                last_hydration_success_at: prior.last_hydration_success_at,
                hydration_failure: prior.hydration_failure,
                last_hydration_failure_at: prior.last_hydration_failure_at,
                last_hydration_transfer: prior.last_hydration_transfer,
                health_path: Some(health_path),
                persistence_error: None,
            },
            None => {
                let telemetry = Self::new(root_id, owner_instance_id, owner_process_id, now);
                let mut state = telemetry.lock_state();
                state.heartbeat_stale_after = heartbeat_stale_after;
                state.health_path = Some(health_path);
                RootHealthTelemetryState {
                    root_id: state.root_id,
                    owner_instance_id: state.owner_instance_id,
                    owner_process_id: state.owner_process_id,
                    connection_generation: state.connection_generation,
                    snapshot_revision: state.snapshot_revision,
                    lifecycle: state.lifecycle,
                    lifecycle_changed_at: state.lifecycle_changed_at,
                    last_start_attempt_at: state.last_start_attempt_at,
                    last_start_success_at: state.last_start_success_at,
                    last_start_failure_at: state.last_start_failure_at,
                    last_start_failure: state.last_start_failure.clone(),
                    last_disconnect_failure_at: state.last_disconnect_failure_at,
                    last_disconnect_failure: state.last_disconnect_failure.clone(),
                    stop_count: state.stop_count,
                    last_stopped_at: state.last_stopped_at,
                    last_heartbeat_at: state.last_heartbeat_at,
                    last_heartbeat_monotonic: None,
                    heartbeat_stale_after,
                    callbacks: BTreeMap::new(),
                    active_probe: CloudRootProbeHealth::default(),
                    next_observation_id: 0,
                    hydration_success_observed: false,
                    last_hydration_success_at: None,
                    hydration_failure: None,
                    last_hydration_failure_at: None,
                    last_hydration_transfer: None,
                    health_path: state.health_path.clone(),
                    persistence_error: None,
                }
            }
        };
        state.connection_generation =
            state.connection_generation.checked_add(1).ok_or_else(|| {
                CloudProviderError::Callback(
                    "Cloud Files health connection generation is exhausted".into(),
                )
            })?;
        state.snapshot_revision = state.snapshot_revision.checked_add(1).ok_or_else(|| {
            CloudProviderError::Callback("Cloud Files health snapshot revision is exhausted".into())
        })?;
        state.lifecycle = CloudRootConnectionState::Starting;
        state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
        RootHealthTelemetryState::update_latest(&mut state.last_start_attempt_at, now);
        state.last_heartbeat_at = None;
        state.last_heartbeat_monotonic = None;
        state.reset_generation_observations();
        let generation = state.connection_generation;
        let snapshot = Self::snapshot_locked(&state, now, heartbeat_stale_after, Instant::now());
        Self::publish_locked(&state, &snapshot)?;
        Ok((
            Self {
                state: Arc::new(Mutex::new(state)),
                _writer_claim: Some(writer_claim),
            },
            generation,
        ))
    }

    fn publish_locked(
        state: &RootHealthTelemetryState,
        snapshot: &CloudRootOperationalHealth,
    ) -> Result<()> {
        match &state.health_path {
            Some(path) => write_health_snapshot(path, snapshot),
            None => Ok(()),
        }
    }

    fn mutate_and_publish<T>(
        &self,
        now: DateTime<Utc>,
        mutate: impl FnOnce(&mut RootHealthTelemetryState) -> Result<Option<T>>,
    ) -> Result<PublishedHealthMutation<T>> {
        let mut state = self.lock_state();
        if state.snapshot_revision == u64::MAX {
            return Err(CloudProviderError::Callback(
                "Cloud Files health snapshot revision is exhausted".into(),
            ));
        }
        let Some(value) = mutate(&mut state)? else {
            return Ok(PublishedHealthMutation {
                value: None,
                persistence_error: None,
            });
        };
        state.snapshot_revision += 1;
        state.persistence_error = None;
        let snapshot =
            Self::snapshot_locked(&state, now, state.heartbeat_stale_after, Instant::now());
        let persistence_error = Self::publish_locked(&state, &snapshot).err();
        if let Some(error) = &persistence_error {
            state.persistence_error = Some(error.to_string());
        }
        Ok(PublishedHealthMutation {
            value: Some(value),
            persistence_error,
        })
    }

    fn record_starting(&self, now: DateTime<Utc>) -> Result<u64> {
        let mutation = self.mutate_and_publish(now, |state| {
            state.connection_generation =
                state.connection_generation.checked_add(1).ok_or_else(|| {
                    CloudProviderError::Callback(
                        "Cloud Files health connection generation is exhausted".into(),
                    )
                })?;
            state.lifecycle = CloudRootConnectionState::Starting;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            RootHealthTelemetryState::update_latest(&mut state.last_start_attempt_at, now);
            state.last_heartbeat_at = None;
            state.last_heartbeat_monotonic = None;
            state.reset_generation_observations();
            Ok(Some(state.connection_generation))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        mutation
            .value
            .ok_or_else(|| CloudProviderError::Callback("starting transition was rejected".into()))
    }

    fn record_running(&self, generation: u64, now: DateTime<Utc>) -> Result<bool> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || state.lifecycle != CloudRootConnectionState::Starting
            {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Running;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            RootHealthTelemetryState::update_latest(&mut state.last_start_success_at, now);
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn record_start_failure(
        &self,
        generation: u64,
        now: DateTime<Utc>,
        failure: impl Into<String>,
    ) -> bool {
        let failure = failure.into();
        self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || !matches!(
                    state.lifecycle,
                    CloudRootConnectionState::Starting | CloudRootConnectionState::Running
                )
            {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Failed;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            if RootHealthTelemetryState::update_latest(&mut state.last_start_failure_at, now) {
                state.last_start_failure = Some(failure);
            }
            state.last_heartbeat_monotonic = None;
            Ok(Some(()))
        })
        .is_ok_and(|mutation| mutation.value.is_some())
    }

    fn record_startup_cleanup_failure(
        &self,
        generation: u64,
        now: DateTime<Utc>,
        startup_failure: impl Into<String>,
        disconnect_failure: impl Into<String>,
    ) -> bool {
        let startup_failure = startup_failure.into();
        let disconnect_failure = disconnect_failure.into();
        self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || !matches!(
                    state.lifecycle,
                    CloudRootConnectionState::Starting
                        | CloudRootConnectionState::Running
                        | CloudRootConnectionState::ShuttingDown
                        | CloudRootConnectionState::Failed
                )
            {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Failed;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            if RootHealthTelemetryState::update_latest(&mut state.last_start_failure_at, now) {
                state.last_start_failure = Some(startup_failure);
            }
            if RootHealthTelemetryState::update_latest(&mut state.last_disconnect_failure_at, now) {
                state.last_disconnect_failure = Some(disconnect_failure);
            }
            state.last_heartbeat_at = None;
            state.last_heartbeat_monotonic = None;
            Ok(Some(()))
        })
        .is_ok_and(|mutation| mutation.value.is_some())
    }

    fn record_shutting_down(&self, generation: u64, now: DateTime<Utc>) -> bool {
        self.try_record_shutting_down(generation, now)
            .unwrap_or(false)
    }

    fn try_record_shutting_down(&self, generation: u64, now: DateTime<Utc>) -> Result<bool> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation {
                return Ok(None);
            }
            if state.lifecycle == CloudRootConnectionState::ShuttingDown {
                return Ok(Some(()));
            }
            if !matches!(
                state.lifecycle,
                CloudRootConnectionState::Running | CloudRootConnectionState::Failed
            ) {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::ShuttingDown;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn record_disconnect_failure(
        &self,
        generation: u64,
        now: DateTime<Utc>,
        failure: impl Into<String>,
    ) -> bool {
        let failure = failure.into();
        self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || state.lifecycle != CloudRootConnectionState::ShuttingDown
            {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Failed;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            if RootHealthTelemetryState::update_latest(&mut state.last_disconnect_failure_at, now) {
                state.last_disconnect_failure = Some(failure);
            }
            state.last_heartbeat_at = None;
            state.last_heartbeat_monotonic = None;
            Ok(Some(()))
        })
        .is_ok_and(|mutation| mutation.value.is_some())
    }

    fn record_stopped(&self, generation: u64, now: DateTime<Utc>) -> bool {
        self.try_record_stopped(generation, now).unwrap_or(false)
    }

    fn try_record_stopped(&self, generation: u64, now: DateTime<Utc>) -> Result<bool> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation {
                return Ok(None);
            }
            if state.lifecycle == CloudRootConnectionState::Disconnected {
                return Ok(Some(()));
            }
            if !matches!(
                state.lifecycle,
                CloudRootConnectionState::Running | CloudRootConnectionState::ShuttingDown
            ) {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Disconnected;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            state.stop_count = state.stop_count.saturating_add(1);
            RootHealthTelemetryState::update_latest(&mut state.last_stopped_at, now);
            state.last_heartbeat_at = None;
            state.last_heartbeat_monotonic = None;
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn record_heartbeat(&self, generation: u64, now: DateTime<Utc>) -> bool {
        self.try_record_heartbeat_inner(generation, now, None)
            .unwrap_or(false)
    }

    fn record_heartbeat_monotonic(&self, generation: u64) -> bool {
        self.try_record_heartbeat_inner(generation, Utc::now(), Some(Instant::now()))
            .unwrap_or(false)
    }

    fn try_record_heartbeat(&self, generation: u64, now: DateTime<Utc>) -> Result<bool> {
        self.try_record_heartbeat_inner(generation, now, None)
    }

    fn try_record_heartbeat_inner(
        &self,
        generation: u64,
        now: DateTime<Utc>,
        monotonic: Option<Instant>,
    ) -> Result<bool> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || !matches!(
                    state.lifecycle,
                    CloudRootConnectionState::Starting | CloudRootConnectionState::Running
                )
            {
                return Ok(None);
            }
            RootHealthTelemetryState::update_latest(&mut state.last_heartbeat_at, now);
            state.last_heartbeat_monotonic = monotonic;
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn record_owner_lost(&self, generation: u64, now: DateTime<Utc>) -> bool {
        self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation
                || !matches!(
                    state.lifecycle,
                    CloudRootConnectionState::Starting | CloudRootConnectionState::Running
                )
            {
                return Ok(None);
            }
            state.lifecycle = CloudRootConnectionState::Failed;
            state.lifecycle_changed_at = state.lifecycle_changed_at.max(now);
            state.last_start_failure = Some("health heartbeat owner lost".to_string());
            RootHealthTelemetryState::update_latest(&mut state.last_start_failure_at, now);
            state.last_heartbeat_monotonic = None;
            Ok(Some(()))
        })
        .is_ok_and(|mutation| mutation.value.is_some())
    }

    fn begin_callback(
        &self,
        generation: u64,
        kind: CloudCallbackKind,
        started_at: DateTime<Utc>,
        deadline_at: DateTime<Utc>,
    ) -> Result<CallbackHealthObservation> {
        self.begin_callback_at(generation, kind, started_at, deadline_at, Instant::now())
    }

    fn begin_callback_at(
        &self,
        generation: u64,
        kind: CloudCallbackKind,
        started_at: DateTime<Utc>,
        deadline_at: DateTime<Utc>,
        monotonic_started_at: Instant,
    ) -> Result<CallbackHealthObservation> {
        let deadline_monotonic = deadline_at
            .signed_duration_since(started_at)
            .to_std()
            .ok()
            .and_then(|duration| monotonic_started_at.checked_add(duration));
        let mutation = self.mutate_and_publish(started_at, |state| {
            if state.connection_generation != generation
                || !matches!(
                    state.lifecycle,
                    CloudRootConnectionState::Starting | CloudRootConnectionState::Running
                )
            {
                return Ok(None);
            }
            let observation_id = state.next_observation_id;
            state.next_observation_id =
                state.next_observation_id.checked_add(1).ok_or_else(|| {
                    CloudProviderError::Callback(
                        "Cloud Files health callback observation ID is exhausted".into(),
                    )
                })?;
            let record = state
                .callbacks
                .entry(kind)
                .or_insert_with(|| CallbackHealthRecord::empty(kind, generation));
            record.health.attempt_count = record.health.attempt_count.saturating_add(1);
            RootHealthTelemetryState::update_latest(&mut record.health.last_attempt_at, started_at);
            record.in_flight.insert(
                observation_id,
                InFlightCallbackHealth {
                    started_at,
                    deadline_at,
                    deadline_monotonic,
                },
            );
            Ok(Some(observation_id))
        })?;
        Ok(CallbackHealthObservation {
            telemetry: self.clone(),
            kind,
            generation,
            observation_id: mutation.value,
            finished: false,
        })
    }

    fn finish_callback(
        &self,
        kind: CloudCallbackKind,
        generation: u64,
        observation_id: Option<u64>,
        outcome: CallbackOutcome,
        finished_at: DateTime<Utc>,
    ) -> bool {
        let Some(observation_id) = observation_id else {
            return false;
        };
        self.mutate_and_publish(finished_at, |state| {
            if state.connection_generation != generation {
                return Ok(None);
            }
            let mut hydration_outcome = None;
            {
                let Some(record) = state.callbacks.get_mut(&kind) else {
                    return Ok(None);
                };
                if record.in_flight.remove(&observation_id).is_none() {
                    return Ok(None);
                }
                let is_latest_outcome = record
                    .last_outcome_observation_id
                    .map_or(true, |latest| observation_id > latest);
                match &outcome {
                    CallbackOutcome::Succeeded => {
                        record.health.success_count = record.health.success_count.saturating_add(1);
                        RootHealthTelemetryState::update_latest(
                            &mut record.health.last_success_at,
                            finished_at,
                        );
                        record.health.callback_success_observed = true;
                        if is_latest_outcome {
                            record.last_outcome_observation_id = Some(observation_id);
                            record.health.unresolved_failure = None;
                            hydration_outcome = Some(Ok(()));
                        }
                    }
                    CallbackOutcome::Failed(failure) => {
                        record.health.failure_count = record.health.failure_count.saturating_add(1);
                        if RootHealthTelemetryState::update_latest(
                            &mut record.health.last_failure_at,
                            finished_at,
                        ) {
                            record.health.last_failure = Some(failure.clone());
                        }
                        if is_latest_outcome {
                            record.last_outcome_observation_id = Some(observation_id);
                            record.health.unresolved_failure = Some(failure.clone());
                            hydration_outcome = Some(Err(failure.clone()));
                        }
                    }
                    CallbackOutcome::Observed => {}
                }
            }
            if kind == CloudCallbackKind::FetchData {
                match &outcome {
                    CallbackOutcome::Succeeded => {
                        state.hydration_success_observed = true;
                        RootHealthTelemetryState::update_latest(
                            &mut state.last_hydration_success_at,
                            finished_at,
                        );
                    }
                    CallbackOutcome::Failed(_) => {
                        RootHealthTelemetryState::update_latest(
                            &mut state.last_hydration_failure_at,
                            finished_at,
                        );
                    }
                    CallbackOutcome::Observed => {}
                }
                match hydration_outcome {
                    Some(Ok(())) => state.hydration_failure = None,
                    Some(Err(failure)) => state.hydration_failure = Some(failure),
                    None => {}
                }
            }
            Ok(Some(()))
        })
        .is_ok_and(|mutation| mutation.value.is_some())
    }

    fn record_hydration_transfer(
        &self,
        generation: u64,
        transfer: CloudHydrationTransferTelemetry,
    ) -> Result<bool> {
        let completed_at = transfer.completed_at;
        let mutation = self.mutate_and_publish(completed_at, |state| {
            if state.connection_generation != generation {
                return Ok(None);
            }
            state.last_hydration_transfer = Some(transfer);
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn begin_active_probe(&self, now: DateTime<Utc>) -> Result<u64> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.lifecycle != CloudRootConnectionState::Running {
                return Err(CloudProviderError::Callback(
                    "active Cloud Files probe requires a running root".into(),
                ));
            }
            if state.active_probe.in_flight {
                return Err(CloudProviderError::Callback(
                    "active Cloud Files probe is already running".into(),
                ));
            }
            state.active_probe.attempt_count = state.active_probe.attempt_count.saturating_add(1);
            state.active_probe.in_flight = true;
            state.active_probe.last_attempt_at = Some(now);
            Ok(Some(state.connection_generation))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        mutation.value.ok_or_else(|| {
            CloudProviderError::Callback("active Cloud Files probe start was rejected".into())
        })
    }

    fn finish_active_probe(
        &self,
        generation: u64,
        now: DateTime<Utc>,
        outcome: std::result::Result<CloudRootProbeKind, String>,
    ) -> Result<bool> {
        let mutation = self.mutate_and_publish(now, |state| {
            if state.connection_generation != generation || !state.active_probe.in_flight {
                return Ok(None);
            }
            state.active_probe.in_flight = false;
            match outcome {
                Ok(kind) => {
                    state.active_probe.success_count =
                        state.active_probe.success_count.saturating_add(1);
                    state.active_probe.success_observed = true;
                    state.active_probe.last_kind = Some(kind);
                    state.active_probe.last_success_at = Some(now);
                    state.active_probe.last_failure = None;
                }
                Err(failure) => {
                    state.active_probe.failure_count =
                        state.active_probe.failure_count.saturating_add(1);
                    state.active_probe.last_failure_at = Some(now);
                    state.active_probe.last_failure = Some(failure);
                }
            }
            Ok(Some(()))
        })?;
        if let Some(error) = mutation.persistence_error {
            return Err(error);
        }
        Ok(mutation.value.is_some())
    }

    fn snapshot(
        &self,
        now: DateTime<Utc>,
        heartbeat_stale_after: Duration,
    ) -> CloudRootOperationalHealth {
        self.snapshot_at(now, heartbeat_stale_after, Instant::now())
    }

    fn snapshot_at(
        &self,
        now: DateTime<Utc>,
        heartbeat_stale_after: Duration,
        monotonic_now: Instant,
    ) -> CloudRootOperationalHealth {
        let state = self.lock_state();
        Self::snapshot_locked(&state, now, heartbeat_stale_after, monotonic_now)
    }

    fn snapshot_locked(
        state: &RootHealthTelemetryState,
        now: DateTime<Utc>,
        heartbeat_stale_after: Duration,
        monotonic_now: Instant,
    ) -> CloudRootOperationalHealth {
        let mut unhealthy_evidence = Vec::new();
        match state.lifecycle {
            CloudRootConnectionState::Running => match state.last_heartbeat_at {
                Some(heartbeat_at) => {
                    let stale_after = chrono::Duration::from_std(heartbeat_stale_after)
                        .unwrap_or(chrono::Duration::MAX);
                    let stale = state.last_heartbeat_monotonic.map_or_else(
                        || now.signed_duration_since(heartbeat_at) > stale_after,
                        |heartbeat_instant| {
                            monotonic_now.saturating_duration_since(heartbeat_instant)
                                > heartbeat_stale_after
                        },
                    );
                    if stale {
                        unhealthy_evidence.push("running root heartbeat is stale".to_string());
                    }
                }
                None => unhealthy_evidence.push("running root heartbeat is missing".to_string()),
            },
            CloudRootConnectionState::Failed => {
                unhealthy_evidence.push("root lifecycle is failed".to_string())
            }
            CloudRootConnectionState::ShuttingDown => {
                unhealthy_evidence.push("root lifecycle is shutting down".to_string())
            }
            CloudRootConnectionState::Starting => {
                unhealthy_evidence.push("root lifecycle is starting".to_string())
            }
            CloudRootConnectionState::Disconnected => {
                unhealthy_evidence.push("root lifecycle is disconnected".to_string())
            }
        }

        let callback_health = CloudCallbackKind::ALL
            .into_iter()
            .map(|kind| {
                let Some(record) = state.callbacks.get(&kind) else {
                    return CloudCallbackHealth::empty(kind, state.connection_generation);
                };
                let mut health = record.health.clone();
                health.in_flight_count = record.in_flight.len() as u64;
                health.overdue_in_flight_count = record
                    .in_flight
                    .values()
                    .filter(|observation| {
                        observation.deadline_monotonic.map_or_else(
                            || now > observation.deadline_at,
                            |deadline| monotonic_now > deadline,
                        )
                    })
                    .count() as u64;
                health.oldest_in_flight_started_at = record
                    .in_flight
                    .values()
                    .map(|observation| observation.started_at)
                    .min();
                health.earliest_in_flight_deadline_at = record
                    .in_flight
                    .values()
                    .map(|observation| observation.deadline_at)
                    .min();
                if let Some(failure) = &health.unresolved_failure {
                    unhealthy_evidence.push(format!("{kind:?} callback failed: {failure}"));
                }
                if health.overdue_in_flight_count > 0 {
                    unhealthy_evidence
                        .push(format!("{kind:?} callback exceeded its operation deadline"));
                }
                health
            })
            .collect();

        if state.active_probe.in_flight {
            unhealthy_evidence.push("active Cloud Files probe is still in flight".to_string());
        }
        if let Some(failure) = &state.active_probe.last_failure {
            unhealthy_evidence.push(format!("active Cloud Files probe failed: {failure}"));
        }

        if let Some(error) = &state.persistence_error {
            unhealthy_evidence.push(format!("health snapshot persistence failed: {error}"));
        }

        let transfer_health_state = if state.hydration_failure.is_some() {
            CloudTransferHealthState::TransferDegraded
        } else if state.hydration_success_observed {
            CloudTransferHealthState::TransferHealthy
        } else if state.active_probe.success_observed {
            CloudTransferHealthState::HydrationNotObserved
        } else {
            CloudTransferHealthState::NamespaceReady
        };

        CloudRootOperationalHealth {
            root_id: state.root_id,
            owner_instance_id: state.owner_instance_id,
            owner_process_id: state.owner_process_id,
            connection_generation: state.connection_generation,
            snapshot_revision: state.snapshot_revision,
            lifecycle: state.lifecycle,
            lifecycle_changed_at: state.lifecycle_changed_at,
            last_start_attempt_at: state.last_start_attempt_at,
            last_start_success_at: state.last_start_success_at,
            last_start_failure_at: state.last_start_failure_at,
            last_start_failure: state.last_start_failure.clone(),
            last_disconnect_failure_at: state.last_disconnect_failure_at,
            last_disconnect_failure: state.last_disconnect_failure.clone(),
            stop_count: state.stop_count,
            last_stopped_at: state.last_stopped_at,
            last_heartbeat_at: state.last_heartbeat_at,
            heartbeat_stale_after_millis: u64::try_from(heartbeat_stale_after.as_millis())
                .unwrap_or(u64::MAX),
            callback_health,
            active_probe: state.active_probe.clone(),
            hydration_success_observed: state.hydration_success_observed,
            last_hydration_success_at: state.last_hydration_success_at,
            hydration_failure: state.hydration_failure.clone(),
            last_hydration_failure_at: state.last_hydration_failure_at,
            transfer_health_state,
            last_hydration_transfer: state.last_hydration_transfer.clone(),
            persistence_error: state.persistence_error.clone(),
            assessed_at: now,
            healthy: unhealthy_evidence.is_empty(),
            unhealthy_evidence,
        }
    }
}

#[allow(dead_code)]
struct StartupHealthOwner {
    telemetry: RootHealthTelemetry,
    generation: u64,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    transferred: bool,
}

#[allow(dead_code)]
impl StartupHealthOwner {
    fn start(
        telemetry: RootHealthTelemetry,
        generation: u64,
        heartbeat_interval: Duration,
    ) -> Self {
        let heartbeat_state = Arc::downgrade(&telemetry.state);
        let heartbeat_writer_claim = telemetry._writer_claim.as_ref().map(Arc::downgrade);
        let interval_duration = heartbeat_interval.max(Duration::from_millis(1));
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_duration);
            loop {
                interval.tick().await;
                let Some(state) = heartbeat_state.upgrade() else {
                    break;
                };
                let writer_claim = match &heartbeat_writer_claim {
                    Some(claim) => {
                        let Some(claim) = claim.upgrade() else {
                            break;
                        };
                        Some(claim)
                    }
                    None => None,
                };
                let heartbeat_telemetry = RootHealthTelemetry {
                    state,
                    _writer_claim: writer_claim,
                };
                let _ = heartbeat_telemetry.record_heartbeat_monotonic(generation);
            }
        });
        Self {
            telemetry,
            generation,
            heartbeat: Some(heartbeat),
            transferred: false,
        }
    }

    fn mark_running_durable(&mut self, now: DateTime<Utc>) -> Result<()> {
        if self.telemetry.record_running(self.generation, now)? {
            Ok(())
        } else {
            Err(CloudProviderError::Callback(
                "health startup owner cannot transition this generation to Running".into(),
            ))
        }
    }

    fn transfer_to_runtime(&mut self) -> Result<RuntimeHealthOwner> {
        {
            let state = self.telemetry.lock_state();
            if state.connection_generation != self.generation
                || state.lifecycle != CloudRootConnectionState::Running
                || state.persistence_error.is_some()
            {
                return Err(CloudProviderError::StartupRecoveryUnavailable);
            }
        }
        let heartbeat = self
            .heartbeat
            .take()
            .ok_or(CloudProviderError::StartupRecoveryUnavailable)?;
        self.transferred = true;
        Ok(RuntimeHealthOwner {
            telemetry: self.telemetry.clone(),
            generation: self.generation,
            heartbeat: Some(heartbeat),
            disconnected: false,
        })
    }
}

impl Drop for StartupHealthOwner {
    fn drop(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
        if !self.transferred {
            let _ = self
                .telemetry
                .record_owner_lost(self.generation, Utc::now());
        }
    }
}

#[allow(dead_code)]
struct RuntimeHealthOwner {
    telemetry: RootHealthTelemetry,
    generation: u64,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
    disconnected: bool,
}

impl RuntimeHealthOwner {
    async fn shutdown_with<F, Fut>(&mut self, disconnect: F) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        if self.disconnected {
            if self.telemetry.lock_state().persistence_error.is_none() {
                return Ok(());
            }
            return self
                .telemetry
                .try_record_stopped(self.generation, Utc::now())
                .and_then(|recorded| {
                    if recorded {
                        Ok(())
                    } else {
                        Err(CloudProviderError::Callback(
                            "health runtime owner could not durably retry confirmed disconnect"
                                .into(),
                        ))
                    }
                });
        }
        if !self
            .telemetry
            .try_record_shutting_down(self.generation, Utc::now())?
        {
            return Err(CloudProviderError::Callback(
                "health runtime owner cannot transition this generation to ShuttingDown".into(),
            ));
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
        match disconnect().await {
            Ok(()) => {
                self.disconnected = true;
                if !self
                    .telemetry
                    .try_record_stopped(self.generation, Utc::now())?
                {
                    return Err(CloudProviderError::Callback(
                        "health runtime owner could not durably record confirmed disconnect".into(),
                    ));
                }
                Ok(())
            }
            Err(error) => {
                let _ = self.telemetry.record_disconnect_failure(
                    self.generation,
                    Utc::now(),
                    error.to_string(),
                );
                Err(error)
            }
        }
    }

    fn begin_drop_shutdown(&mut self) -> bool {
        if self.disconnected {
            return false;
        }
        let _ = self
            .telemetry
            .try_record_shutting_down(self.generation, Utc::now());
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
        true
    }

    fn record_drop_disconnect_failure(&self, failure: impl Into<String>) {
        let _ =
            self.telemetry
                .record_disconnect_failure(self.generation, Utc::now(), failure.into());
    }
}

impl Drop for RuntimeHealthOwner {
    fn drop(&mut self) {
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
    }
}

#[derive(Debug)]
enum CallbackOutcome {
    Succeeded,
    Failed(String),
    Observed,
}

struct CallbackOutcomeAdapter;

#[cfg(any(test, target_os = "windows"))]
fn callback_status_is_cancelled(selected_status: i32) -> bool {
    #[cfg(target_os = "windows")]
    {
        return selected_status == windows::Win32::Foundation::STATUS_CLOUD_FILE_REQUEST_ABORTED.0;
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = selected_status;
        false
    }
}

#[cfg(any(test, target_os = "windows"))]
fn actionable_callback_handler_outcome(
    handler_failure: Option<String>,
    selected_status: i32,
) -> std::result::Result<(), String> {
    if let Some(failure) = handler_failure {
        return Err(failure);
    }
    // NT_SUCCESS treats every nonnegative NTSTATUS as success, including
    // informational statuses. Negative values are warnings/errors.
    if selected_status >= 0 {
        Ok(())
    } else if callback_status_is_cancelled(selected_status) {
        // A caller closing the handle or cancelling a subrange is normal control
        // flow. Keep it in hydration telemetry without degrading provider health.
        Ok(())
    } else {
        Err(format!(
            "callback handler selected non-success NTSTATUS 0x{:08X}",
            selected_status as u32
        ))
    }
}

impl CallbackOutcomeAdapter {
    fn select(
        class: CloudCallbackClass,
        handler: std::result::Result<(), String>,
        completion: Option<std::result::Result<(), String>>,
    ) -> CallbackOutcome {
        match class {
            CloudCallbackClass::Cancellation => match handler {
                Ok(()) => CallbackOutcome::Observed,
                Err(failure) => CallbackOutcome::Failed(failure),
            },
            CloudCallbackClass::Notification => match handler {
                Ok(()) => CallbackOutcome::Succeeded,
                Err(failure) => CallbackOutcome::Failed(failure),
            },
            CloudCallbackClass::Actionable => match (handler, completion) {
                (Err(failure), _) | (Ok(()), Some(Err(failure))) => {
                    CallbackOutcome::Failed(failure)
                }
                (Ok(()), Some(Ok(()))) => CallbackOutcome::Succeeded,
                (Ok(()), None) => {
                    CallbackOutcome::Failed("completion outcome was not selected".to_string())
                }
            },
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
struct NativeConnectionBacking<T> {
    value: Option<T>,
    release_confirmed: bool,
}

#[cfg(any(test, target_os = "windows"))]
impl<T> NativeConnectionBacking<T> {
    fn new(value: T) -> Self {
        Self {
            value: Some(value),
            release_confirmed: false,
        }
    }

    #[cfg(target_os = "windows")]
    fn as_ref(&self) -> &T {
        self.value
            .as_ref()
            .expect("native connection backing is retained until final drop")
    }

    fn retain_after_unconfirmed_disconnect(&mut self) {
        if let Some(value) = self.value.take() {
            std::mem::forget(value);
        }
    }

    fn release_after_confirmed_disconnect(&mut self) {
        self.release_confirmed = true;
    }
}

#[cfg(any(test, target_os = "windows"))]
impl<T> Drop for NativeConnectionBacking<T> {
    fn drop(&mut self) {
        if !self.release_confirmed {
            self.retain_after_unconfirmed_disconnect();
        }
    }
}

fn new_health_owner_instance_id() -> Uuid {
    Uuid::new_v4()
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Default)]
struct OffThreadDisconnectAttempt {
    in_flight: Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
}

#[cfg(any(test, target_os = "windows"))]
impl OffThreadDisconnectAttempt {
    async fn run<F>(&mut self, start: F) -> std::result::Result<(), String>
    where
        F: FnOnce() -> std::result::Result<(), String> + Send + 'static,
    {
        if self.in_flight.is_none() {
            self.in_flight = Some(tokio::task::spawn_blocking(start));
        }
        // Await the stored handle by mutable reference. If this future is
        // cancelled, the handle remains owned here and the next call observes
        // the same native attempt instead of starting a concurrent duplicate.
        let joined = self
            .in_flight
            .as_mut()
            .expect("disconnect attempt must exist before awaiting")
            .await;
        self.in_flight = None;
        match joined {
            Ok(result) => result,
            Err(error) => Err(format!("native disconnect worker failed: {error}")),
        }
    }

    fn has_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }
}

#[cfg(any(test, target_os = "windows"))]
async fn drain_provider_background_tasks(
    tasks: &mut Vec<tokio::task::JoinHandle<()>>,
    timeout: Duration,
) -> Result<()> {
    for task in tasks.iter() {
        task.abort();
    }
    let deadline = tokio::time::Instant::now() + timeout;
    while !tasks.is_empty() {
        let mut task = tasks.remove(0);
        if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
            tasks.insert(0, task);
            return Err(CloudProviderError::Callback(
                "provider background tasks did not drain before the disconnect deadline".into(),
            ));
        }
    }
    Ok(())
}

#[allow(dead_code)]
struct CallbackHealthObservation {
    telemetry: RootHealthTelemetry,
    kind: CloudCallbackKind,
    generation: u64,
    observation_id: Option<u64>,
    finished: bool,
}

#[allow(dead_code)]
impl CallbackHealthObservation {
    fn finish_at(
        mut self,
        handler: std::result::Result<(), String>,
        completion: Option<std::result::Result<(), String>>,
        finished_at: DateTime<Utc>,
    ) {
        let outcome = CallbackOutcomeAdapter::select(self.kind.class(), handler, completion);
        self.telemetry.finish_callback(
            self.kind,
            self.generation,
            self.observation_id,
            outcome,
            finished_at,
        );
        self.finished = true;
    }

    fn finish_observed_at(mut self, finished_at: DateTime<Utc>) {
        self.telemetry.finish_callback(
            self.kind,
            self.generation,
            self.observation_id,
            CallbackOutcome::Observed,
            finished_at,
        );
        self.finished = true;
    }
}

#[allow(dead_code)]
trait CallbackHealthObservationResultExt {
    fn finish_at(
        self,
        handler: std::result::Result<(), String>,
        completion: Option<std::result::Result<(), String>>,
        finished_at: DateTime<Utc>,
    );
}

impl CallbackHealthObservationResultExt for Result<CallbackHealthObservation> {
    fn finish_at(
        self,
        handler: std::result::Result<(), String>,
        completion: Option<std::result::Result<(), String>>,
        finished_at: DateTime<Utc>,
    ) {
        if let Ok(observation) = self {
            observation.finish_at(handler, completion, finished_at);
        }
    }
}

impl Drop for CallbackHealthObservation {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let outcome = match self.kind.class() {
            CloudCallbackClass::Actionable
            | CloudCallbackClass::Notification
            | CloudCallbackClass::Cancellation => {
                CallbackOutcome::Failed("completion outcome was not selected".to_string())
            }
        };
        let _ = self.telemetry.finish_callback(
            self.kind,
            self.generation,
            self.observation_id,
            outcome,
            Utc::now(),
        );
        self.finished = true;
    }
}

const CLOUD_OBJECT_IDENTITY_VERSION: u16 = 2;

/// Opaque Windows placeholder identity. Paths and content revisions live in
/// durable provider state so rename never changes the identity Windows returns
/// to subsequent callbacks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudObjectIdentityV2 {
    pub version: u16,
    pub root_id: Uuid,
    pub kind: hybridcipher_provider_core::ProviderEntryKind,
    pub object_id: String,
}

impl CloudObjectIdentityV2 {
    pub fn new(
        root_id: Uuid,
        kind: hybridcipher_provider_core::ProviderEntryKind,
        object_id: impl Into<String>,
    ) -> Self {
        Self {
            version: CLOUD_OBJECT_IDENTITY_VERSION,
            root_id,
            kind,
            object_id: object_id.into(),
        }
    }

    pub fn from_legacy(
        legacy: &hybridcipher_provider_core::FileIdentityV1,
        directory_object_id: Option<Uuid>,
    ) -> Result<Self> {
        use hybridcipher_provider_core::ProviderEntryKind;
        let object_id = match legacy.kind {
            ProviderEntryKind::File => legacy.file_id.clone().ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "legacy file identity for {} has no stable file id",
                    legacy.relative_path
                ))
            })?,
            ProviderEntryKind::Directory => directory_object_id
                .map(|id| id.to_string())
                .ok_or_else(|| {
                    CloudProviderError::Callback(format!(
                        "legacy directory identity for {} has no persisted directory id",
                        legacy.relative_path
                    ))
                })?,
        };
        Ok(Self::new(legacy.root_id, legacy.kind, object_id))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let identity: Self = serde_json::from_slice(bytes)?;
        if identity.version != CLOUD_OBJECT_IDENTITY_VERSION || identity.object_id.is_empty() {
            return Err(CloudProviderError::Callback(
                "invalid Windows Cloud Files V2 identity".to_string(),
            ));
        }
        Ok(identity)
    }
}

fn parse_json_state_bytes<T: DeserializeOwned>(data: &[u8]) -> Result<(T, bool)> {
    match serde_json::from_slice(data) {
        Ok(value) => Ok((value, false)),
        Err(strict_error) => {
            let mut stream = serde_json::Deserializer::from_slice(data).into_iter::<T>();
            match stream.next() {
                Some(Ok(value)) => Ok((value, true)),
                Some(Err(_)) | None => Err(CloudProviderError::Serialization(strict_error)),
            }
        }
    }
}

fn read_json_state_file<T: DeserializeOwned + Serialize>(path: &Path) -> Result<T> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    let backup_path = path.with_file_name(format!("{file_name}.bak"));
    let primary = fs::read(path)
        .map_err(CloudProviderError::from)
        .and_then(|bytes| parse_json_state_bytes::<T>(&bytes));
    match primary {
        Ok((value, repaired)) => {
            if repaired {
                write_json_file_pretty(path, &value)?;
            }
            Ok(value)
        }
        Err(primary_error) if backup_path.exists() => {
            let (value, _) = parse_json_state_bytes::<T>(&fs::read(&backup_path)?)?;
            tracing::warn!(
                "Recovered Cloud Files state {} from backup after primary error: {}",
                path.display(),
                primary_error
            );
            quarantine_corrupt_file(path)?;
            write_json_file_pretty(path, &value)?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

fn collect_ingestion_candidates(
    root: &Path,
    is_placeholder: &impl Fn(&Path, &fs::Metadata) -> bool,
) -> Result<Vec<PathBuf>> {
    fn walk(
        root: &Path,
        output: &mut Vec<PathBuf>,
        is_placeholder: &impl Fn(&Path, &fs::Metadata) -> bool,
    ) -> Result<()> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            let placeholder = is_placeholder(&path, &metadata);
            if metadata.is_dir() {
                if !placeholder {
                    output.push(path.clone());
                }
                walk(&path, output, is_placeholder)?;
            } else if metadata.is_file() && !placeholder {
                output.push(path);
            }
        }
        Ok(())
    }

    let mut paths = Vec::new();
    walk(root, &mut paths, is_placeholder)?;
    paths.sort_by_key(|path| (usize::from(path.is_file()), path.components().count()));
    Ok(paths)
}

fn existing_file_ingestion_expected_version(
    item: &CloudItemState,
) -> Result<ExpectedProviderVersion> {
    if item.identity.kind != ProviderEntryKind::File {
        return Err(CloudProviderError::Callback(format!(
            "existing ingestion item {} is not a file",
            item.relative_path
        )));
    }
    item.content_version
        .clone()
        .map(ExpectedProviderVersion::Exact)
        .ok_or_else(|| {
            CloudProviderError::Callback(format!(
                "existing ingestion file {} has no authenticated content version",
                item.relative_path
            ))
        })
}

fn quarantine_corrupt_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    let quarantine = path.with_file_name(format!("{file_name}.corrupt-{}", Uuid::new_v4()));
    fs::rename(path, &quarantine)?;
    let _ = fs::remove_file(quarantine);
    Ok(())
}

fn write_json_file_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::new_v4()));
    let mut temp = File::create(&temp_path)?;
    temp.write_all(&serde_json::to_vec_pretty(value)?)?;
    temp.flush()?;
    temp.sync_all()?;
    // Close the replacement before the Windows atomic rename.
    drop(temp);
    let backup_path = path.with_file_name(format!("{file_name}.bak"));
    if path.exists() {
        fs::copy(path, &backup_path)?;
        // FlushFileBuffers requires a writable Windows handle; File::open is read-only.
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&backup_path)?
            .sync_all()?;
    }
    if let Err(err) = replace_file_durable(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err);
    }
    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

const LEGACY_CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION: u16 = 1;
const LEGACY_CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION_V2: u16 = 2;
const CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION: u16 = 3;
const DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS: u64 = 30_000;

fn default_health_heartbeat_stale_after_millis() -> u64 {
    DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudHealthSnapshotEnvelope {
    schema_version: u16,
    persisted_generation: u64,
    persisted_revision: u64,
    checksum_hex: String,
    snapshot: CloudRootOperationalHealth,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistedRootOperationalHealthV1 {
    root_id: Uuid,
    owner_instance_id: Uuid,
    owner_process_id: u32,
    connection_generation: u64,
    snapshot_revision: u64,
    lifecycle: CloudRootConnectionState,
    lifecycle_changed_at: DateTime<Utc>,
    last_start_attempt_at: Option<DateTime<Utc>>,
    last_start_success_at: Option<DateTime<Utc>>,
    last_start_failure_at: Option<DateTime<Utc>>,
    last_start_failure: Option<String>,
    stop_count: u64,
    last_stopped_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    callback_health: Vec<CloudCallbackHealth>,
    hydration_success_observed: bool,
    last_hydration_success_at: Option<DateTime<Utc>>,
    hydration_failure: Option<String>,
    last_hydration_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    persistence_error: Option<String>,
    assessed_at: DateTime<Utc>,
    healthy: bool,
    unhealthy_evidence: Vec<String>,
}

impl From<LegacyPersistedRootOperationalHealthV1> for CloudRootOperationalHealth {
    fn from(snapshot: LegacyPersistedRootOperationalHealthV1) -> Self {
        Self {
            root_id: snapshot.root_id,
            owner_instance_id: snapshot.owner_instance_id,
            owner_process_id: snapshot.owner_process_id,
            connection_generation: snapshot.connection_generation,
            snapshot_revision: snapshot.snapshot_revision,
            lifecycle: snapshot.lifecycle,
            lifecycle_changed_at: snapshot.lifecycle_changed_at,
            last_start_attempt_at: snapshot.last_start_attempt_at,
            last_start_success_at: snapshot.last_start_success_at,
            last_start_failure_at: snapshot.last_start_failure_at,
            last_start_failure: snapshot.last_start_failure,
            last_disconnect_failure_at: None,
            last_disconnect_failure: None,
            stop_count: snapshot.stop_count,
            last_stopped_at: snapshot.last_stopped_at,
            last_heartbeat_at: snapshot.last_heartbeat_at,
            heartbeat_stale_after_millis: DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS,
            callback_health: snapshot.callback_health,
            active_probe: CloudRootProbeHealth::default(),
            hydration_success_observed: snapshot.hydration_success_observed,
            last_hydration_success_at: snapshot.last_hydration_success_at,
            hydration_failure: snapshot.hydration_failure,
            last_hydration_failure_at: snapshot.last_hydration_failure_at,
            transfer_health_state: CloudTransferHealthState::NamespaceReady,
            last_hydration_transfer: None,
            persistence_error: snapshot.persistence_error,
            assessed_at: snapshot.assessed_at,
            healthy: snapshot.healthy,
            unhealthy_evidence: snapshot.unhealthy_evidence,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistedRootOperationalHealthV2 {
    root_id: Uuid,
    owner_instance_id: Uuid,
    owner_process_id: u32,
    connection_generation: u64,
    snapshot_revision: u64,
    lifecycle: CloudRootConnectionState,
    lifecycle_changed_at: DateTime<Utc>,
    last_start_attempt_at: Option<DateTime<Utc>>,
    last_start_success_at: Option<DateTime<Utc>>,
    last_start_failure_at: Option<DateTime<Utc>>,
    last_start_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_disconnect_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_disconnect_failure: Option<String>,
    stop_count: u64,
    last_stopped_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
    #[serde(default = "default_health_heartbeat_stale_after_millis")]
    heartbeat_stale_after_millis: u64,
    callback_health: Vec<CloudCallbackHealth>,
    #[serde(default, skip_serializing_if = "CloudRootProbeHealth::is_empty")]
    active_probe: CloudRootProbeHealth,
    hydration_success_observed: bool,
    last_hydration_success_at: Option<DateTime<Utc>>,
    hydration_failure: Option<String>,
    last_hydration_failure_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    persistence_error: Option<String>,
    assessed_at: DateTime<Utc>,
    healthy: bool,
    unhealthy_evidence: Vec<String>,
}

impl From<LegacyPersistedRootOperationalHealthV2> for CloudRootOperationalHealth {
    fn from(snapshot: LegacyPersistedRootOperationalHealthV2) -> Self {
        let transfer_health_state = if snapshot.hydration_failure.is_some() {
            CloudTransferHealthState::TransferDegraded
        } else if snapshot.hydration_success_observed {
            CloudTransferHealthState::TransferHealthy
        } else if snapshot.active_probe.success_observed {
            CloudTransferHealthState::HydrationNotObserved
        } else {
            CloudTransferHealthState::NamespaceReady
        };
        Self {
            root_id: snapshot.root_id,
            owner_instance_id: snapshot.owner_instance_id,
            owner_process_id: snapshot.owner_process_id,
            connection_generation: snapshot.connection_generation,
            snapshot_revision: snapshot.snapshot_revision,
            lifecycle: snapshot.lifecycle,
            lifecycle_changed_at: snapshot.lifecycle_changed_at,
            last_start_attempt_at: snapshot.last_start_attempt_at,
            last_start_success_at: snapshot.last_start_success_at,
            last_start_failure_at: snapshot.last_start_failure_at,
            last_start_failure: snapshot.last_start_failure,
            last_disconnect_failure_at: snapshot.last_disconnect_failure_at,
            last_disconnect_failure: snapshot.last_disconnect_failure,
            stop_count: snapshot.stop_count,
            last_stopped_at: snapshot.last_stopped_at,
            last_heartbeat_at: snapshot.last_heartbeat_at,
            heartbeat_stale_after_millis: snapshot.heartbeat_stale_after_millis,
            callback_health: snapshot.callback_health,
            active_probe: snapshot.active_probe,
            hydration_success_observed: snapshot.hydration_success_observed,
            last_hydration_success_at: snapshot.last_hydration_success_at,
            hydration_failure: snapshot.hydration_failure,
            last_hydration_failure_at: snapshot.last_hydration_failure_at,
            transfer_health_state,
            last_hydration_transfer: None,
            persistence_error: snapshot.persistence_error,
            assessed_at: snapshot.assessed_at,
            healthy: snapshot.healthy,
            unhealthy_evidence: snapshot.unhealthy_evidence,
        }
    }
}

#[cfg(test)]
impl From<&CloudRootOperationalHealth> for LegacyPersistedRootOperationalHealthV2 {
    fn from(snapshot: &CloudRootOperationalHealth) -> Self {
        Self {
            root_id: snapshot.root_id,
            owner_instance_id: snapshot.owner_instance_id,
            owner_process_id: snapshot.owner_process_id,
            connection_generation: snapshot.connection_generation,
            snapshot_revision: snapshot.snapshot_revision,
            lifecycle: snapshot.lifecycle,
            lifecycle_changed_at: snapshot.lifecycle_changed_at,
            last_start_attempt_at: snapshot.last_start_attempt_at,
            last_start_success_at: snapshot.last_start_success_at,
            last_start_failure_at: snapshot.last_start_failure_at,
            last_start_failure: snapshot.last_start_failure.clone(),
            last_disconnect_failure_at: snapshot.last_disconnect_failure_at,
            last_disconnect_failure: snapshot.last_disconnect_failure.clone(),
            stop_count: snapshot.stop_count,
            last_stopped_at: snapshot.last_stopped_at,
            last_heartbeat_at: snapshot.last_heartbeat_at,
            heartbeat_stale_after_millis: snapshot.heartbeat_stale_after_millis,
            callback_health: snapshot.callback_health.clone(),
            active_probe: snapshot.active_probe.clone(),
            hydration_success_observed: snapshot.hydration_success_observed,
            last_hydration_success_at: snapshot.last_hydration_success_at,
            hydration_failure: snapshot.hydration_failure.clone(),
            last_hydration_failure_at: snapshot.last_hydration_failure_at,
            persistence_error: snapshot.persistence_error.clone(),
            assessed_at: snapshot.assessed_at,
            healthy: snapshot.healthy,
            unhealthy_evidence: snapshot.unhealthy_evidence.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistedHealthSnapshotEnvelopeV1 {
    schema_version: u16,
    persisted_generation: u64,
    persisted_revision: u64,
    checksum_hex: String,
    snapshot: LegacyPersistedRootOperationalHealthV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyPersistedHealthSnapshotEnvelopeV2 {
    schema_version: u16,
    persisted_generation: u64,
    persisted_revision: u64,
    checksum_hex: String,
    snapshot: LegacyPersistedRootOperationalHealthV2,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudHealthSnapshotEnvelopeProbe {
    schema_version: u16,
    #[serde(rename = "persisted_generation")]
    _persisted_generation: serde::de::IgnoredAny,
    #[serde(rename = "persisted_revision")]
    _persisted_revision: serde::de::IgnoredAny,
    #[serde(rename = "checksum_hex")]
    _checksum_hex: serde::de::IgnoredAny,
    #[serde(rename = "snapshot")]
    _snapshot: serde::de::IgnoredAny,
}

fn health_snapshot_checksum(snapshot: &CloudRootOperationalHealth) -> Result<String> {
    Ok(Sha256::digest(serde_json::to_vec(snapshot)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn legacy_health_snapshot_checksum(
    snapshot: &LegacyPersistedRootOperationalHealthV1,
) -> Result<String> {
    Ok(Sha256::digest(serde_json::to_vec(snapshot)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn legacy_health_snapshot_v2_checksum(
    snapshot: &LegacyPersistedRootOperationalHealthV2,
) -> Result<String> {
    Ok(Sha256::digest(serde_json::to_vec(snapshot)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn encode_health_snapshot(snapshot: &CloudRootOperationalHealth) -> Result<Vec<u8>> {
    serde_json::to_vec_pretty(&CloudHealthSnapshotEnvelope {
        schema_version: CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION,
        persisted_generation: snapshot.connection_generation,
        persisted_revision: snapshot.snapshot_revision,
        checksum_hex: health_snapshot_checksum(snapshot)?,
        snapshot: snapshot.clone(),
    })
    .map_err(Into::into)
}

#[allow(dead_code)]
fn parse_health_snapshot_validated(
    data: &[u8],
    expected_root_id: Uuid,
) -> Result<CloudRootOperationalHealth> {
    // Health inspection must never accept a valid prefix followed by truncated or trailing data.
    let probe: CloudHealthSnapshotEnvelopeProbe = serde_json::from_slice(data)?;
    let schema_version = probe.schema_version;
    let snapshot = match schema_version {
        CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION => {
            let value: serde_json::Value = serde_json::from_slice(data)?;
            if value
                .get("snapshot")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|snapshot| !snapshot.contains_key("heartbeat_stale_after_millis"))
            {
                return Err(CloudProviderError::Callback(
                    "Cloud Files health v3 snapshot is missing heartbeat stale-after".into(),
                ));
            }
            let envelope: CloudHealthSnapshotEnvelope = serde_json::from_slice(data)?;
            if envelope.persisted_generation != envelope.snapshot.connection_generation
                || envelope.persisted_revision != envelope.snapshot.snapshot_revision
                || envelope.snapshot.root_id != expected_root_id
                || health_snapshot_checksum(&envelope.snapshot)? != envelope.checksum_hex
            {
                return Err(CloudProviderError::Callback(
                    "Cloud Files health snapshot checksum, owner root, generation, or revision mismatch"
                        .into(),
                ));
            }
            envelope.snapshot
        }
        LEGACY_CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION_V2 => {
            let envelope: LegacyPersistedHealthSnapshotEnvelopeV2 = serde_json::from_slice(data)?;
            if envelope.persisted_generation != envelope.snapshot.connection_generation
                || envelope.persisted_revision != envelope.snapshot.snapshot_revision
                || envelope.snapshot.root_id != expected_root_id
                || legacy_health_snapshot_v2_checksum(&envelope.snapshot)? != envelope.checksum_hex
            {
                return Err(CloudProviderError::Callback(
                    "Cloud Files v2 health snapshot checksum, owner root, generation, or revision mismatch"
                        .into(),
                ));
            }
            envelope.snapshot.into()
        }
        LEGACY_CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION => {
            let envelope: LegacyPersistedHealthSnapshotEnvelopeV1 = serde_json::from_slice(data)?;
            if envelope.persisted_generation != envelope.snapshot.connection_generation
                || envelope.persisted_revision != envelope.snapshot.snapshot_revision
                || envelope.snapshot.root_id != expected_root_id
                || legacy_health_snapshot_checksum(&envelope.snapshot)? != envelope.checksum_hex
            {
                return Err(CloudProviderError::Callback(
                    "Cloud Files legacy health snapshot checksum, owner root, generation, or revision mismatch"
                        .into(),
                ));
            }
            envelope.snapshot.into()
        }
        _ => {
            return Err(CloudProviderError::Callback(format!(
                "unsupported Cloud Files health snapshot schema version {schema_version}"
            )))
        }
    };
    Ok(snapshot)
}

#[allow(dead_code)]
fn parse_health_snapshot(
    data: &[u8],
    expected_root_id: Uuid,
) -> Result<CloudRootOperationalHealth> {
    parse_health_snapshot_at(data, expected_root_id, Utc::now())
}

fn parse_health_snapshot_at(
    data: &[u8],
    expected_root_id: Uuid,
    now: DateTime<Utc>,
) -> Result<CloudRootOperationalHealth> {
    Ok(reassess_persisted_health(
        parse_health_snapshot_validated(data, expected_root_id)?,
        now,
    ))
}

fn read_valid_health_snapshot(
    path: &Path,
    expected_root_id: Uuid,
) -> Option<CloudRootOperationalHealth> {
    fs::read(path)
        .ok()
        .and_then(|bytes| parse_health_snapshot_validated(&bytes, expected_root_id).ok())
}

fn health_backup_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("health.json");
    path.with_file_name(format!("{file_name}.bak"))
}

fn select_newest_valid_health_snapshot(
    path: &Path,
    expected_root_id: Uuid,
) -> Result<Option<CloudRootOperationalHealth>> {
    let primary = read_valid_health_snapshot(path, expected_root_id);
    let backup = read_valid_health_snapshot(&health_backup_path(path), expected_root_id);
    let selected = match (primary, backup) {
        (Some(primary), Some(backup)) => {
            if (backup.connection_generation, backup.snapshot_revision)
                > (primary.connection_generation, primary.snapshot_revision)
            {
                Some(backup)
            } else {
                Some(primary)
            }
        }
        (Some(primary), None) => Some(primary),
        (None, Some(backup)) => Some(backup),
        (None, None) if !path.exists() && !health_backup_path(path).exists() => None,
        (None, None) => {
            return Err(CloudProviderError::Callback(
                "Cloud Files health primary and backup are both invalid".into(),
            ))
        }
    };
    Ok(selected)
}

fn inspect_health_snapshot_sources(
    path: &Path,
    expected_root_id: Uuid,
    now: DateTime<Utc>,
) -> Result<Option<DurableInspection<CloudRootOperationalHealth>>> {
    let backup_path = health_backup_path(path);
    let primary_exists = path.exists();
    let backup_exists = backup_path.exists();
    if !primary_exists && !backup_exists {
        return Ok(None);
    }
    let inspect_one = |source_path: &Path, source| {
        fs::read(source_path)
            .ok()
            .and_then(|bytes| parse_health_snapshot_validated(&bytes, expected_root_id).ok())
            .map(|value| DurableInspection {
                generation: value.connection_generation,
                value,
                source,
            })
    };
    let primary = inspect_one(path, DurableInspectionSource::Primary);
    let backup = inspect_one(&backup_path, DurableInspectionSource::Backup);
    let selected = match (primary, backup) {
        (Some(primary), Some(backup)) => {
            if (
                backup.value.connection_generation,
                backup.value.snapshot_revision,
            ) > (
                primary.value.connection_generation,
                primary.value.snapshot_revision,
            ) {
                backup
            } else {
                primary
            }
        }
        (Some(primary), None) => primary,
        (None, Some(backup)) => backup,
        (None, None) => {
            return Err(CloudProviderError::Callback(
                "Cloud Files health primary and backup are both invalid".into(),
            ))
        }
    };
    Ok(Some(DurableInspection {
        generation: selected.generation,
        source: selected.source,
        value: reassess_persisted_health(selected.value, now),
    }))
}

fn newest_valid_health_snapshot(
    path: &Path,
    expected_root_id: Uuid,
) -> Option<CloudRootOperationalHealth> {
    let primary = read_valid_health_snapshot(path, expected_root_id);
    let backup = read_valid_health_snapshot(&health_backup_path(path), expected_root_id);
    match (primary, backup) {
        (Some(primary), Some(backup)) => {
            if (backup.connection_generation, backup.snapshot_revision)
                > (primary.connection_generation, primary.snapshot_revision)
            {
                Some(backup)
            } else {
                Some(primary)
            }
        }
        (Some(primary), None) => Some(primary),
        (None, Some(backup)) => Some(backup),
        (None, None) => None,
    }
}

struct HealthTempPath {
    path: PathBuf,
    armed: bool,
}

impl HealthTempPath {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for HealthTempPath {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn write_health_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("health.json");
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::new_v4()));
    let mut cleanup = HealthTempPath::new(temp_path.clone());
    let mut temp = File::create(&temp_path)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.sync_all()?;
    drop(temp);
    replace_file_durable(&temp_path, path)?;
    cleanup.disarm();
    if let Some(parent) = path.parent() {
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

fn write_health_snapshot(path: &Path, snapshot: &CloudRootOperationalHealth) -> Result<()> {
    let bytes = encode_health_snapshot(snapshot)?;
    if let Some(prior) = newest_valid_health_snapshot(path, snapshot.root_id) {
        write_health_bytes_atomic(&health_backup_path(path), &encode_health_snapshot(&prior)?)?;
    }
    write_health_bytes_atomic(path, &bytes)
}

fn reassess_persisted_health(
    mut snapshot: CloudRootOperationalHealth,
    now: DateTime<Utc>,
) -> CloudRootOperationalHealth {
    let mut unhealthy_evidence = Vec::new();
    match snapshot.lifecycle {
        CloudRootConnectionState::Running => match snapshot.last_heartbeat_at {
            Some(heartbeat_at) if heartbeat_at > now => {
                unhealthy_evidence.push("running root heartbeat is in the future".to_string())
            }
            Some(heartbeat_at) => {
                let stale_after = chrono::Duration::milliseconds(
                    i64::try_from(snapshot.heartbeat_stale_after_millis).unwrap_or(i64::MAX),
                );
                if now.signed_duration_since(heartbeat_at) > stale_after {
                    unhealthy_evidence.push("running root heartbeat is stale".to_string());
                }
            }
            None => unhealthy_evidence.push("running root heartbeat is missing".to_string()),
        },
        CloudRootConnectionState::Failed => {
            unhealthy_evidence.push("root lifecycle is failed".to_string())
        }
        CloudRootConnectionState::ShuttingDown => {
            unhealthy_evidence.push("root lifecycle is shutting down".to_string())
        }
        CloudRootConnectionState::Starting => {
            unhealthy_evidence.push("root lifecycle is starting".to_string())
        }
        CloudRootConnectionState::Disconnected => {
            unhealthy_evidence.push("root lifecycle is disconnected".to_string())
        }
    }
    for callback in &mut snapshot.callback_health {
        if let Some(failure) = &callback.unresolved_failure {
            unhealthy_evidence.push(format!("{:?} callback failed: {failure}", callback.kind));
        }
        if callback.in_flight_count > 0 {
            match callback.earliest_in_flight_deadline_at {
                Some(deadline) if now > deadline => {
                    callback.overdue_in_flight_count = 1;
                    unhealthy_evidence.push(format!(
                        "{:?} callback exceeded its operation deadline",
                        callback.kind
                    ));
                }
                Some(_) => callback.overdue_in_flight_count = 0,
                None => {
                    callback.overdue_in_flight_count = 1;
                    unhealthy_evidence.push(format!(
                        "{:?} callback has in-flight work without a durable deadline",
                        callback.kind
                    ));
                }
            }
        } else {
            callback.overdue_in_flight_count = 0;
        }
    }
    if snapshot.active_probe.in_flight {
        unhealthy_evidence.push("active Cloud Files probe is still in flight".to_string());
    }
    if let Some(failure) = &snapshot.active_probe.last_failure {
        unhealthy_evidence.push(format!("active Cloud Files probe failed: {failure}"));
    }
    if let Some(error) = &snapshot.persistence_error {
        unhealthy_evidence.push(format!("health snapshot persistence failed: {error}"));
    }
    snapshot.assessed_at = now;
    snapshot.healthy = unhealthy_evidence.is_empty();
    snapshot.unhealthy_evidence = unhealthy_evidence;
    snapshot
}

/// Loads the newest valid primary/backup health snapshot and may repair the primary.
///
/// This is intentionally recovery-capable and is not suitable for a read-only inspector.
#[allow(dead_code)]
fn load_health_snapshot_recovery_capable(
    path: &Path,
    expected_root_id: Uuid,
) -> Result<CloudRootOperationalHealth> {
    load_health_snapshot_recovery_capable_at(path, expected_root_id, Utc::now())
}

fn load_health_snapshot_recovery_capable_at(
    path: &Path,
    expected_root_id: Uuid,
    now: DateTime<Utc>,
) -> Result<CloudRootOperationalHealth> {
    let backup_path = health_backup_path(path);
    let primary = fs::read(path)
        .map_err(CloudProviderError::from)
        .and_then(|bytes| parse_health_snapshot_validated(&bytes, expected_root_id));
    let backup = fs::read(&backup_path)
        .map_err(CloudProviderError::from)
        .and_then(|bytes| parse_health_snapshot_validated(&bytes, expected_root_id));

    let (selected, repair_primary) = match (primary, backup) {
        (Ok(primary), Ok(backup)) => {
            if (backup.connection_generation, backup.snapshot_revision)
                > (primary.connection_generation, primary.snapshot_revision)
            {
                (backup, true)
            } else {
                (primary, false)
            }
        }
        (Ok(primary), Err(_)) => (primary, false),
        (Err(_), Ok(backup)) => (backup, true),
        (Err(primary_error), Err(_)) => return Err(primary_error),
    };

    if repair_primary {
        write_health_snapshot(path, &selected)?;
    }
    Ok(reassess_persisted_health(selected, now))
}

#[allow(dead_code)]
fn cleanup_health_snapshots(path: &Path, writer_lease: &Arc<RootWriterLease>) -> Result<()> {
    let _cleanup_claim = writer_lease.claim_health_writer(writer_lease.root_id, path)?;
    let mut snapshots = Vec::new();
    for candidate in [path.to_path_buf(), health_backup_path(path)] {
        match fs::read(&candidate) {
            Ok(bytes) => snapshots.push(parse_health_snapshot_validated(
                &bytes,
                writer_lease.root_id,
            )?),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let newest = snapshots
        .into_iter()
        .max_by_key(|snapshot| (snapshot.connection_generation, snapshot.snapshot_revision))
        .ok_or(CloudProviderError::StartupRecoveryUnavailable)?;
    if newest.lifecycle != CloudRootConnectionState::Disconnected {
        return Err(CloudProviderError::StartupRecoveryUnavailable);
    }
    let backup_path = health_backup_path(path);
    for candidate in [path, backup_path.as_path()] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn replace_file_durable(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_file_durable(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = fs::canonicalize(source)?;
    let destination = fs::canonicalize(destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Destination has no parent",
        )
    })?)?
    .join(destination.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Destination has no filename",
        )
    })?);
    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    const MAX_REPLACE_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_REPLACE_ATTEMPTS {
        let result = unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt + 1 < MAX_REPLACE_ATTEMPTS
                    && matches!(error.code().0 as u32, 0x8007_0005 | 0x8007_0020) =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("the bounded Windows replacement loop always returns")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHostConfig {
    pub user_config_dir: PathBuf,
    #[serde(default)]
    pub pipe_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudRootRegistrationKind {
    LegacyCfApi,
    ShellIntegrated,
}

impl Default for CloudRootRegistrationKind {
    fn default() -> Self {
        Self::LegacyCfApi
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloudRootRegistration {
    pub root_id: Uuid,
    pub sync_root_path: PathBuf,
    pub encrypted_root: PathBuf,
    pub display_name: String,
    #[serde(default)]
    pub registration_kind: CloudRootRegistrationKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_sync_root_id: Option<String>,
}

impl CloudRootRegistration {
    pub fn legacy_cfapi(
        root_id: Uuid,
        sync_root_path: PathBuf,
        encrypted_root: PathBuf,
        display_name: String,
    ) -> Self {
        Self {
            root_id,
            sync_root_path,
            encrypted_root,
            display_name,
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        }
    }

    pub fn shell_integrated(
        root_id: Uuid,
        sync_root_path: PathBuf,
        encrypted_root: PathBuf,
        display_name: String,
    ) -> Result<Self> {
        Ok(Self {
            root_id,
            sync_root_path,
            encrypted_root,
            display_name,
            registration_kind: CloudRootRegistrationKind::ShellIntegrated,
            shell_sync_root_id: Some(platform::current_user_shell_sync_root_id(root_id)?),
        })
    }
}

const CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION: u16 = 2;
const LEGACY_CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION: u16 = 1;

#[derive(Serialize)]
struct LegacyCloudRootRegistrationV1<'a> {
    root_id: Uuid,
    sync_root_path: &'a Path,
    encrypted_root: &'a Path,
    display_name: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudRootRegistrationEnvelope {
    schema_version: u16,
    generation: u64,
    checksum_hex: String,
    registration: CloudRootRegistration,
}

#[derive(Debug, Clone)]
struct RegistrationInspection {
    value: CloudRootRegistration,
    source: DurableInspectionSource,
    generation: u64,
    legacy: bool,
}

fn registration_checksum(registration: &CloudRootRegistration, generation: u64) -> Result<String> {
    Ok(Sha256::digest(serde_json::to_vec(&(
        CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION,
        generation,
        registration,
    ))?)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect())
}

fn legacy_registration_checksum(
    registration: &CloudRootRegistration,
    generation: u64,
) -> Result<String> {
    let legacy = LegacyCloudRootRegistrationV1 {
        root_id: registration.root_id,
        sync_root_path: &registration.sync_root_path,
        encrypted_root: &registration.encrypted_root,
        display_name: &registration.display_name,
    };
    Ok(Sha256::digest(serde_json::to_vec(&(
        LEGACY_CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION,
        generation,
        legacy,
    ))?)
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect())
}

fn encode_registration(registration: &CloudRootRegistration, generation: u64) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec_pretty(&CloudRootRegistrationEnvelope {
        schema_version: CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION,
        generation,
        checksum_hex: registration_checksum(registration, generation)?,
        registration: registration.clone(),
    })?)
}

fn parse_registration(
    data: &[u8],
    expected_root_id: Uuid,
) -> Result<(CloudRootRegistration, u64, bool)> {
    match serde_json::from_slice::<CloudRootRegistrationEnvelope>(data) {
        Ok(envelope) => {
            let checksum_matches = match envelope.schema_version {
                CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION => {
                    registration_checksum(&envelope.registration, envelope.generation)?
                        == envelope.checksum_hex
                }
                LEGACY_CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION => {
                    legacy_registration_checksum(&envelope.registration, envelope.generation)?
                        == envelope.checksum_hex
                }
                _ => false,
            };
            if envelope.registration.root_id != expected_root_id || !checksum_matches {
                return Err(CloudProviderError::Callback(
                    "Cloud Files registration schema, root, or checksum mismatch".into(),
                ));
            }
            Ok((
                envelope.registration,
                envelope.generation,
                envelope.schema_version != CLOUD_ROOT_REGISTRATION_SCHEMA_VERSION,
            ))
        }
        Err(envelope_error) => {
            let registration = serde_json::from_slice::<CloudRootRegistration>(data)
                .map_err(|_| envelope_error)?;
            if registration.root_id != expected_root_id {
                return Err(CloudProviderError::Callback(
                    "Cloud Files registration belongs to another root".into(),
                ));
            }
            Ok((registration, 0, true))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderStatus {
    pub backend: &'static str,
    pub available: bool,
    pub native_callbacks_ready: bool,
    pub running_root_count: usize,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CloudProviderStatus {
    pub fn scaffolded(available: bool, message: impl Into<String>) -> Self {
        Self::new(available, false, 0, Some(message.into()))
    }

    pub fn new(
        available: bool,
        native_callbacks_ready: bool,
        running_root_count: usize,
        message: Option<String>,
    ) -> Self {
        Self {
            backend: "windows-cloud-files",
            available,
            native_callbacks_ready,
            running_root_count,
            updated_at: Utc::now(),
            message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderSyncSummary {
    pub root_id: Uuid,
    pub requested_count: usize,
    pub processed_count: u32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehydrateRootSummary {
    pub sync_root_path: PathBuf,
    pub attempted_count: usize,
    pub dehydrated_count: usize,
    pub failed_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

type CloudCleanupPathFilter = dyn Fn(&Path) -> bool + Send + Sync;

fn no_cloud_cleanup_path_filter(_path: &Path) -> bool {
    false
}

fn validate_dehydrate_summary(summary: &DehydrateRootSummary) -> Result<()> {
    if summary.failed_count == 0
        && summary.dehydrated_count == summary.attempted_count
        && summary.failures.is_empty()
    {
        return Ok(());
    }

    let details = summary
        .failures
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let omitted = summary.failures.len().saturating_sub(3);
    let detail = if details.is_empty() {
        String::new()
    } else if omitted == 0 {
        format!(": {details}")
    } else {
        format!(": {details}; and {omitted} more")
    };
    Err(CloudProviderError::Callback(format!(
        "Cloud Files dehydration completed only {} of {} files ({} failed){detail}",
        summary.dehydrated_count, summary.attempted_count, summary.failed_count
    )))
}

fn validate_sync_root_cleanup_target(
    user_config_dir: &Path,
    registration: &CloudRootRegistration,
) -> Result<()> {
    let mount_name = registration
        .sync_root_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    if !mount_name.ends_with("_mount") {
        return Err(CloudProviderError::InvalidPath(format!(
            "refusing to clear Cloud Files path that is not a HybridCipher mount directory: {}",
            registration.sync_root_path.display()
        )));
    }

    let mount_base = registration.sync_root_path.parent().ok_or_else(|| {
        CloudProviderError::InvalidPath("Cloud Files mount directory has no parent".into())
    })?;
    if mount_base.file_name().and_then(|name| name.to_str()) != Some(".hybridcipher") {
        return Err(CloudProviderError::InvalidPath(format!(
            "refusing to clear Cloud Files path outside the HybridCipher mount base: {}",
            registration.sync_root_path.display()
        )));
    }
    let configured_base = user_config_dir
        .ancestors()
        .find(|ancestor| {
            ancestor.file_name().and_then(|name| name.to_str()) == Some(".hybridcipher")
        })
        .ok_or_else(|| {
            CloudProviderError::InvalidPath(
                "Cloud Files user configuration is not under a .hybridcipher directory".into(),
            )
        })?;
    let canonical_mount_base = fs::canonicalize(mount_base)?;
    let canonical_configured_base = fs::canonicalize(configured_base)?;
    if !paths_equal_for_platform(&canonical_mount_base, &canonical_configured_base) {
        return Err(CloudProviderError::InvalidPath(format!(
            "refusing to clear Cloud Files path outside the configured HybridCipher base: {}",
            registration.sync_root_path.display()
        )));
    }

    if registration.encrypted_root.exists() && registration.sync_root_path.exists() {
        let canonical_encrypted_root = fs::canonicalize(&registration.encrypted_root)?;
        let canonical_sync_root = fs::canonicalize(&registration.sync_root_path)?;
        if paths_equal_for_platform(&canonical_encrypted_root, &canonical_sync_root) {
            return Err(CloudProviderError::InvalidPath(
                "refusing to clear a Cloud Files mount that resolves to the encrypted source"
                    .into(),
            ));
        }
    }
    Ok(())
}

fn paths_equal_for_platform(left: &Path, right: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        left.to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .eq_ignore_ascii_case(
                right
                    .to_string_lossy()
                    .replace('/', "\\")
                    .trim_end_matches('\\'),
            )
    }
    #[cfg(not(target_os = "windows"))]
    {
        left == right
    }
}

async fn wait_for_root_dehydrated_filtered(
    sync_root_path: &Path,
    timeout: Duration,
    cleanup_path_filter: &CloudCleanupPathFilter,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        match platform::verify_root_dehydrated_filtered(sync_root_path, cleanup_path_filter) {
            Ok(()) => return Ok(()),
            Err(err) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
                tracing::debug!(
                    path = %sync_root_path.display(),
                    "Waiting for Cloud Files dehydration to become visible: {err}"
                );
            }
            Err(err) => return Err(err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CloudMutationKind {
    Writeback,
    Delete,
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMutationRecord {
    pub id: Uuid,
    #[serde(default)]
    pub sequence: u64,
    pub kind: CloudMutationKind,
    pub root_id: Uuid,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<hybridcipher_provider_core::FileIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<ProviderContentVersion>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub state: PendingOperationState,
    #[serde(default)]
    pub merged_records: u32,
    #[serde(default)]
    pub retry_after: Option<DateTime<Utc>>,
    #[serde(default)]
    pub committed_version: Option<ProviderContentVersion>,
    #[serde(default)]
    pub observed_local_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<hybridcipher_provider_core::ProviderFileErrorCode>,
}

impl CloudMutationRecord {
    fn new(
        kind: CloudMutationKind,
        root_id: Uuid,
        relative_path: impl Into<String>,
        identity: Option<hybridcipher_provider_core::FileIdentityV1>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            sequence: 0,
            kind,
            root_id,
            relative_path: relative_path.into(),
            target_relative_path: None,
            plaintext_path: None,
            target_plaintext_path: None,
            identity,
            expected_version: None,
            attempts: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
            state: PendingOperationState::Ready,
            merged_records: 0,
            retry_after: None,
            committed_version: None,
            observed_local_state: None,
            error_code: None,
        }
    }
}

fn same_pending_rename(left: &CloudMutationRecord, right: &CloudMutationRecord) -> bool {
    left.kind == CloudMutationKind::Rename
        && right.kind == CloudMutationKind::Rename
        && left.root_id == right.root_id
        && left.relative_path == right.relative_path
        && left.target_relative_path == right.target_relative_path
        && left.plaintext_path == right.plaintext_path
        && left.target_plaintext_path == right.target_plaintext_path
        && left.identity == right.identity
        && left.expected_version == right.expected_version
        && left
            .committed_version
            .as_ref()
            .zip(right.committed_version.as_ref())
            .is_none_or(|(a, b)| a == b)
        && left
            .identity
            .as_ref()
            .is_some_and(|id| id.file_id.is_some())
}

fn coalesce_matching_pending_renames(
    records: &mut Vec<CloudMutationRecord>,
    candidate: &CloudMutationRecord,
) -> Option<Uuid> {
    pending::compact(records);
    pending::matching_operation(records, candidate).map(|index| records[index].id)
}

fn unsafe_replay_error(
    record: &CloudMutationRecord,
    reason: impl std::fmt::Display,
) -> CloudProviderError {
    CloudProviderError::Callback(format!(
        "refusing unsafe replay of {:?} for {}: {reason}",
        record.kind, record.relative_path
    ))
}

fn validate_replay_relative_path(record: &CloudMutationRecord, path: &str) -> Result<String> {
    let normalized = path.replace('\\', "/");
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.split('/').any(|component| {
            component.is_empty() || component == "." || component == ".." || component.contains(':')
        })
    {
        return Err(unsafe_replay_error(
            record,
            "mutation path is not a safe relative path",
        ));
    }
    Ok(normalized)
}

fn validate_replay_plaintext_path(
    record: &CloudMutationRecord,
    sync_root: &Path,
    plaintext_path: &Path,
    expected_relative_path: &str,
) -> Result<()> {
    let expected_relative_path = validate_replay_relative_path(record, expected_relative_path)?;
    if !plaintext_path.is_absolute() {
        return Err(unsafe_replay_error(
            record,
            "plaintext path is not absolute",
        ));
    }
    let root = fs::canonicalize(sync_root)
        .map_err(|err| unsafe_replay_error(record, format!("sync root is unavailable: {err}")))?;
    let metadata = fs::symlink_metadata(plaintext_path).map_err(|err| {
        unsafe_replay_error(record, format!("plaintext path is unavailable: {err}"))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(unsafe_replay_error(
            record,
            "plaintext path is a symbolic link or reparse traversal",
        ));
    }
    let plaintext_path = fs::canonicalize(plaintext_path).map_err(|err| {
        unsafe_replay_error(record, format!("plaintext path cannot be resolved: {err}"))
    })?;
    let relative = plaintext_path.strip_prefix(&root).map_err(|_| {
        unsafe_replay_error(record, "plaintext path is outside the registered sync root")
    })?;
    let actual_relative_path = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    let matches = if cfg!(target_os = "windows") {
        actual_relative_path.eq_ignore_ascii_case(&expected_relative_path)
    } else {
        actual_relative_path == expected_relative_path
    };
    if !matches {
        return Err(unsafe_replay_error(
            record,
            "plaintext path does not match the journal path",
        ));
    }
    Ok(())
}

fn validate_replay_plaintext_paths(record: &CloudMutationRecord, sync_root: &Path) -> Result<()> {
    match record.kind {
        CloudMutationKind::Writeback => {
            let path = record.plaintext_path.as_deref().ok_or_else(|| {
                unsafe_replay_error(record, "pending writeback is missing plaintext_path")
            })?;
            validate_replay_plaintext_path(record, sync_root, path, &record.relative_path)
        }
        CloudMutationKind::Delete => Ok(()),
        CloudMutationKind::Rename => match (
            record.plaintext_path.as_deref(),
            record.target_plaintext_path.as_deref(),
            record.target_relative_path.as_deref(),
        ) {
            (Some(path), _, Some(_target)) => {
                validate_replay_plaintext_path(record, sync_root, path, &record.relative_path)
            }
            (None, Some(path), Some(target)) => {
                validate_replay_plaintext_path(record, sync_root, path, target)
            }
            (None, None, Some(_)) => Ok(()),
            (_, _, None) => Err(unsafe_replay_error(
                record,
                "pending rename is missing target_relative_path",
            )),
        },
    }
}

fn replay_expected_version(
    record: &CloudMutationRecord,
    expected_root_id: Uuid,
) -> Result<ExpectedProviderVersion> {
    if record.root_id != expected_root_id {
        return Err(unsafe_replay_error(
            record,
            "mutation record belongs to another root",
        ));
    }
    let relative_path = validate_replay_relative_path(record, &record.relative_path)?;
    if let Some(target) = record.target_relative_path.as_deref() {
        validate_replay_relative_path(record, target)?;
    }
    if let Some(identity) = record.identity.as_ref() {
        let encoded = identity
            .to_bytes()
            .map_err(|err| unsafe_replay_error(record, err))?;
        let validated = hybridcipher_provider_core::FileIdentityV1::from_bytes(&encoded)
            .map_err(|err| unsafe_replay_error(record, err))?;
        if validated.root_id != expected_root_id {
            return Err(unsafe_replay_error(
                record,
                "mutation identity belongs to another root",
            ));
        }
        if validated.relative_path != relative_path {
            return Err(unsafe_replay_error(
                record,
                "mutation identity path does not match the journal path",
            ));
        }
        let replayable_identity = match (&record.kind, validated.kind) {
            (CloudMutationKind::Rename, ProviderEntryKind::Directory) => true,
            (_, ProviderEntryKind::File) => validated.file_id.is_some(),
            _ => false,
        };
        if !replayable_identity {
            return Err(unsafe_replay_error(
                record,
                "existing-object replay requires a stable supported identity",
            ));
        }
    }
    let shape_is_valid = match record.kind {
        CloudMutationKind::Writeback => {
            record.target_relative_path.is_none() && record.target_plaintext_path.is_none()
        }
        CloudMutationKind::Delete => {
            record.identity.is_some()
                && record.plaintext_path.is_none()
                && record.target_relative_path.is_none()
                && record.target_plaintext_path.is_none()
        }
        CloudMutationKind::Rename => {
            record.identity.is_some()
                && record.target_relative_path.is_some()
                && !(record.plaintext_path.is_some() && record.target_plaintext_path.is_some())
        }
    };
    if !shape_is_valid {
        return Err(unsafe_replay_error(
            record,
            "mutation record fields do not match the operation kind",
        ));
    }
    match (
        record.identity.as_ref(),
        record.expected_version.as_ref(),
        &record.kind,
    ) {
        (None, None, CloudMutationKind::Writeback) => Ok(ExpectedProviderVersion::Absent),
        (Some(_), Some(version), _) => Ok(ExpectedProviderVersion::Exact(version.clone())),
        (Some(identity), None, CloudMutationKind::Rename)
            if identity.kind == ProviderEntryKind::Directory =>
        {
            Ok(ExpectedProviderVersion::Unchecked)
        }
        _ => Err(unsafe_replay_error(
            record,
            "mutation record has no valid exact or expected-absent precondition",
        )),
    }
}

#[derive(Debug, Default)]
#[cfg(any(test, target_os = "windows"))]
struct StartupRecoveryActivity {
    state: AtomicU8,
    changed: tokio::sync::Notify,
}

#[cfg(any(test, target_os = "windows"))]
impl StartupRecoveryActivity {
    const RUNNING: u8 = 1;
    const SHUTTING_DOWN: u8 = 2;

    fn mark_running(&self) {
        self.state.store(Self::RUNNING, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn begin_shutdown(&self) {
        self.state.store(Self::SHUTTING_DOWN, Ordering::Release);
        self.changed.notify_waiters();
    }

    fn ensure_wait_allowed(&self) -> Result<()> {
        if self.state.load(Ordering::Acquire) == Self::SHUTTING_DOWN {
            Err(CloudProviderError::StartupRecoveryUnavailable)
        } else {
            Ok(())
        }
    }

    fn ensure_running(&self) -> Result<()> {
        if self.state.load(Ordering::Acquire) == Self::RUNNING {
            Ok(())
        } else {
            Err(CloudProviderError::StartupRecoveryUnavailable)
        }
    }

    async fn wait_until_running(&self) -> Result<()> {
        loop {
            // Enable the waiter before observing the state so a transition cannot
            // be lost between the state check and awaiting the notification.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.state.load(Ordering::Acquire) {
                Self::RUNNING => return Ok(()),
                Self::SHUTTING_DOWN => return Err(CloudProviderError::StartupRecoveryUnavailable),
                _ => notified.await,
            }
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
async fn begin_provider_shutdown_barrier(
    activity: &StartupRecoveryActivity,
    operation_lock: &tokio::sync::Mutex<()>,
) {
    // Queue behind work that already passed the running-state check. Once the
    // lock is ours, switching the gate prevents later callbacks from starting.
    let _operation = operation_lock.lock().await;
    activity.begin_shutdown();
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMutationJournal {
    pub root_id: Uuid,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub next_sequence: u64,
    #[serde(default)]
    pub records: Vec<CloudMutationRecord>,
    pub updated_at: DateTime<Utc>,
}

impl CloudMutationJournal {
    fn empty(root_id: Uuid) -> Self {
        Self {
            root_id,
            generation: 0,
            next_sequence: 0,
            records: Vec::new(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CloudMutationJournalEnvelope {
    schema_version: u16,
    generation: u64,
    checksum_hex: String,
    journal: CloudMutationJournal,
}

const CLOUD_MUTATION_JOURNAL_SCHEMA_VERSION: u16 = 3;

fn mutation_journal_checksum(journal: &CloudMutationJournal) -> Result<String> {
    Ok(Sha256::digest(serde_json::to_vec(journal)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn parse_checked_mutation_journal(data: &[u8], root_id: Uuid) -> Result<CloudMutationJournal> {
    if serde_json::from_slice::<serde_json::Value>(data)?["schema_version"].as_u64() == Some(2) {
        return journal_schema2::decode(data, root_id);
    }
    let envelope: CloudMutationJournalEnvelope = serde_json::from_slice(data)?;
    if envelope.schema_version != CLOUD_MUTATION_JOURNAL_SCHEMA_VERSION
        || envelope.generation != envelope.journal.generation
        || envelope.journal.root_id != root_id
        || mutation_journal_checksum(&envelope.journal)? != envelope.checksum_hex
    {
        return Err(CloudProviderError::Callback(
            "Cloud Files mutation journal checksum or generation mismatch".into(),
        ));
    }
    Ok(envelope.journal)
}

fn parse_mutation_journal(data: &[u8], root_id: Uuid) -> Result<CloudMutationJournal> {
    if serde_json::from_slice::<CloudMutationJournalEnvelope>(data).is_ok() {
        return parse_checked_mutation_journal(data, root_id);
    }

    let (journal, _) = parse_json_state_bytes::<CloudMutationJournal>(data)?;
    if journal.root_id != root_id {
        return Err(CloudProviderError::Callback(
            "Cloud Files mutation journal belongs to another root".into(),
        ));
    }
    Ok(journal)
}

fn inspect_mutation_journal_sources(
    path: &Path,
    root_id: Uuid,
) -> Result<Option<DurableInspection<CloudMutationJournal>>> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("journal.json");
    let backup_path = path.with_file_name(format!("{file_name}.bak"));
    if !path.exists() && !backup_path.exists() {
        return Ok(None);
    }
    let inspect_one = |source_path: &Path, source| {
        fs::read(source_path)
            .ok()
            .and_then(|bytes| parse_checked_mutation_journal(&bytes, root_id).ok())
            .map(|value| DurableInspection {
                generation: value.generation,
                value,
                source,
            })
    };
    let primary = inspect_one(path, DurableInspectionSource::Primary);
    let backup = inspect_one(&backup_path, DurableInspectionSource::Backup);
    match (primary, backup) {
        (Some(primary), Some(backup)) => Ok(Some(if backup.generation > primary.generation {
            backup
        } else {
            primary
        })),
        (Some(primary), None) => Ok(Some(primary)),
        (None, Some(backup)) => Ok(Some(backup)),
        (None, None) => Err(CloudProviderError::Callback(format!(
            "no valid Cloud Files mutation journal generation remains for {root_id}"
        ))),
    }
}

/// Repairs or republishes mutation-journal state.
///
/// Production callers must validate and hold the exact root writer lease before invoking this
/// helper. Read-only status and health APIs use `inspect_mutation_journal_sources` instead.
fn recover_mutation_journal_for_writer(path: &Path, root_id: Uuid) -> Result<CloudMutationJournal> {
    let backup = path.with_file_name(format!(
        "{}.bak",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("journal.json")
    ));
    if !path.exists() && !backup.exists() {
        return Ok(CloudMutationJournal::empty(root_id));
    }
    let (mut journal, original, from_backup) = match inspect_mutation_journal_sources(path, root_id)
    {
        Ok(Some(value)) => {
            let from_backup = value.source == DurableInspectionSource::Backup;
            let bytes = fs::read(if from_backup { &backup } else { path })?;
            (value.value, bytes, from_backup)
        }
        _ => {
            let primary = fs::read(path).ok().and_then(|bytes| {
                parse_mutation_journal(&bytes, root_id)
                    .ok()
                    .map(|value| (value, bytes, false))
            });
            match primary {
                Some(value) => value,
                None => {
                    let bytes = fs::read(&backup)?;
                    (parse_mutation_journal(&bytes, root_id)?, bytes, true)
                }
            }
        }
    };
    let old_sequence = journal.next_sequence;
    journal.next_sequence = old_sequence.max(
        journal
            .records
            .iter()
            .map(|r| r.sequence)
            .max()
            .unwrap_or(0),
    );
    let migrated = serde_json::from_slice::<serde_json::Value>(&original)?["schema_version"]
        .as_u64()
        != Some(3);
    let changed = pending::compact(&mut journal.records);
    if migrated || changed || from_backup || old_sequence != journal.next_sequence {
        let parent = fs::canonicalize(
            path.parent()
                .ok_or_else(|| CloudProviderError::InvalidPath("Journal has no parent".into()))?,
        )?;
        let snapshot = parent
            .join(path.file_name().unwrap())
            .with_extension(format!("recovery-{:x}.json", Sha256::digest(&original)));
        // The root writer lease excludes competing migrations. Publish and flush
        // the original snapshot before replacing any recoverable journal bytes.
        if snapshot.exists() {
            if fs::read(&snapshot)? != original {
                return Err(CloudProviderError::Callback(
                    "Journal recovery snapshot does not match its digest".into(),
                ));
            }
        } else {
            write_health_bytes_atomic(&snapshot, &original)?;
        }
        if from_backup
            && path.exists()
            && fs::read(path)
                .ok()
                .and_then(|bytes| parse_mutation_journal(&bytes, root_id).ok())
                .is_none()
        {
            quarantine_corrupt_file(path)?;
        }
        journal.updated_at = Utc::now();
        write_mutation_journal(path, &journal)?;
        journal.generation = journal.generation.saturating_add(1);
    }
    Ok(journal)
}
fn write_mutation_journal(path: &Path, journal: &CloudMutationJournal) -> Result<()> {
    let mut journal = journal.clone();
    journal.generation = journal.generation.saturating_add(1);
    let envelope = CloudMutationJournalEnvelope {
        schema_version: CLOUD_MUTATION_JOURNAL_SCHEMA_VERSION,
        generation: journal.generation,
        checksum_hex: mutation_journal_checksum(&journal)?,
        journal,
    };
    write_json_file_pretty(path, &envelope)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CloudRuntimePaths {
    status_path: PathBuf,
    journal_path: PathBuf,
    #[allow(dead_code)]
    health_path: PathBuf,
    state_path: PathBuf,
    cache_dir: PathBuf,
    writer_lock_path: PathBuf,
}

#[derive(Debug)]
struct RootWriterLease {
    file: File,
    root_id: Uuid,
    lock_path: PathBuf,
    health_writer_claimed: AtomicBool,
}

impl RootWriterLease {
    fn acquire(root_id: Uuid, path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;
        file.try_lock_exclusive().map_err(|err| {
            CloudProviderError::Callback(format!(
                "Cloud Files root {root_id} is already owned by another provider process: {err}"
            ))
        })?;
        Ok(Self {
            file,
            root_id,
            lock_path: path.to_path_buf(),
            health_writer_claimed: AtomicBool::new(false),
        })
    }

    fn validate_health_path(&self, root_id: Uuid, health_path: &Path) -> Result<()> {
        let expected_lock_name = format!("cloud_provider_writer_{root_id}.lock");
        let expected_health_name = format!("cloud_provider_health_{root_id}.json");
        let lock_matches = self.root_id == root_id
            && self
                .lock_path
                .file_name()
                .is_some_and(|name| name == expected_lock_name.as_str());
        let expected_health_path = self.lock_path.with_file_name(expected_health_name);
        if !lock_matches || expected_health_path != health_path {
            return Err(CloudProviderError::StartupRecoveryUnavailable);
        }
        Ok(())
    }

    fn claim_health_writer(
        self: &Arc<Self>,
        root_id: Uuid,
        health_path: &Path,
    ) -> Result<HealthWriterClaim> {
        self.validate_health_path(root_id, health_path)?;
        self.health_writer_claimed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| CloudProviderError::StartupRecoveryUnavailable)?;
        Ok(HealthWriterClaim {
            writer_lease: self.clone(),
        })
    }
}

#[derive(Debug)]
struct HealthWriterClaim {
    writer_lease: Arc<RootWriterLease>,
}

impl Drop for HealthWriterClaim {
    fn drop(&mut self) {
        self.writer_lease
            .health_writer_claimed
            .store(false, Ordering::Release);
    }
}

impl Drop for RootWriterLease {
    fn drop(&mut self) {
        if let Err(err) = FileExt::unlock(&self.file) {
            tracing::warn!("Failed to release Cloud Files root writer lease: {err}");
        }
    }
}

async fn wait_for_writer_quiescence(lease: &Arc<RootWriterLease>, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while Arc::strong_count(lease) != 1 {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10).min(deadline - now)).await;
    }
    true
}

fn prepare_plaintext_cache_for_startup(paths: &CloudRuntimePaths) -> Result<()> {
    if paths.cache_dir.exists() {
        fs::remove_dir_all(&paths.cache_dir)?;
    }
    fs::create_dir_all(&paths.cache_dir)?;
    platform::restrict_hydration_temp_directory(&paths.cache_dir)?;
    Ok(())
}

/// Removes every Explorer sync-root registration owned by HybridCipher for the current user.
///
/// This is intentionally independent of the durable per-root registry so uninstall can clean up
/// an Explorer entry even when the application registry was damaged or already removed.
pub fn unregister_all_hybridcipher_shell_roots() -> Result<usize> {
    platform::unregister_all_shell_roots()
}

#[cfg(any(test, target_os = "windows"))]
fn complete_callback_once<T, E>(
    result: std::result::Result<T, E>,
    failure: T,
    complete: impl FnOnce(T),
) -> Option<E> {
    match result {
        Ok(completion) => {
            complete(completion);
            None
        }
        Err(err) => {
            complete(failure);
            Some(err)
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
const HYDRATION_TRANSFER_CHUNK_BYTES: usize = 4 * 1024 * 1024;
#[cfg(any(test, target_os = "windows"))]
const HYDRATION_TRANSFER_ALIGNMENT_BYTES: usize = 4096;

#[cfg(any(test, target_os = "windows"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HydrationRequest {
    offset: u64,
    length: usize,
}

#[cfg(any(test, target_os = "windows"))]
fn validate_hydration_request(
    logical_size: u64,
    offset: i64,
    requested_length: i64,
) -> Result<HydrationRequest> {
    let offset = u64::try_from(offset).map_err(|_| {
        CloudProviderError::Callback("Cloud Files hydration offset is negative".into())
    })?;
    let length = usize::try_from(requested_length).map_err(|_| {
        CloudProviderError::Callback("Cloud Files hydration length is negative or too large".into())
    })?;
    if length == 0 {
        return Err(CloudProviderError::Callback(
            "Cloud Files hydration range must be nonzero".into(),
        ));
    }
    let end = offset.checked_add(length as u64).ok_or_else(|| {
        CloudProviderError::Callback("Cloud Files hydration range overflows".into())
    })?;
    if end > logical_size {
        return Err(CloudProviderError::Callback(format!(
            "Cloud Files hydration range {offset}..{end} exceeds logical file size {logical_size}"
        )));
    }
    let alignment = HYDRATION_TRANSFER_ALIGNMENT_BYTES as u64;
    if offset % alignment != 0 {
        return Err(CloudProviderError::Callback(format!(
            "Cloud Files hydration offset {offset} is not 4-KiB aligned"
        )));
    }
    if end != logical_size && (length as u64) % alignment != 0 {
        return Err(CloudProviderError::Callback(format!(
            "Cloud Files hydration length {length} is not 4-KiB aligned and does not end at EOF"
        )));
    }
    Ok(HydrationRequest { offset, length })
}

#[cfg(any(test, target_os = "windows"))]
fn hydration_completion_range(file_size: i64, offset: i64, length: i64) -> (i64, i64) {
    let alignment = HYDRATION_TRANSFER_ALIGNMENT_BYTES as i64;
    if offset >= 0
        && length > 0
        && offset < file_size.max(1)
        && offset % alignment == 0
        && offset
            .checked_add(length)
            .is_some_and(|end| length % alignment == 0 || end >= file_size.max(0))
    {
        return (offset, length);
    }

    // Malformed callback parameters still need a valid nonzero failure completion.
    // Use the aligned page containing the requested offset, clamped to the file.
    let safe_size = file_size.max(1);
    let clamped_offset = offset.max(0).min(safe_size - 1);
    let aligned_offset = clamped_offset - clamped_offset % alignment;
    (aligned_offset, alignment)
}

#[cfg(any(test, target_os = "windows"))]
fn hydration_transfer_ranges(request: HydrationRequest) -> Result<Vec<HydrationRequest>> {
    let mut ranges = Vec::new();
    let mut offset = request.offset;
    let mut remaining = request.length;
    while remaining > 0 {
        let mut length = remaining.min(HYDRATION_TRANSFER_CHUNK_BYTES);
        if length < remaining {
            length -= length % HYDRATION_TRANSFER_ALIGNMENT_BYTES;
        }
        if length == 0 {
            return Err(CloudProviderError::Callback(
                "Cloud Files hydration transfer could not make aligned progress".into(),
            ));
        }
        ranges.push(HydrationRequest { offset, length });
        offset = offset
            .checked_add(length as u64)
            .ok_or_else(|| CloudProviderError::Callback("hydration range overflows".into()))?;
        remaining -= length;
    }
    Ok(ranges)
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Default, Clone)]
struct HydrationCancellationRegistry {
    inner: Arc<HydrationCancellationRegistryInner>,
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Default)]
struct HydrationCancellationRegistryInner {
    next_id: AtomicU64,
    active: Mutex<Vec<HydrationCancellationEntry>>,
}

#[cfg(any(test, target_os = "windows"))]
struct HydrationCancellationEntry {
    id: u64,
    transfer_key: i64,
    offset: i64,
    length: i64,
    state: Arc<HydrationCancellationState>,
}

#[cfg(any(test, target_os = "windows"))]
struct HydrationCancellationState {
    offset: i64,
    length: i64,
    cancelled_ranges: Mutex<Vec<(i64, i64)>>,
    notify: tokio::sync::Notify,
}

#[cfg(any(test, target_os = "windows"))]
struct HydrationCancellationToken {
    id: u64,
    registry: std::sync::Weak<HydrationCancellationRegistryInner>,
    state: Arc<HydrationCancellationState>,
}

#[cfg(any(test, target_os = "windows"))]
impl HydrationCancellationRegistry {
    fn register(&self, transfer_key: i64, offset: i64, length: i64) -> HydrationCancellationToken {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let state = Arc::new(HydrationCancellationState {
            offset,
            length,
            cancelled_ranges: Mutex::new(Vec::new()),
            notify: tokio::sync::Notify::new(),
        });
        self.inner
            .active
            .lock()
            .expect("hydration cancellation registry lock poisoned")
            .push(HydrationCancellationEntry {
                id,
                transfer_key,
                offset,
                length,
                state: state.clone(),
            });
        HydrationCancellationToken {
            id,
            registry: Arc::downgrade(&self.inner),
            state,
        }
    }

    fn cancel_intersecting(&self, transfer_key: i64, offset: i64, length: i64) -> usize {
        let Some(cancel_end) = offset
            .checked_add(length)
            .filter(|_| offset >= 0 && length > 0)
        else {
            return 0;
        };
        let active = self
            .inner
            .active
            .lock()
            .expect("hydration cancellation registry lock poisoned");
        let mut cancelled_count = 0;
        for entry in active.iter().filter(|entry| {
            entry.transfer_key == transfer_key
                && entry
                    .offset
                    .checked_add(entry.length)
                    .filter(|_| entry.offset >= 0 && entry.length > 0)
                    .is_some_and(|request_end| entry.offset < cancel_end && offset < request_end)
        }) {
            let intersection_start = entry.offset.max(offset);
            let request_end = entry.offset.saturating_add(entry.length);
            let intersection_end = request_end.min(cancel_end);
            if entry
                .state
                .record_cancelled_range(intersection_start, intersection_end)
            {
                cancelled_count += 1;
                entry.state.notify.notify_waiters();
            }
        }
        cancelled_count
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.inner
            .active
            .lock()
            .expect("hydration cancellation registry lock poisoned")
            .len()
    }
}

#[cfg(any(test, target_os = "windows"))]
impl HydrationCancellationToken {
    fn is_cancelled(&self) -> bool {
        self.state.is_fully_cancelled()
    }

    fn cancelled_ranges(&self, offset: i64, length: i64) -> Vec<(i64, i64)> {
        self.state.cancelled_ranges(offset, length)
    }

    #[cfg(target_os = "windows")]
    async fn cancelled(&self) {
        loop {
            let notified = self.state.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
impl HydrationCancellationState {
    fn record_cancelled_range(&self, start: i64, end: i64) -> bool {
        if start < 0 || end <= start {
            return false;
        }
        let mut ranges = self
            .cancelled_ranges
            .lock()
            .expect("hydration cancellation range lock poisoned");
        let before = ranges.clone();
        ranges.push((start, end));
        ranges.sort_unstable_by_key(|range| range.0);
        let mut merged: Vec<(i64, i64)> = Vec::with_capacity(ranges.len());
        for (range_start, range_end) in ranges.drain(..) {
            if let Some(last) = merged.last_mut() {
                if range_start <= last.1 {
                    last.1 = last.1.max(range_end);
                    continue;
                }
            }
            merged.push((range_start, range_end));
        }
        let changed = merged != before;
        *ranges = merged;
        changed
    }

    fn cancelled_ranges(&self, offset: i64, length: i64) -> Vec<(i64, i64)> {
        let Some(end) = offset
            .checked_add(length)
            .filter(|_| offset >= 0 && length > 0)
        else {
            return Vec::new();
        };
        self.cancelled_ranges
            .lock()
            .expect("hydration cancellation range lock poisoned")
            .iter()
            .filter_map(|(start, range_end)| {
                let clipped_start = (*start).max(offset);
                let clipped_end = (*range_end).min(end);
                (clipped_end > clipped_start).then_some((clipped_start, clipped_end))
            })
            .collect()
    }

    fn is_fully_cancelled(&self) -> bool {
        self.cancelled_ranges(self.offset, self.length)
            .first()
            .is_some_and(|(start, end)| {
                *start <= self.offset && *end >= self.offset.saturating_add(self.length)
            })
    }
}

#[cfg(any(test, target_os = "windows"))]
impl Drop for HydrationCancellationToken {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        if let Ok(mut active) = registry.active.lock() {
            active.retain(|entry| entry.id != self.id);
        };
    }
}

#[cfg(any(test, target_os = "windows"))]
#[derive(Clone)]
struct HydrationWorkerGate {
    permits: Arc<tokio::sync::Semaphore>,
}

#[cfg(any(test, target_os = "windows"))]
impl HydrationWorkerGate {
    async fn begin(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.permits
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| CloudProviderError::Callback("hydration worker queue closed".into()))
    }

    #[cfg(test)]
    fn try_begin(&self) -> Result<tokio::sync::OwnedSemaphorePermit> {
        self.permits.clone().try_acquire_owned().map_err(|_| {
            CloudProviderError::Callback("both Cloud Files hydration workers are active".into())
        })
    }
}

#[cfg(any(test, target_os = "windows"))]
impl Default for HydrationWorkerGate {
    fn default() -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }
}

#[cfg(any(test, target_os = "windows"))]
struct HydrationTemporaryFile {
    path: Option<PathBuf>,
    _writer_lease: Arc<RootWriterLease>,
}

#[cfg(any(test, target_os = "windows"))]
impl HydrationTemporaryFile {
    fn new(path: PathBuf, writer_lease: Arc<RootWriterLease>) -> Self {
        Self {
            path: Some(path),
            _writer_lease: writer_lease,
        }
    }

    #[cfg(target_os = "windows")]
    fn path(&self) -> &Path {
        self.path
            .as_deref()
            .expect("hydration temporary path consumed before publication")
    }
}

#[cfg(any(test, target_os = "windows"))]
impl Drop for HydrationTemporaryFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if let Err(err) = fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(
                        "Failed to remove abandoned hydration plaintext {}: {err}",
                        path.display()
                    );
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct CloudPlaceholderEntry {
    entry: ProviderEntry,
    identity: CloudObjectIdentityV2,
    dirty: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalRefreshDisposition {
    Safe,
    Missing,
    Busy,
    Dirty,
}

const WINDOWS_PROJECTED_COMPONENT_MAX_UTF16: usize = 240;

fn windows_component_is_compatible(component: &str) -> bool {
    if component.is_empty() || component == "." || component == ".." {
        return false;
    }
    if component.ends_with(['.', ' '])
        || component.chars().any(|character| {
            character <= '\u{1f}'
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
        })
        || component.encode_utf16().count() > WINDOWS_PROJECTED_COMPONENT_MAX_UTF16
    {
        return false;
    }

    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !matches!(
            stem.as_str(),
            "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
        )
        && !matches!(
            stem.as_str(),
            "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9"
        )
}

fn truncate_utf16(value: &str, max_units: usize) -> String {
    let mut units = 0usize;
    value
        .chars()
        .take_while(|character| {
            let next = units.saturating_add(character.len_utf16());
            if next > max_units {
                false
            } else {
                units = next;
                true
            }
        })
        .collect()
}

fn windows_projected_component(component: &str, source_prefix: &str) -> String {
    if windows_component_is_compatible(component) {
        return component.to_string();
    }

    let mut sanitized = component
        .chars()
        .map(|character| {
            if character <= '\u{1f}'
                || matches!(
                    character,
                    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*'
                )
            {
                '_'
            } else {
                character
            }
        })
        .collect::<String>();
    while sanitized.ends_with(['.', ' ']) {
        sanitized.pop();
    }
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        sanitized = "unnamed".to_string();
    }

    let digest = Sha256::digest(source_prefix.as_bytes());
    let suffix = format!(
        "~hc-{}",
        digest[..6]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let extension = sanitized
        .rfind('.')
        .filter(|index| *index > 0 && *index + 1 < sanitized.len())
        .map(|index| sanitized.split_at(index));
    let (stem, extension) = extension
        .map(|(stem, extension)| (stem, extension))
        .unwrap_or((sanitized.as_str(), ""));
    let reserved_units = suffix.encode_utf16().count() + extension.encode_utf16().count();
    let available = WINDOWS_PROJECTED_COMPONENT_MAX_UTF16.saturating_sub(reserved_units);
    let mut stem = truncate_utf16(stem, available);
    if stem.is_empty() {
        stem = "unnamed".to_string();
    }
    format!("{stem}{suffix}{extension}")
}

fn project_windows_inventory(
    mut entries: Vec<ProviderEntry>,
) -> ProviderResult<Vec<ProviderEntry>> {
    let mut projected_sources = HashMap::new();
    for entry in &mut entries {
        let normalized = entry.relative_path.replace('\\', "/");
        let mut source_prefix = String::new();
        let projected = normalized
            .split('/')
            .filter(|component| !component.is_empty())
            .map(|component| {
                if !source_prefix.is_empty() {
                    source_prefix.push('/');
                }
                source_prefix.push_str(component);
                windows_projected_component(component, &source_prefix)
            })
            .collect::<Vec<_>>()
            .join("/");
        if projected != normalized {
            tracing::warn!(
                "Projecting Windows-incompatible provider path '{}' as '{}'",
                normalized,
                projected
            );
        }
        let key = projected.to_lowercase();
        if let Some(existing) = projected_sources.insert(key, normalized.clone()) {
            if existing != normalized {
                return Err(ProviderCoreError::InvalidIdentity(format!(
                    "provider paths '{existing}' and '{normalized}' map to the same Windows path '{projected}'"
                )));
            }
        }
        entry.relative_path = projected;
        entry.identity = FileIdentityV1::new(
            entry.root_id,
            entry.kind,
            entry.relative_path.clone(),
            entry.identity.file_id.clone(),
            entry.identity.epoch_id,
        );
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

struct WindowsProjectedBridge {
    inner: Arc<dyn ProviderBridge>,
}

impl WindowsProjectedBridge {
    fn new(inner: Arc<dyn ProviderBridge>) -> Self {
        Self { inner }
    }

    async fn raw_entry_for_identity(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identity: &FileIdentityV1,
    ) -> ProviderResult<Option<ProviderEntry>> {
        let raw_entries = self.inner.inventory(root_id, encrypted_root).await?;
        if let Some(file_id) = identity.file_id.as_ref() {
            return Ok(raw_entries.into_iter().find(|entry| {
                entry.root_id == root_id
                    && entry.kind == identity.kind
                    && entry.identity.file_id.as_ref() == Some(file_id)
            }));
        }
        let projected = project_windows_inventory(raw_entries)?;
        Ok(projected
            .into_iter()
            .find(|entry| entry.identity == *identity))
    }

    async fn translate_existing_mutation(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        requested_relative_path: &str,
        identity: Option<&FileIdentityV1>,
    ) -> ProviderResult<(String, Option<FileIdentityV1>)> {
        let Some(projected_identity) = identity else {
            return Ok((requested_relative_path.to_string(), None));
        };
        let raw_entry = self
            .raw_entry_for_identity(root_id, encrypted_root, projected_identity)
            .await?
            .ok_or_else(|| ProviderCoreError::ContentConflict {
                path: projected_identity.relative_path.clone(),
                expected: None,
                actual: None,
            })?;
        let relative_path =
            if requested_relative_path.replace('\\', "/") == projected_identity.relative_path {
                raw_entry.relative_path.clone()
            } else {
                requested_relative_path.to_string()
            };
        Ok((relative_path, Some(raw_entry.identity)))
    }

    fn project_entry(entry: ProviderEntry) -> ProviderResult<ProviderEntry> {
        project_windows_inventory(vec![entry]).map(|mut entries| entries.remove(0))
    }
}

#[async_trait]
impl ProviderBridge for WindowsProjectedBridge {
    fn compatibility_status(&self) -> Option<VaultCompatibilityStatus> {
        self.inner.compatibility_status()
    }
    fn set_legacy_compatibility(&self, enabled: bool) -> ProviderResult<VaultCompatibilityStatus> {
        self.inner.set_legacy_compatibility(enabled)
    }
    fn is_path_excluded(&self, encrypted_root: &Path, relative_path: &Path) -> bool {
        self.inner.is_path_excluded(encrypted_root, relative_path)
    }

    async fn inventory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> ProviderResult<Vec<ProviderEntry>> {
        project_windows_inventory(self.inner.inventory(root_id, encrypted_root).await?)
    }

    async fn hydrate_file(&self, entry: &ProviderEntry) -> ProviderResult<Vec<u8>> {
        self.inner.hydrate_file(entry).await
    }

    async fn hydrate_file_range(
        &self,
        entry: &ProviderEntry,
        offset: u64,
        length: usize,
    ) -> ProviderResult<zeroize::Zeroizing<Vec<u8>>> {
        self.inner.hydrate_file_range(entry, offset, length).await
    }

    async fn hydrate_file_to_path(
        &self,
        entry: &ProviderEntry,
        output_path: &Path,
    ) -> ProviderResult<()> {
        self.inner.hydrate_file_to_path(entry, output_path).await
    }

    async fn writeback_file(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
    ) -> ProviderResult<ProviderEntry> {
        let (raw_relative_path, raw_identity) = self
            .translate_existing_mutation(root_id, encrypted_root, relative_path, existing_identity)
            .await?;
        Self::project_entry(
            self.inner
                .writeback_file(
                    root_id,
                    encrypted_root,
                    &raw_relative_path,
                    plaintext_path,
                    raw_identity.as_ref(),
                )
                .await?,
        )
    }

    async fn writeback_file_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
        expected_version: &ExpectedProviderVersion,
    ) -> ProviderResult<ProviderEntry> {
        let (raw_relative_path, raw_identity) = self
            .translate_existing_mutation(root_id, encrypted_root, relative_path, existing_identity)
            .await?;
        Self::project_entry(
            self.inner
                .writeback_file_checked(
                    root_id,
                    encrypted_root,
                    &raw_relative_path,
                    plaintext_path,
                    raw_identity.as_ref(),
                    expected_version,
                )
                .await?,
        )
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> ProviderResult<ProviderEntry> {
        Self::project_entry(
            self.inner
                .create_directory(root_id, encrypted_root, relative_path)
                .await?,
        )
    }

    async fn delete_entry(
        &self,
        encrypted_root: &Path,
        identity: &FileIdentityV1,
    ) -> ProviderResult<()> {
        let raw = self
            .raw_entry_for_identity(identity.root_id, encrypted_root, identity)
            .await?;
        match raw {
            Some(entry) => {
                self.inner
                    .delete_entry(encrypted_root, &entry.identity)
                    .await
            }
            None => Ok(()),
        }
    }

    async fn delete_entry_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identity: &FileIdentityV1,
        expected_version: &ExpectedProviderVersion,
    ) -> ProviderResult<()> {
        let raw = self
            .raw_entry_for_identity(root_id, encrypted_root, identity)
            .await?;
        match raw {
            Some(entry) => {
                self.inner
                    .delete_entry_checked(
                        root_id,
                        encrypted_root,
                        &entry.identity,
                        expected_version,
                    )
                    .await
            }
            None => Ok(()),
        }
    }

    async fn lookup_identity(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> ProviderResult<Option<FileIdentityV1>> {
        let normalized = identifier.trim_start_matches('/').replace('\\', "/");
        let parsed_identity = serde_json::from_str::<FileIdentityV1>(identifier).ok();
        Ok(self
            .inventory(root_id, encrypted_root)
            .await?
            .into_iter()
            .find(|entry| {
                entry.relative_path == normalized
                    || parsed_identity
                        .as_ref()
                        .is_some_and(|identity| entry.identity == *identity)
            })
            .map(|entry| entry.identity))
    }

    async fn rename_entry(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> ProviderResult<Option<ProviderEntry>> {
        let raw = self
            .raw_entry_for_identity(root_id, encrypted_root, source_identity)
            .await?
            .ok_or_else(|| ProviderCoreError::ContentConflict {
                path: source_identity.relative_path.clone(),
                expected: None,
                actual: None,
            })?;
        self.inner
            .rename_entry(
                root_id,
                encrypted_root,
                &raw.identity,
                target_relative_path,
                target_plaintext_path,
            )
            .await?
            .map(Self::project_entry)
            .transpose()
    }

    async fn rename_entry_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
        expected_version: &ExpectedProviderVersion,
    ) -> ProviderResult<Option<ProviderEntry>> {
        let raw = self
            .raw_entry_for_identity(root_id, encrypted_root, source_identity)
            .await?
            .ok_or_else(|| ProviderCoreError::ContentConflict {
                path: source_identity.relative_path.clone(),
                expected: None,
                actual: None,
            })?;
        self.inner
            .rename_entry_checked(
                root_id,
                encrypted_root,
                &raw.identity,
                target_relative_path,
                target_plaintext_path,
                expected_version,
            )
            .await?
            .map(Self::project_entry)
            .transpose()
    }
}

struct RemoteReconciliationPlan {
    proposed_state: CloudRootPersistentState,
    placeholders: Vec<CloudPlaceholderEntry>,
    placeholder_guard_ids: HashMap<String, String>,
    inventory_entries: Vec<(String, ProviderEntry)>,
    removed_items: Vec<(String, String)>,
}

fn plan_remote_reconciliation(
    registration: &CloudRootRegistration,
    current_state: &CloudRootPersistentState,
    current_inventory: &HashMap<String, ProviderEntry>,
    entries: &[ProviderEntry],
    local_dispositions: &HashMap<String, LocalRefreshDisposition>,
) -> Result<RemoteReconciliationPlan> {
    let mut proposed_state = current_state.clone();
    let mut placeholders = Vec::new();
    let mut placeholder_guard_ids = HashMap::new();
    let mut inventory_entries = Vec::with_capacity(entries.len());
    let mut removed_items = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for entry in entries {
        let stable_object_id = match entry.kind {
            ProviderEntryKind::File => entry.identity.file_id.clone(),
            ProviderEntryKind::Directory => entry.identity.file_id.clone().or_else(|| {
                current_state
                    .directory_ids
                    .get(&entry.relative_path)
                    .map(Uuid::to_string)
            }),
        };
        let previous_object_id = stable_object_id
            .as_ref()
            .filter(|object_id| current_state.items.contains_key(*object_id))
            .cloned()
            .or_else(|| {
                current_state
                    .items
                    .iter()
                    .find(|(_, item)| {
                        item.relative_path == entry.relative_path
                            && item.identity.kind == entry.kind
                    })
                    .map(|(object_id, _)| object_id.clone())
            });
        let previous = previous_object_id
            .as_ref()
            .and_then(|object_id| current_state.items.get(object_id))
            .cloned();
        let disposition = previous_object_id
            .as_ref()
            .and_then(|object_id| local_dispositions.get(object_id))
            .copied()
            .unwrap_or(LocalRefreshDisposition::Safe);
        let disposition = if previous.as_ref().is_some_and(|item| item.dirty) {
            LocalRefreshDisposition::Dirty
        } else {
            disposition
        };

        if let (Some(object_id), Some(previous_item)) =
            (previous_object_id.as_ref(), previous.as_ref())
        {
            match disposition {
                LocalRefreshDisposition::Busy => {
                    seen.insert(object_id.clone());
                    if let Some(existing_entry) = current_inventory.get(object_id) {
                        inventory_entries.push((object_id.clone(), existing_entry.clone()));
                    }
                    continue;
                }
                LocalRefreshDisposition::Dirty => {
                    seen.insert(object_id.clone());
                    if let Some(item) = proposed_state.items.get_mut(object_id) {
                        item.dirty = true;
                    }
                    let incoming_version = entry.content_version();
                    let remote_changed = previous_item.content_version != incoming_version
                        || previous_item.relative_path != entry.relative_path;
                    if remote_changed
                        && !proposed_state.conflicts.iter().any(|conflict| {
                            conflict.object_id == *object_id
                                && conflict.actual_version == incoming_version
                        })
                    {
                        proposed_state.conflicts.push(CloudConflictRecord {
                            id: Uuid::new_v4(),
                            object_id: object_id.clone(),
                            relative_path: previous_item.relative_path.clone(),
                            expected_version: previous_item.content_version.clone(),
                            actual_version: incoming_version,
                            local_plaintext_path: Some(
                                registration
                                    .sync_root_path
                                    .join(previous_item.relative_path.replace('/', "\\")),
                            ),
                            created_at: Utc::now(),
                        });
                    }
                    if let Some(existing_entry) = current_inventory.get(object_id) {
                        inventory_entries.push((object_id.clone(), existing_entry.clone()));
                    }
                    continue;
                }
                LocalRefreshDisposition::Safe | LocalRefreshDisposition::Missing => {}
            }
        }

        let identity = proposed_state.upsert_inventory_entry(entry)?;
        seen.insert(identity.object_id.clone());
        let current = proposed_state
            .items
            .get(&identity.object_id)
            .cloned()
            .ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "state upsert lost Cloud Files object {}",
                    identity.object_id
                ))
            })?;
        let identity_changed = previous_object_id
            .as_ref()
            .is_some_and(|old_object_id| old_object_id != &identity.object_id);
        if identity_changed {
            let old_object_id = previous_object_id
                .as_ref()
                .expect("identity change requires a previous object");
            proposed_state.items.remove(old_object_id);
            seen.insert(old_object_id.clone());
            placeholder_guard_ids.insert(identity.object_id.clone(), old_object_id.clone());
        }
        let changed = identity_changed
            || disposition == LocalRefreshDisposition::Missing
            || previous.as_ref().is_none_or(|old| {
                old.relative_path != current.relative_path
                    || old.content_version != current.content_version
            });
        if changed {
            if let Some(old) = previous
                .as_ref()
                .filter(|old| !identity_changed && old.relative_path != current.relative_path)
            {
                removed_items.push((identity.object_id.clone(), old.relative_path.clone()));
            }
            placeholders.push(CloudPlaceholderEntry {
                entry: entry.clone(),
                identity: identity.clone(),
                dirty: current.dirty,
            });
        }
        inventory_entries.push((identity.object_id, entry.clone()));
    }

    let missing = current_state
        .items
        .iter()
        .filter(|(object_id, _)| !seen.contains(*object_id))
        .map(|(object_id, item)| (object_id.clone(), item.clone()))
        .collect::<Vec<_>>();
    for (object_id, item) in missing {
        let descendant_dispositions =
            current_state
                .items
                .iter()
                .filter_map(|(candidate_id, candidate)| {
                    candidate
                        .relative_path
                        .starts_with(&format!("{}/", item.relative_path))
                        .then_some((
                            candidate.dirty,
                            local_dispositions.get(candidate_id).copied(),
                        ))
                });
        let mut busy_descendant = false;
        let mut dirty_descendant = false;
        if item.identity.kind == ProviderEntryKind::Directory {
            for (persistently_dirty, disposition) in descendant_dispositions {
                dirty_descendant |=
                    persistently_dirty || disposition == Some(LocalRefreshDisposition::Dirty);
                busy_descendant |= disposition == Some(LocalRefreshDisposition::Busy);
            }
        }
        let disposition = local_dispositions
            .get(&object_id)
            .copied()
            .unwrap_or(LocalRefreshDisposition::Safe);
        if disposition == LocalRefreshDisposition::Busy {
            if let Some(existing_entry) = current_inventory.get(&object_id) {
                inventory_entries.push((object_id, existing_entry.clone()));
            }
            continue;
        }
        if busy_descendant && !dirty_descendant {
            if let Some(existing_entry) = current_inventory.get(&object_id) {
                inventory_entries.push((object_id, existing_entry.clone()));
            }
            continue;
        }
        if item.dirty || disposition == LocalRefreshDisposition::Dirty || dirty_descendant {
            if let Some(current) = proposed_state.items.get_mut(&object_id) {
                current.dirty |= disposition == LocalRefreshDisposition::Dirty;
            }
            if !proposed_state
                .conflicts
                .iter()
                .any(|conflict| conflict.object_id == object_id)
            {
                proposed_state.conflicts.push(CloudConflictRecord {
                    id: Uuid::new_v4(),
                    object_id: object_id.clone(),
                    relative_path: item.relative_path.clone(),
                    expected_version: item.content_version,
                    actual_version: None,
                    local_plaintext_path: None,
                    created_at: Utc::now(),
                });
            }
            if let Some(existing_entry) = current_inventory.get(&object_id) {
                inventory_entries.push((object_id, existing_entry.clone()));
            }
        } else {
            removed_items.push((object_id.clone(), item.relative_path));
            proposed_state.items.remove(&object_id);
        }
    }

    Ok(RemoteReconciliationPlan {
        proposed_state,
        placeholders,
        placeholder_guard_ids,
        inventory_entries,
        removed_items,
    })
}

type BridgeFactory = Arc<dyn Fn(&CloudRootRegistration) -> Arc<dyn ProviderBridge> + Send + Sync>;

#[derive(Clone)]
pub struct CloudProviderHost {
    config: ProviderHostConfig,
    connections: Arc<Mutex<HashMap<Uuid, CloudRootConnection>>>,
    health_registry: Arc<Mutex<HashMap<Uuid, RootHealthTelemetry>>>,
    bridge_factory: Option<BridgeFactory>,
}

pub struct CloudRootConnection {
    inner: platform::ConnectedCloudRoot,
    writer_lease: Arc<RootWriterLease>,
    health_owner: RuntimeHealthOwner,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SafeRootStopOutcome {
    Cleaned,
    RecoveryPreserved { reason: String },
}

impl CloudRootConnection {
    pub fn root_id(&self) -> Uuid {
        self.inner.root_id()
    }

    pub fn sync_root_path(&self) -> &Path {
        self.inner.sync_root_path()
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        let inner = &mut self.inner;
        self.health_owner.shutdown_with(|| inner.disconnect()).await
    }

    fn shutdown_barrier(&self) -> platform::CloudRootShutdownBarrier {
        self.inner.shutdown_barrier()
    }
}

impl Drop for CloudRootConnection {
    fn drop(&mut self) {
        if self.health_owner.begin_drop_shutdown() {
            if let Err(error) = self.inner.disconnect_best_effort_on_drop() {
                self.health_owner
                    .record_drop_disconnect_failure(error.to_string());
                tracing::warn!(
                    root_id = %self.inner.root_id(),
                    "best-effort Cloud Files disconnect failed during drop: {error}"
                );
            }
        }
    }
}

impl CloudProviderHost {
    pub fn new(config: ProviderHostConfig) -> Self {
        Self {
            config,
            connections: Arc::new(Mutex::new(HashMap::new())),
            health_registry: Arc::new(Mutex::new(HashMap::new())),
            bridge_factory: None,
        }
    }

    pub fn with_bridge_factory(config: ProviderHostConfig, bridge_factory: BridgeFactory) -> Self {
        Self {
            config,
            connections: Arc::new(Mutex::new(HashMap::new())),
            health_registry: Arc::new(Mutex::new(HashMap::new())),
            bridge_factory: Some(bridge_factory),
        }
    }

    pub fn with_provider_bridge(
        config: ProviderHostConfig,
        bridge: Arc<dyn ProviderBridge>,
    ) -> Self {
        Self::with_bridge_factory(config, Arc::new(move |_| bridge.clone()))
    }

    pub fn config(&self) -> &ProviderHostConfig {
        &self.config
    }

    fn cleanup_path_filter(
        &self,
        registration: &CloudRootRegistration,
    ) -> Arc<CloudCleanupPathFilter> {
        let Some(factory) = &self.bridge_factory else {
            return Arc::new(no_cloud_cleanup_path_filter);
        };
        let bridge = factory(registration);
        let encrypted_root = registration.encrypted_root.clone();
        let sync_root_path = registration.sync_root_path.clone();
        Arc::new(move |path: &Path| {
            path.strip_prefix(&sync_root_path)
                .ok()
                .filter(|relative_path| !relative_path.as_os_str().is_empty())
                .is_some_and(|relative_path| {
                    bridge.is_path_excluded(&encrypted_root, relative_path)
                })
        })
    }

    pub fn status(&self) -> CloudProviderStatus {
        let mut status = platform::status();
        status.running_root_count = self.running_root_count();
        status
    }

    pub fn register_root(&self, registration: &CloudRootRegistration) -> Result<()> {
        self.ensure_root_stopped(registration.root_id, "register")?;
        let paths = self.runtime_paths(registration.root_id)?;
        let writer = self.root_writer_access(registration.root_id, &paths)?;
        let mut registration = registration.clone();
        if registration.registration_kind == CloudRootRegistrationKind::ShellIntegrated {
            let duplicate_name = self.load_registrations()?.into_iter().any(|existing| {
                existing.root_id != registration.root_id
                    && existing.registration_kind == CloudRootRegistrationKind::ShellIntegrated
                    && existing.display_name == registration.display_name
            });
            if duplicate_name {
                let short = registration.root_id.simple().to_string();
                registration.display_name =
                    format!("{} ({})", registration.display_name, &short[..8]);
            }
        }
        if let Some(existing) = self.load_registration(registration.root_id)? {
            if existing.sync_root_path != registration.sync_root_path
                || existing.encrypted_root != registration.encrypted_root
            {
                return Err(CloudProviderError::Callback(format!(
                    "root {} is already registered with different source or mount paths",
                    registration.root_id
                )));
            }
            if existing.registration_kind == CloudRootRegistrationKind::LegacyCfApi
                && registration.registration_kind == CloudRootRegistrationKind::ShellIntegrated
            {
                self.migrate_legacy_registration_to_shell(&existing)?;
            }
        }
        platform::register_root(&registration)?;
        self.save_registration_locked(&registration, writer.as_ref())?;
        Ok(())
    }

    fn migrate_legacy_registration_to_shell(
        &self,
        registration: &CloudRootRegistration,
    ) -> Result<()> {
        let status = self.read_durable_runtime_status(registration.root_id).map_err(|error| {
            CloudProviderError::Callback(format!(
                "Cloud Files Explorer migration is deferred because safety state could not be verified: {error}"
            ))
        })?;
        if !status.safe_to_unmount {
            let detail = if status.unsafe_reasons.is_empty() {
                "pending writeback or conflict work exists".to_string()
            } else {
                status
                    .unsafe_reasons
                    .iter()
                    .take(3)
                    .map(|reason| format!("{reason:?}"))
                    .collect::<Vec<_>>()
                    .join("; ")
            };
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files Explorer migration is deferred until the vault is safe: {detail}"
            )));
        }
        let cleanup_filter = self.cleanup_path_filter(registration);
        if registration.sync_root_path.exists() {
            validate_dehydrate_summary(&platform::dehydrate_root_filtered(
                &registration.sync_root_path,
                cleanup_filter.as_ref(),
            )?)?;
            platform::verify_root_dehydrated_filtered(
                &registration.sync_root_path,
                cleanup_filter.as_ref(),
            )?;
            platform::clear_dehydrated_root_filtered(
                &registration.sync_root_path,
                cleanup_filter.as_ref(),
            )?;
        }
        platform::unregister_registration(registration)?;
        tracing::info!(
            root_id = %registration.root_id,
            "Migrated legacy CFAPI-only registration boundary; Shell registration will reuse the same path"
        );
        Ok(())
    }

    pub fn unregister_root_path(&self, sync_root_path: &Path) -> Result<()> {
        if let Some(registration) = self
            .load_registrations()?
            .into_iter()
            .find(|registration| registration.sync_root_path == sync_root_path)
        {
            self.ensure_root_stopped(registration.root_id, "unregister")?;
            let paths = self.runtime_paths(registration.root_id)?;
            let _writer = self.root_writer_access(registration.root_id, &paths)?;
            return platform::unregister_registration(&registration);
        }
        platform::unregister_root(sync_root_path)
    }

    pub fn unregister_system_domain(&self, registration: &CloudRootRegistration) -> Result<()> {
        self.ensure_root_stopped(registration.root_id, "unregister")?;
        let paths = self.runtime_paths(registration.root_id)?;
        let _writer = self.root_writer_access(registration.root_id, &paths)?;
        platform::unregister_registration(registration)
    }

    pub fn unregister_domain_state(&self, root_id: Uuid) -> Result<()> {
        self.ensure_root_stopped(root_id, "remove provider state")?;
        let paths = self.runtime_paths(root_id)?;
        let _writer = self.root_writer_access(root_id, &paths)?;
        self.remove_runtime_artifacts(root_id)?;
        self.remove_registration(root_id)
    }

    pub fn sync_placeholders(
        &self,
        registration: &CloudRootRegistration,
    ) -> Result<PlaceholderSyncSummary> {
        self.ensure_root_stopped(registration.root_id, "synchronize placeholders offline")?;
        let runtime_paths = self.runtime_paths(registration.root_id)?;
        let _writer = self.root_writer_access(registration.root_id, &runtime_paths)?;
        let entries = project_windows_inventory(
            EncryptedInventory::new(registration.root_id, &registration.encrypted_root).scan()?,
        )?;
        let store = CloudStateStore::new(runtime_paths.state_path.clone(), registration.root_id);
        let current_state = store.load()?;
        if !current_state.items.is_empty() {
            return Err(CloudProviderError::Callback(
                "offline placeholder sync is only allowed for a new Cloud Files root; start the root to reconcile existing placeholders safely"
                    .into(),
            ));
        }
        if fs::read_dir(&registration.sync_root_path)?
            .next()
            .transpose()?
            .is_some()
        {
            return Err(CloudProviderError::Callback(
                "offline placeholder sync requires an empty new sync root; start the root to ingest or reconcile existing local content safely"
                    .into(),
            ));
        }
        let plan = plan_remote_reconciliation(
            registration,
            &current_state,
            &HashMap::new(),
            &entries,
            &HashMap::new(),
        )?;
        let placeholders = plan.placeholders;
        let processed_count =
            platform::create_placeholders(&registration.sync_root_path, &placeholders)?;
        if processed_count as usize != placeholders.len() {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files placeholder sync only confirmed {} of {} inventory entries",
                processed_count,
                placeholders.len()
            )));
        }
        store.replace_if_generation(current_state.generation, plan.proposed_state)?;
        Ok(PlaceholderSyncSummary {
            root_id: registration.root_id,
            requested_count: placeholders.len(),
            processed_count,
            updated_at: Utc::now(),
        })
    }

    async fn connect_root(
        &self,
        registration: &CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
    ) -> CloudRootStartResult<CloudRootConnection> {
        let bridge: Arc<dyn ProviderBridge> = Arc::new(WindowsProjectedBridge::new(bridge));
        let runtime_paths = self.runtime_paths(registration.root_id)?;
        let writer_lease = Arc::new(RootWriterLease::acquire(
            registration.root_id,
            &runtime_paths.writer_lock_path,
        )?);
        self.migrate_registration_if_needed(registration.root_id, writer_lease.as_ref())?;
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            registration.root_id,
            new_health_owner_instance_id(),
            std::process::id(),
            Utc::now(),
            Duration::from_millis(DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS),
            runtime_paths.health_path.clone(),
            &writer_lease,
        )?;
        let registry_result = self
            .health_registry
            .lock()
            .map_err(|_| CloudProviderError::Callback("health registry lock poisoned".into()))
            .map(|mut registry| {
                registry.insert(registration.root_id, telemetry.registry_handle());
            });
        if let Err(error) = registry_result {
            let _ = telemetry.record_start_failure(generation, Utc::now(), error.to_string());
            return Err(error.into());
        }
        let mut startup_health =
            StartupHealthOwner::start(telemetry.clone(), generation, Duration::from_secs(10));
        let attempt = async {
            self.ensure_health_safety_sources(
                registration.root_id,
                &runtime_paths,
                writer_lease.as_ref(),
            )?;
            prepare_plaintext_cache_for_startup(&runtime_paths)?;
            let entries = bridge
                .inventory(registration.root_id, &registration.encrypted_root)
                .await
                .map_err(CloudProviderError::from)?;
            let placeholders =
                self.load_existing_placeholder_entries(registration, entries, &runtime_paths)?;
            self.write_runtime_status(registration.root_id, &runtime_paths, None)?;
            platform::connect_root(
                registration,
                bridge,
                placeholders,
                runtime_paths,
                writer_lease.clone(),
                telemetry.clone(),
                generation,
            )
            .await
        }
        .await;
        let mut inner = match attempt {
            Ok(inner) => inner,
            Err(error) => {
                let _ = telemetry.record_start_failure(generation, Utc::now(), error.to_string());
                return Err(error);
            }
        };
        if let Err(error) = startup_health.mark_running_durable(Utc::now()) {
            return match inner.disconnect().await {
                Ok(()) => {
                    let _ =
                        telemetry.record_start_failure(generation, Utc::now(), error.to_string());
                    Err(startup_error_after_disconnect(error, Ok(())))
                }
                Err(disconnect_error) => {
                    let _ = telemetry.record_startup_cleanup_failure(
                        generation,
                        Utc::now(),
                        error.to_string(),
                        disconnect_error.to_string(),
                    );
                    Err(startup_error_after_disconnect(error, Err(disconnect_error)))
                }
            };
        }
        let health_owner = match startup_health.transfer_to_runtime() {
            Ok(owner) => owner,
            Err(error) => {
                return match inner.disconnect().await {
                    Ok(()) => {
                        let _ = telemetry.record_start_failure(
                            generation,
                            Utc::now(),
                            error.to_string(),
                        );
                        Err(startup_error_after_disconnect(error, Ok(())))
                    }
                    Err(disconnect_error) => {
                        let _ = telemetry.record_startup_cleanup_failure(
                            generation,
                            Utc::now(),
                            error.to_string(),
                            disconnect_error.to_string(),
                        );
                        Err(startup_error_after_disconnect(error, Err(disconnect_error)))
                    }
                };
            }
        };
        Ok(CloudRootConnection {
            inner,
            writer_lease,
            health_owner,
        })
    }

    pub async fn start_root_with_bridge(
        &self,
        root_id: Uuid,
        bridge: Arc<dyn ProviderBridge>,
    ) -> CloudRootStartResult<()> {
        if self.is_root_running(root_id) {
            return Ok(());
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let mut connection = self.connect_root(&registration, bridge).await?;
        let registry_error = match self.connections.lock() {
            Ok(mut connections) => {
                connections.insert(root_id, connection);
                return Ok(());
            }
            Err(_) => CloudProviderError::Callback("connection registry lock poisoned".into()),
        };
        Err(startup_error_after_disconnect(
            registry_error,
            connection.shutdown().await,
        ))
    }

    pub async fn start_root(&self, root_id: Uuid) -> CloudRootStartResult<()> {
        if self.is_root_running(root_id) {
            return Ok(());
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let Some(factory) = &self.bridge_factory else {
            return Err(CloudProviderError::Callback(
                "start-root requires an in-process ProviderBridge; use start_root_with_bridge from the CLI/Tauri host or create the host with a bridge factory".to_string(),
            )
            .into());
        };
        self.start_root_with_bridge(root_id, factory(&registration))
            .await
    }

    fn root_controls(&self, root_id: Uuid) -> Result<platform::CloudRootShutdownBarrier> {
        self.connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .get(&root_id)
            .map(CloudRootConnection::shutdown_barrier)
            .ok_or_else(|| {
                CloudProviderError::Callback(
                    "Mount this folder to change its compatibility or resolve pending operations"
                        .into(),
                )
            })
    }

    pub fn compatibility_status(&self, root_id: Uuid) -> Result<Option<VaultCompatibilityStatus>> {
        Ok(self.root_controls(root_id)?.compatibility_status())
    }

    pub async fn set_legacy_compatibility(
        &self,
        root_id: Uuid,
        enabled: bool,
    ) -> Result<VaultCompatibilityStatus> {
        self.root_controls(root_id)?
            .set_legacy_compatibility(enabled)
            .await
    }

    pub async fn resolve_pending_operation(
        &self,
        root_id: Uuid,
        operation_id: Uuid,
        action: PendingOperationResolution,
    ) -> Result<()> {
        self.root_controls(root_id)?
            .resolve_pending(operation_id, action)
            .await
    }

    pub async fn probe_root(&self, root_id: Uuid) -> Result<CloudRootProbeResult> {
        if !self.is_root_running(root_id) {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files root {root_id} is not running"
            )));
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let telemetry = self
            .health_registry
            .lock()
            .map_err(|_| CloudProviderError::Callback("health registry lock poisoned".into()))?
            .get(&root_id)
            .cloned()
            .ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "Cloud Files root {root_id} has no live health owner"
                ))
            })?;
        let generation = telemetry.begin_active_probe(Utc::now())?;
        let sync_root_path = registration.sync_root_path;
        let attempt = tokio::time::timeout(
            Duration::from_secs(55),
            tokio::task::spawn_blocking(move || platform::active_probe(&sync_root_path)),
        )
        .await;
        let completed_at = Utc::now();
        let outcome = match attempt {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(CloudProviderError::Callback(format!(
                "active Cloud Files probe worker failed: {error}"
            ))),
            Err(_) => Err(CloudProviderError::Callback(
                "active Cloud Files probe exceeded 55 seconds".into(),
            )),
        };
        match outcome {
            Ok(kind) => {
                if !telemetry.finish_active_probe(generation, completed_at, Ok(kind))? {
                    return Err(CloudProviderError::Callback(
                        "active Cloud Files probe result belongs to a stale connection".into(),
                    ));
                }
                Ok(CloudRootProbeResult {
                    root_id,
                    kind,
                    completed_at,
                })
            }
            Err(error) => {
                let failure = error.to_string();
                if let Err(persistence_error) =
                    telemetry.finish_active_probe(generation, completed_at, Err(failure.clone()))
                {
                    return Err(CloudProviderError::Callback(format!(
                        "{failure}; failed to persist active probe failure: {persistence_error}"
                    )));
                }
                Err(error)
            }
        }
    }

    pub async fn stop_root(&self, root_id: Uuid) -> Result<()> {
        let removed = self
            .connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .remove(&root_id);
        let Some(mut connection) = removed else {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files root {root_id} is not running"
            )));
        };
        if let Err(error) = connection.shutdown().await {
            self.connections
                .lock()
                .map_err(|_| {
                    CloudProviderError::Callback("connection registry lock poisoned".into())
                })?
                .insert(root_id, connection);
            return Err(error);
        }
        Ok(())
    }

    /// Disconnect without deleting recovery data, and wait for callback-owned
    /// writer leases before allowing a replacement connection to start.
    pub async fn stop_root_for_restart(&self, root_id: Uuid) -> Result<()> {
        let writer = self
            .connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .get(&root_id)
            .map(|connection| connection.writer_lease.clone());
        self.stop_root(root_id).await?;
        if let Some(writer) = writer {
            if !wait_for_writer_quiescence(&writer, Duration::from_secs(30)).await {
                return Err(CloudProviderError::Callback(
                    "disconnected provider still has active work; restart deferred until its writer lease is released".into(),
                ));
            }
        }
        Ok(())
    }

    pub async fn stop_root_safely(
        &self,
        root_id: Uuid,
        dehydrate: bool,
    ) -> Result<SafeRootStopOutcome> {
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let paths = self.runtime_paths(root_id)?;
        let _writer = self.root_writer_access(root_id, &paths)?;
        let status = self.read_durable_runtime_status(root_id)?;
        if !status.safe_to_unmount {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files root {root_id} has unresolved mutation or conflict state"
            )));
        }

        let cleanup_path_filter = self.cleanup_path_filter(&registration);
        let shutdown_barrier = if dehydrate {
            self.connections
                .lock()
                .map_err(|_| {
                    CloudProviderError::Callback("connection registry lock poisoned".into())
                })?
                .get(&root_id)
                .map(CloudRootConnection::shutdown_barrier)
        } else {
            None
        };
        let dehydrated_while_connected = shutdown_barrier.is_some();

        if let Some(barrier) = shutdown_barrier.as_ref() {
            // Wait for any callback that already passed the running-state check,
            // then reject new mutation/hydration work without disconnecting the
            // CFAPI callback channel. Hydrated placeholders need that channel to
            // deliver and ACK NOTIFY_DEHYDRATE.
            barrier.begin().await?;

            let drained_status = match self.read_durable_runtime_status(root_id) {
                Ok(status) => status,
                Err(err) => {
                    barrier.resume();
                    return Err(CloudProviderError::Callback(format!(
                        "pre-disconnect safety state could not be read; Cloud Files provider remains connected: {err}"
                    )));
                }
            };
            if !drained_status.safe_to_unmount {
                barrier.resume();
                return Err(CloudProviderError::Callback(
                    "new durable mutation or conflict state appeared while callbacks drained; Cloud Files provider remains connected"
                        .into(),
                ));
            }

            let dehydration = platform::dehydrate_root_filtered(
                &registration.sync_root_path,
                cleanup_path_filter.as_ref(),
            )
            .and_then(|summary| validate_dehydrate_summary(&summary));
            if let Err(err) = dehydration {
                barrier.resume();
                return Err(CloudProviderError::Callback(format!(
                    "dehydration failed before disconnect; Cloud Files provider remains connected: {err}"
                )));
            }
            if let Err(err) = wait_for_root_dehydrated_filtered(
                &registration.sync_root_path,
                Duration::from_secs(3),
                cleanup_path_filter.as_ref(),
            )
            .await
            {
                barrier.resume();
                return Err(CloudProviderError::Callback(format!(
                    "dehydration verification failed before disconnect; Cloud Files provider remains connected: {err}"
                )));
            }
        }

        if self.root_is_running(root_id)? {
            if let Err(err) = self.stop_root(root_id).await {
                if let Some(barrier) = shutdown_barrier.as_ref() {
                    barrier.resume();
                }
                return Err(err);
            }
        }
        // The barrier owns a callback-context reference, including the shared
        // writer lease. Release it once disconnect is confirmed so quiescence
        // observes only genuinely active provider work.
        drop(shutdown_barrier);

        if !wait_for_writer_quiescence(&_writer, Duration::from_secs(2)).await {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: "provider background or hydration cleanup did not drain within two seconds"
                    .into(),
            });
        }
        // Disconnect drains callback delivery. Recheck durable safety in case a
        // callback committed work between the optimistic check and shutdown.
        // Preserve all recovery artifacts if that narrow race occurred.
        let drained_status = match self.read_durable_runtime_status(root_id) {
            Ok(status) => status,
            Err(err) => {
                return Ok(SafeRootStopOutcome::RecoveryPreserved {
                    reason: format!("post-disconnect safety state could not be read: {err}"),
                });
            }
        };
        if !drained_status.safe_to_unmount {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: "new durable mutation or conflict state appeared while callbacks drained"
                    .into(),
            });
        }
        if dehydrate && !dehydrated_while_connected {
            let dehydration = platform::dehydrate_root_filtered(
                &registration.sync_root_path,
                cleanup_path_filter.as_ref(),
            )
            .and_then(|summary| validate_dehydrate_summary(&summary));
            if let Err(err) = dehydration {
                return Ok(SafeRootStopOutcome::RecoveryPreserved {
                    reason: format!("dehydration requires a connected Cloud Files provider: {err}"),
                });
            }
            if let Err(err) = wait_for_root_dehydrated_filtered(
                &registration.sync_root_path,
                Duration::from_secs(3),
                cleanup_path_filter.as_ref(),
            )
            .await
            {
                return Ok(SafeRootStopOutcome::RecoveryPreserved {
                    reason: format!("dehydration verification failed after disconnect: {err}"),
                });
            }
        }
        if let Err(err) = self.cleanup_plaintext_cache_locked(root_id, &paths) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("plaintext cache cleanup failed after disconnect: {err}"),
            });
        }
        Ok(SafeRootStopOutcome::Cleaned)
    }

    pub async fn unmount_root_safely(&self, root_id: Uuid) -> Result<SafeRootStopOutcome> {
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        validate_sync_root_cleanup_target(&self.config.user_config_dir, &registration)?;

        match self.stop_root_safely(root_id, true).await? {
            SafeRootStopOutcome::RecoveryPreserved { reason } => {
                return Ok(SafeRootStopOutcome::RecoveryPreserved { reason });
            }
            SafeRootStopOutcome::Cleaned => {}
        }

        let paths = self.runtime_paths(root_id)?;
        let _writer = self.root_writer_access(root_id, &paths)?;
        if let Err(err) = cleanup_health_snapshots(&paths.health_path, &_writer) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("Cloud Files health-state cleanup failed: {err}"),
            });
        }
        let cleanup_path_filter = self.cleanup_path_filter(&registration);
        if let Err(err) = platform::clear_dehydrated_root_filtered(
            &registration.sync_root_path,
            cleanup_path_filter.as_ref(),
        ) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("dehydrated placeholder cleanup failed: {err}"),
            });
        }
        if let Err(err) = platform::unregister_registration(&registration) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("Cloud Files sync-root unregistration failed: {err}"),
            });
        }
        if registration.sync_root_path.exists() {
            if let Err(err) = fs::remove_dir(&registration.sync_root_path) {
                return Ok(SafeRootStopOutcome::RecoveryPreserved {
                    reason: format!("empty mount directory removal failed: {err}"),
                });
            }
        }
        if let Err(err) = self.remove_runtime_artifacts(root_id) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("Cloud Files runtime cleanup failed: {err}"),
            });
        }
        if let Err(err) = self.remove_registration(root_id) {
            return Ok(SafeRootStopOutcome::RecoveryPreserved {
                reason: format!("Cloud Files registration cleanup failed: {err}"),
            });
        }
        Ok(SafeRootStopOutcome::Cleaned)
    }

    pub fn dehydrate_root_path(&self, sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        // CfDehydratePlaceholder is an OS-coordinated placeholder operation and
        // does not mutate provider journal/state/cache data. Cloud Files returns
        // per-file sharing/conflict failures when a live file cannot be evicted.
        platform::dehydrate_root(sync_root_path)
    }

    pub async fn serve_ipc(&self) -> Result<()> {
        ipc::serve(self.clone()).await
    }

    pub async fn reset_root(&self, root_id: Uuid) -> Result<()> {
        match self.unmount_root_safely(root_id).await? {
            SafeRootStopOutcome::Cleaned => Ok(()),
            SafeRootStopOutcome::RecoveryPreserved { reason } => Err(CloudProviderError::Callback(
                format!("Cloud Files reset preserved recovery state: {reason}"),
            )),
        }
    }

    fn rollback_root_start(&self, root_id: Uuid) -> Result<()> {
        self.ensure_root_stopped(root_id, "roll back root startup")?;
        let paths = self.runtime_paths(root_id)?;
        let _writer = self.root_writer_access(root_id, &paths)?;
        if let Some(registration) = self.load_registration(root_id)? {
            #[cfg(target_os = "windows")]
            match fs::metadata(&registration.sync_root_path) {
                Ok(_) => platform::unregister_registration(&registration)?,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            #[cfg(not(target_os = "windows"))]
            let _ = registration;
        }
        self.remove_runtime_artifacts(root_id)?;
        self.remove_registration(root_id)
    }

    pub fn registration_exists(&self, root_id: Uuid) -> Result<bool> {
        Ok(self.load_registration(root_id)?.is_some())
    }

    fn cleanup_failed_root_start(
        &self,
        root_id: Uuid,
        registration_preexisted: bool,
    ) -> Result<()> {
        if registration_preexisted {
            tracing::warn!(
                "Preserving Cloud Files recovery state for restored root {} after startup failure",
                root_id
            );
            return Ok(());
        }
        self.rollback_root_start(root_id)
    }

    pub async fn cleanup_failed_root_start_after_error(
        &self,
        root_id: Uuid,
        registration_preexisted: bool,
        cleanup_disposition: StartupCleanupDisposition,
        primary_error: impl Into<String>,
    ) -> String {
        orchestrate_failed_start_cleanup(
            primary_error.into(),
            cleanup_disposition,
            registration_preexisted,
            || self.cleanup_failed_root_start(root_id, registration_preexisted),
        )
    }

    pub async fn cleanup_failed_root_readiness_after_error(
        &self,
        root_id: Uuid,
        registration_preexisted: bool,
        primary_error: impl Into<String>,
    ) -> String {
        orchestrate_failed_root_readiness_cleanup(
            primary_error.into(),
            registration_preexisted,
            || self.stop_root(root_id),
            || self.cleanup_failed_root_start(root_id, registration_preexisted),
        )
        .await
    }

    pub fn cleanup_plaintext_cache(&self, root_id: Uuid) -> Result<()> {
        self.ensure_root_stopped(root_id, "clean the plaintext cache")?;
        let paths = self.runtime_paths(root_id)?;
        let _writer = self.root_writer_access(root_id, &paths)?;
        self.cleanup_plaintext_cache_locked(root_id, &paths)
    }

    fn cleanup_plaintext_cache_locked(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
    ) -> Result<()> {
        let status = self.read_durable_runtime_status(root_id)?;
        if !status.safe_to_unmount {
            return Err(CloudProviderError::Callback(format!(
                "refusing to remove Cloud Files plaintext cache for unsafe root {root_id}"
            )));
        }
        if paths.cache_dir.exists() {
            fs::remove_dir_all(&paths.cache_dir)?;
        }
        Ok(())
    }

    pub fn load_registrations(&self) -> Result<Vec<CloudRootRegistration>> {
        let Some(directory) = self.root_state_dir() else {
            return Ok(Vec::new());
        };
        if !directory.exists() {
            return Ok(Vec::new());
        }
        let mut root_ids = BTreeSet::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let root_id_text = file_name
                .strip_suffix(".json.bak")
                .or_else(|| file_name.strip_suffix(".json"));
            let Some(root_id) = root_id_text.and_then(|root_id| Uuid::parse_str(root_id).ok())
            else {
                continue;
            };
            root_ids.insert(root_id);
        }
        let mut registrations = Vec::with_capacity(root_ids.len());
        for root_id in root_ids {
            if let Some(registration) = self.inspect_registration(root_id)? {
                registrations.push(registration.value);
            }
        }
        registrations.sort_by_key(|registration| registration.root_id);
        Ok(registrations)
    }

    fn remove_runtime_artifacts(&self, root_id: Uuid) -> Result<()> {
        let paths = self.runtime_paths(root_id)?;
        let status_backup = paths.status_path.with_file_name(format!(
            "{}.bak",
            paths
                .status_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("status.json")
        ));
        let journal_backup = paths.journal_path.with_file_name(format!(
            "{}.bak",
            paths
                .journal_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("journal.json")
        ));
        for path in [
            paths.status_path,
            status_backup,
            paths.journal_path,
            journal_backup,
            paths.state_path.clone(),
            paths.state_path.with_extension("json.bak"),
            paths.writer_lock_path,
        ] {
            if path.exists() {
                fs::remove_file(path)?;
            }
        }
        if paths.cache_dir.exists() {
            fs::remove_dir_all(paths.cache_dir)?;
        }
        Ok(())
    }

    pub fn runtime_status_path(&self, root_id: Uuid) -> Result<PathBuf> {
        Ok(self.runtime_paths(root_id)?.status_path)
    }

    pub fn mutation_journal_path(&self, root_id: Uuid) -> Result<PathBuf> {
        Ok(self.runtime_paths(root_id)?.journal_path)
    }

    pub fn check_root_health(&self, root_id: Uuid) -> Result<CloudRootHealthResponse> {
        let observed_at = Utc::now();
        let paths = self.read_only_runtime_paths(root_id)?;
        let mut unhealthy_evidence = Vec::new();
        let registration = match self.inspect_registration(root_id) {
            Ok(value) => value,
            Err(error) => {
                unhealthy_evidence.push(format!(
                    "Cloud Files root registration is unreadable: {error}"
                ));
                None
            }
        };
        let registered = match registration.as_ref() {
            Some(_) => true,
            None if unhealthy_evidence.is_empty() => {
                unhealthy_evidence.push(format!("Cloud Files root {root_id} is not registered"));
                false
            }
            None => false,
        };

        // Locking the live registry detects poisoned in-process ownership state, but the
        // persisted snapshot remains the cross-process source of truth.
        let _live_health = self
            .health_registry
            .lock()
            .map_err(|_| CloudProviderError::Callback("health registry lock poisoned".into()))?
            .get(&root_id)
            .cloned();

        let health = if registered {
            inspect_health_snapshot_sources(&paths.health_path, root_id, observed_at)?
        } else {
            None
        };
        if registered && health.is_none() {
            unhealthy_evidence.push("Cloud Files operational health snapshot is missing".into());
        }

        let journal = match inspect_mutation_journal_sources(&paths.journal_path, root_id) {
            Ok(value) => value,
            Err(error) => {
                unhealthy_evidence.push(format!(
                    "Cloud Files mutation journal is unreadable: {error}"
                ));
                None
            }
        };
        if registered && journal.is_none() {
            unhealthy_evidence.push("Cloud Files mutation journal is missing".into());
        }
        let state_store = CloudStateStore::new(paths.state_path.clone(), root_id);
        let state = match state_store.inspect() {
            Ok(value) => value,
            Err(error) => {
                unhealthy_evidence
                    .push(format!("Cloud Files provider state is unreadable: {error}"));
                None
            }
        };
        if registered && state.is_none() {
            unhealthy_evidence.push("Cloud Files provider state is missing".into());
        }

        let operational = health.as_ref().map(|inspection| inspection.value.clone());
        if let Some(snapshot) = &operational {
            unhealthy_evidence.extend(snapshot.unhealthy_evidence.iter().cloned());
        }
        let heartbeat_fresh = operational.as_ref().is_some_and(|snapshot| {
            if snapshot.lifecycle != CloudRootConnectionState::Running {
                return false;
            }
            snapshot.last_heartbeat_at.is_some_and(|heartbeat| {
                heartbeat <= observed_at
                    && observed_at.signed_duration_since(heartbeat)
                        <= chrono::Duration::milliseconds(
                            i64::try_from(snapshot.heartbeat_stale_after_millis)
                                .unwrap_or(i64::MAX),
                        )
            })
        });
        let lifecycle_healthy = operational.as_ref().is_some_and(|snapshot| {
            snapshot.lifecycle == CloudRootConnectionState::Running && heartbeat_fresh
        });
        let durable_state_readable = journal.is_some() && state.is_some();
        let pending_mutation_count = journal
            .as_ref()
            .map(|inspection| inspection.value.records.len());
        let pending_refresh_count = state.as_ref().map(|inspection| {
            inspection.value.ingestion_in_progress
                + usize::from(inspection.value.reconciliation_in_progress)
        });
        let conflict_count = state
            .as_ref()
            .map(|inspection| inspection.value.conflicts.len());
        let safe_to_unmount = lifecycle_healthy
            && match (&journal, &state) {
                (Some(journal), Some(state)) => {
                    state.value.safe_to_unmount(journal.value.records.len())
                }
                _ => false,
            };

        Ok(CloudRootHealthResponse {
            root_id,
            registered,
            operational,
            lifecycle_healthy,
            heartbeat_fresh,
            durable_state_readable,
            safe_to_unmount,
            pending_mutation_count,
            pending_refresh_count,
            conflict_count,
            durable_observed_at: observed_at,
            registration_source: registration.as_ref().map(|inspection| inspection.source),
            registration_generation: registration
                .as_ref()
                .map(|inspection| inspection.generation),
            health_snapshot_source: health.as_ref().map(|inspection| inspection.source),
            health_snapshot_generation: health.as_ref().map(|inspection| inspection.generation),
            health_snapshot_revision: health
                .as_ref()
                .map(|inspection| inspection.value.snapshot_revision),
            mutation_journal_source: journal.as_ref().map(|inspection| inspection.source),
            mutation_journal_generation: journal.as_ref().map(|inspection| inspection.generation),
            provider_state_source: state.as_ref().map(|inspection| inspection.source),
            provider_state_generation: state.as_ref().map(|inspection| inspection.generation),
            unhealthy_evidence,
        })
    }

    pub fn read_runtime_status(&self, root_id: Uuid) -> Result<MountSyncRuntimeStatus> {
        let mut status = self.read_durable_runtime_status(root_id)?;
        let health = self.check_root_health(root_id)?;
        if !health.lifecycle_healthy {
            status.safe_to_unmount = false;
            status.last_error = Some(
                "Cloud Files provider is disconnected or its heartbeat is stale; local changes may not have been scanned. Resume synchronization before unmounting.".into(),
            );
        }
        Ok(status)
    }

    // Shutdown must recheck the journal after disconnect, when a live heartbeat
    // is no longer expected. This is not a claim about unscanned local files.
    fn read_durable_runtime_status(&self, root_id: Uuid) -> Result<MountSyncRuntimeStatus> {
        let paths = self.read_only_runtime_paths(root_id)?;
        let journal =
            inspect_mutation_journal_sources(&paths.journal_path, root_id)?.ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "Cloud Files mutation journal is missing for root {root_id}"
                ))
            })?;
        let state = CloudStateStore::new(paths.state_path.clone(), root_id)
            .inspect()?
            .ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "Cloud Files durable state is missing for root {root_id}"
                ))
            })?;
        let mut status = Self::status_from_journal(root_id, &journal.value, None);
        Self::apply_persistent_safety(&mut status, &state.value);
        Ok(status)
    }

    pub fn unsafe_pending_mutation_count(&self, root_id: Uuid) -> Result<usize> {
        let paths = self.read_only_runtime_paths(root_id)?;
        Ok(
            inspect_mutation_journal_sources(&paths.journal_path, root_id)?
                .ok_or_else(|| {
                    CloudProviderError::Callback(format!(
                        "Cloud Files mutation journal is missing for root {root_id}"
                    ))
                })?
                .value
                .records
                .len(),
        )
    }

    fn runtime_paths(&self, root_id: Uuid) -> Result<CloudRuntimePaths> {
        let user_config_dir = &self.config.user_config_dir;
        if user_config_dir.as_os_str().is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "user_config_dir is required for Cloud Files runtime state".to_string(),
            ));
        }
        let state_dir = user_config_dir.join("mount_states");
        fs::create_dir_all(&state_dir)?;
        Ok(CloudRuntimePaths {
            status_path: state_dir.join(format!("mount_sync_status_{root_id}.json")),
            journal_path: state_dir.join(format!("cloud_mutations_{root_id}.json")),
            health_path: state_dir.join(format!("cloud_provider_health_{root_id}.json")),
            state_path: state_dir.join(format!("cloud_provider_state_{root_id}.json")),
            cache_dir: state_dir.join(format!("cloud_cache_{root_id}")),
            writer_lock_path: state_dir.join(format!("cloud_provider_writer_{root_id}.lock")),
        })
    }

    fn read_only_runtime_paths(&self, root_id: Uuid) -> Result<CloudRuntimePaths> {
        let user_config_dir = &self.config.user_config_dir;
        if user_config_dir.as_os_str().is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "user_config_dir is required for Cloud Files runtime state".to_string(),
            ));
        }
        let state_dir = user_config_dir.join("mount_states");
        Ok(CloudRuntimePaths {
            status_path: state_dir.join(format!("mount_sync_status_{root_id}.json")),
            journal_path: state_dir.join(format!("cloud_mutations_{root_id}.json")),
            health_path: state_dir.join(format!("cloud_provider_health_{root_id}.json")),
            state_path: state_dir.join(format!("cloud_provider_state_{root_id}.json")),
            cache_dir: state_dir.join(format!("cloud_cache_{root_id}")),
            writer_lock_path: state_dir.join(format!("cloud_provider_writer_{root_id}.lock")),
        })
    }

    fn root_writer_access(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
    ) -> Result<Arc<RootWriterLease>> {
        let expected_paths = self.read_only_runtime_paths(root_id)?;
        if paths != &expected_paths {
            return Err(CloudProviderError::StartupRecoveryUnavailable);
        }
        if let Some(connection) = self
            .connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .get(&root_id)
        {
            return Ok(connection.writer_lease.clone());
        }
        Ok(Arc::new(RootWriterLease::acquire(
            root_id,
            &paths.writer_lock_path,
        )?))
    }

    fn validate_root_writer_lease(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
        writer: &RootWriterLease,
    ) -> Result<()> {
        let expected_paths = self.read_only_runtime_paths(root_id)?;
        if writer.root_id != root_id
            || writer.lock_path != expected_paths.writer_lock_path
            || paths != &expected_paths
        {
            return Err(CloudProviderError::StartupRecoveryUnavailable);
        }
        Ok(())
    }

    fn load_existing_placeholder_entries(
        &self,
        registration: &CloudRootRegistration,
        entries: Vec<ProviderEntry>,
        paths: &CloudRuntimePaths,
    ) -> Result<Vec<CloudPlaceholderEntry>> {
        let store = CloudStateStore::new(paths.state_path.clone(), registration.root_id);
        let state = store.load()?;
        let mut placeholders = Vec::new();
        for entry in entries {
            let stable_object_id = entry.identity.file_id.clone();
            let stable_item = stable_object_id
                .as_ref()
                .and_then(|object_id| state.items.get(object_id));
            if let Some(item) = stable_item {
                if item.identity.kind != entry.kind {
                    return Err(CloudProviderError::Callback(format!(
                        "stable identity {} is persisted as a {:?}, not a {:?}",
                        item.identity.object_id, item.identity.kind, entry.kind
                    )));
                }
                placeholders.push(CloudPlaceholderEntry {
                    entry,
                    identity: item.identity.clone(),
                    dirty: item.dirty,
                });
                continue;
            }

            let legacy_object_id = match entry.kind {
                ProviderEntryKind::File => None,
                ProviderEntryKind::Directory => state
                    .directory_ids
                    .get(&entry.relative_path)
                    .map(Uuid::to_string),
            };
            let item = legacy_object_id
                .as_ref()
                .and_then(|object_id| state.items.get(object_id))
                .or_else(|| {
                    state.items.values().find(|item| {
                        item.relative_path == entry.relative_path
                            && item.identity.kind == entry.kind
                    })
                });
            let Some(item) = item else {
                continue;
            };
            if item.identity.kind != entry.kind {
                return Err(CloudProviderError::Callback(format!(
                    "legacy identity {} is persisted as a {:?}, not a {:?}",
                    item.identity.object_id, item.identity.kind, entry.kind
                )));
            }
            placeholders.push(CloudPlaceholderEntry {
                entry,
                identity: item.identity.clone(),
                dirty: item.dirty,
            });
        }
        Ok(placeholders)
    }

    fn read_journal_from_path(
        &self,
        root_id: Uuid,
        journal_path: &Path,
    ) -> Result<CloudMutationJournal> {
        inspect_mutation_journal_sources(journal_path, root_id)?
            .map(|inspection| inspection.value)
            .ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "Cloud Files mutation journal is missing for root {root_id}"
                ))
            })
    }

    fn ensure_health_safety_sources(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
        writer: &RootWriterLease,
    ) -> Result<()> {
        self.validate_root_writer_lease(root_id, paths, writer)?;
        match inspect_mutation_journal_sources(&paths.journal_path, root_id) {
            Ok(Some(_)) => {
                recover_mutation_journal_for_writer(&paths.journal_path, root_id)?;
            }
            Ok(None) => {
                write_mutation_journal(&paths.journal_path, &CloudMutationJournal::empty(root_id))?;
            }
            Err(_) => {
                recover_mutation_journal_for_writer(&paths.journal_path, root_id)?;
            }
        }
        let store = CloudStateStore::new(paths.state_path.clone(), root_id);
        if store.inspect()?.is_none() {
            store.transaction(|_| Ok(()))?;
        }
        Ok(())
    }

    fn write_journal_to_path(
        &self,
        journal_path: &Path,
        journal: &CloudMutationJournal,
    ) -> Result<()> {
        write_mutation_journal(journal_path, journal)
    }

    fn write_runtime_status(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
        last_error: Option<String>,
    ) -> Result<()> {
        let journal = self.read_journal_from_path(root_id, &paths.journal_path)?;
        let mut status = Self::status_from_journal(root_id, &journal, last_error);
        let state = CloudStateStore::new(paths.state_path.clone(), root_id).load()?;
        Self::apply_persistent_safety(&mut status, &state);
        write_json_file_pretty(&paths.status_path, &status)
    }

    fn apply_persistent_safety(
        status: &mut MountSyncRuntimeStatus,
        state: &CloudRootPersistentState,
    ) {
        if !state.conflicts.is_empty() {
            status.unsafe_reasons.push(MountSafetyReason::Conflict {
                count: state.conflicts.len(),
                edited_count: state
                    .conflicts
                    .iter()
                    .filter(|conflict| conflict.local_plaintext_path.is_some())
                    .count(),
                sample_paths: state
                    .conflicts
                    .iter()
                    .take(3)
                    .map(|conflict| conflict.relative_path.clone())
                    .collect(),
            });
        }
        let pending_refresh =
            state.ingestion_in_progress + usize::from(state.reconciliation_in_progress);
        if pending_refresh > 0 {
            status
                .unsafe_reasons
                .push(MountSafetyReason::PendingRefresh {
                    count: pending_refresh,
                });
        }
        status.safe_to_unmount = state.safe_to_unmount(status.pending_writeback_count);
    }

    fn status_from_journal(
        _root_id: Uuid,
        journal: &CloudMutationJournal,
        last_error: Option<String>,
    ) -> MountSyncRuntimeStatus {
        let pending = journal.records.len();
        let mut operation_counts = BTreeMap::new();
        let operations = journal
            .records
            .iter()
            .map(|record| {
                let kind = format!("{:?}", record.kind).to_lowercase();
                *operation_counts.entry(kind.clone()).or_insert(0) += 1;
                hybridcipher_provider_core::PendingOperationSummary {
                    id: record.id,
                    kind,
                    source: record.relative_path.clone(),
                    destination: record.target_relative_path.clone(),
                    state: serde_json::to_value(record.state)
                        .ok()
                        .and_then(|v| v.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                    attempts: record.attempts,
                    merged_records: record.merged_records,
                    last_error: record.last_error.clone(),
                    error_code: record.error_code,
                }
            })
            .collect();
        let affected_file_count = journal
            .records
            .iter()
            .map(|r| {
                r.identity
                    .as_ref()
                    .and_then(|id| id.file_id.clone())
                    .unwrap_or_else(|| r.relative_path.clone())
            })
            .collect::<BTreeSet<_>>()
            .len();
        let sample_paths = journal
            .records
            .iter()
            .map(|record| record.relative_path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .take(3)
            .collect::<Vec<_>>();
        let oldest_age_ms = journal
            .records
            .iter()
            .map(|record| {
                Utc::now()
                    .signed_duration_since(record.created_at)
                    .num_milliseconds()
                    .max(0) as u64
            })
            .max();
        let last_error = last_error.or_else(|| {
            journal
                .records
                .iter()
                .rev()
                .find_map(|record| record.last_error.clone())
        });
        let unsafe_reasons = if pending == 0 {
            Vec::new()
        } else {
            vec![MountSafetyReason::PendingWriteback {
                count: pending,
                oldest_age_ms: oldest_age_ms.unwrap_or(0),
                sample_paths: sample_paths.clone(),
                last_error: last_error.clone(),
            }]
        };

        MountSyncRuntimeStatus {
            safe_to_unmount: pending == 0,
            pending_writeback_count: pending,
            pending_operation_count: pending,
            pending_operation_counts: operation_counts,
            affected_file_count,
            pending_operations: operations,
            pending_writeback_oldest_age_ms: oldest_age_ms,
            pending_writeback_paths: sample_paths,
            unsafe_reasons,
            last_error,
            updated_at: Utc::now(),
            ..MountSyncRuntimeStatus::default()
        }
    }

    fn root_state_dir(&self) -> Option<PathBuf> {
        if self.config.user_config_dir.as_os_str().is_empty() {
            return None;
        }
        Some(
            self.config
                .user_config_dir
                .join("cloud-files")
                .join("roots"),
        )
    }

    fn root_state_path(&self, root_id: Uuid) -> Option<PathBuf> {
        self.root_state_dir()
            .map(|dir| dir.join(format!("{root_id}.json")))
    }

    fn save_registration_locked(
        &self,
        registration: &CloudRootRegistration,
        writer: &RootWriterLease,
    ) -> Result<()> {
        let runtime_paths = self.read_only_runtime_paths(registration.root_id)?;
        self.validate_root_writer_lease(registration.root_id, &runtime_paths, writer)?;
        let Some(path) = self.root_state_path(registration.root_id) else {
            return Ok(());
        };
        let prior = self.inspect_registration(registration.root_id)?;
        let next_generation = prior.as_ref().map_or(Ok(1), |inspection| {
            inspection.generation.checked_add(1).ok_or_else(|| {
                CloudProviderError::Callback("Cloud Files registration generation exhausted".into())
            })
        })?;
        if let Some(prior) = prior {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("registration.json");
            let backup_path = path.with_file_name(format!("{file_name}.bak"));
            write_health_bytes_atomic(
                &backup_path,
                &encode_registration(&prior.value, prior.generation)?,
            )?;
        }
        write_health_bytes_atomic(&path, &encode_registration(registration, next_generation)?)
    }

    fn load_registration(&self, root_id: Uuid) -> Result<Option<CloudRootRegistration>> {
        Ok(self
            .inspect_registration(root_id)?
            .map(|inspection| inspection.value))
    }

    fn migrate_registration_if_needed(
        &self,
        root_id: Uuid,
        writer: &RootWriterLease,
    ) -> Result<()> {
        let runtime_paths = self.read_only_runtime_paths(root_id)?;
        self.validate_root_writer_lease(root_id, &runtime_paths, writer)?;
        let Some(inspection) = self.inspect_registration(root_id)? else {
            return Ok(());
        };
        if inspection.legacy || inspection.source == DurableInspectionSource::Backup {
            self.save_registration_locked(&inspection.value, writer)?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn save_registration(&self, registration: &CloudRootRegistration) -> Result<()> {
        let paths = self.runtime_paths(registration.root_id)?;
        let writer = self.root_writer_access(registration.root_id, &paths)?;
        self.save_registration_locked(registration, writer.as_ref())
    }

    fn inspect_registration(&self, root_id: Uuid) -> Result<Option<RegistrationInspection>> {
        let Some(path) = self.root_state_path(root_id) else {
            return Ok(None);
        };
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registration.json");
        let backup_path = path.with_file_name(format!("{file_name}.bak"));
        if !path.exists() && !backup_path.exists() {
            return Ok(None);
        }
        let parse = |source_path: &Path, source| {
            fs::read(source_path)
                .ok()
                .and_then(|bytes| parse_registration(&bytes, root_id).ok())
                .map(|(value, generation, legacy)| RegistrationInspection {
                    value,
                    source,
                    generation,
                    legacy,
                })
        };
        let primary = parse(&path, DurableInspectionSource::Primary);
        let backup = parse(&backup_path, DurableInspectionSource::Backup);
        match (primary, backup) {
            (Some(primary), Some(backup)) => Ok(Some(if backup.generation > primary.generation {
                backup
            } else {
                primary
            })),
            (Some(primary), None) => Ok(Some(primary)),
            (None, Some(backup)) => Ok(Some(backup)),
            (None, None) => Err(CloudProviderError::Callback(format!(
                "Cloud Files registration for {root_id} is unreadable"
            ))),
        }
    }

    fn remove_registration(&self, root_id: Uuid) -> Result<()> {
        let Some(path) = self.root_state_path(root_id) else {
            return Ok(());
        };
        if path.exists() {
            fs::remove_file(&path)?;
        }
        let backup = path.with_file_name(format!(
            "{}.bak",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("registration.json")
        ));
        if backup.exists() {
            fs::remove_file(backup)?;
        }
        Ok(())
    }

    fn running_root_count(&self) -> usize {
        self.connections
            .lock()
            .map(|connections| connections.len())
            .unwrap_or_default()
    }

    pub fn is_root_running(&self, root_id: Uuid) -> bool {
        self.connections
            .lock()
            .map(|connections| connections.contains_key(&root_id))
            .unwrap_or(false)
    }

    fn root_is_running(&self, root_id: Uuid) -> Result<bool> {
        Ok(self
            .connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .contains_key(&root_id))
    }

    fn ensure_root_stopped(&self, root_id: Uuid, operation: &str) -> Result<()> {
        if self.root_is_running(root_id)? {
            return Err(CloudProviderError::Callback(format!(
                "stop Cloud Files root {root_id} before attempting to {operation}"
            )));
        }
        Ok(())
    }
}

pub fn default_pipe_name() -> &'static str {
    r"\\.\pipe\hybridcipher-cloud-provider"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum ProviderIpcRequest {
    Status,
    RegisterRoot {
        registration: CloudRootRegistration,
        #[serde(default)]
        sync_placeholders: bool,
    },
    SyncPlaceholders {
        registration: CloudRootRegistration,
    },
    UnregisterRoot {
        sync_root_path: PathBuf,
    },
    ResetRoot {
        root_id: Uuid,
    },
    StartRoot {
        root_id: Uuid,
    },
    StopRoot {
        root_id: Uuid,
    },
    RootHealth {
        root_id: Uuid,
    },
    ProbeRoot {
        root_id: Uuid,
    },
    DehydrateRoot {
        sync_root_path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderIpcResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CloudProviderStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_summary: Option<PlaceholderSyncSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dehydrate_summary: Option<DehydrateRootSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_health: Option<CloudRootHealthResponse>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_probe: Option<CloudRootProbeResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProviderIpcResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            status: None,
            placeholder_summary: None,
            dehydrate_summary: None,
            root_health: None,
            root_probe: None,
            message: None,
        }
    }

    fn error(err: impl ToString) -> Self {
        Self {
            ok: false,
            status: None,
            placeholder_summary: None,
            dehydrate_summary: None,
            root_health: None,
            root_probe: None,
            message: Some(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_provider_core::ProviderEntryKind;
    use std::collections::HashMap;

    #[test]
    fn dehydrate_summary_rejects_any_unverified_file() {
        let summary = DehydrateRootSummary {
            sync_root_path: PathBuf::from("mount"),
            attempted_count: 3,
            dehydrated_count: 2,
            failed_count: 1,
            failures: vec!["mount/open.txt: sharing violation".to_string()],
            updated_at: Utc::now(),
        };

        let error = validate_dehydrate_summary(&summary).unwrap_err();

        assert!(error.to_string().contains("2 of 3"));
        assert!(error.to_string().contains("sharing violation"));
    }

    #[test]
    fn sync_root_cleanup_target_must_be_scoped_and_distinct_from_source() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join(".hybridcipher");
        let user_config = base.join("users/test-user");
        let mount = base.join("root_mount");
        let encrypted = temp.path().join("encrypted");
        fs::create_dir_all(&user_config).unwrap();
        fs::create_dir_all(&mount).unwrap();
        fs::create_dir_all(&encrypted).unwrap();
        let mut registration = CloudRootRegistration {
            root_id: Uuid::new_v4(),
            sync_root_path: mount.clone(),
            encrypted_root: encrypted,
            display_name: "test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };

        validate_sync_root_cleanup_target(&user_config, &registration).unwrap();

        registration.sync_root_path = temp.path().join("outside_mount");
        fs::create_dir_all(&registration.sync_root_path).unwrap();
        assert!(validate_sync_root_cleanup_target(&user_config, &registration).is_err());

        registration.sync_root_path = mount.clone();
        registration.encrypted_root = mount;
        assert!(validate_sync_root_cleanup_target(&user_config, &registration).is_err());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dehydrated_root_cleanup_refuses_and_preserves_ordinary_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root_mount");
        fs::create_dir_all(&root).unwrap();
        let ordinary = root.join("uncommitted.txt");
        fs::write(&ordinary, b"recovery data").unwrap();

        let error = platform::clear_dehydrated_root(&root).unwrap_err();

        assert!(error.to_string().contains("ordinary file remains"));
        assert_eq!(fs::read(&ordinary).unwrap(), b"recovery data");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dehydration_skips_excluded_ordinary_files() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root_mount");
        let excluded = root.join(".obsidian").join("app.json");
        fs::create_dir_all(excluded.parent().unwrap()).unwrap();
        fs::write(&excluded, br#"{"theme":"dark"}"#).unwrap();

        let summary = platform::dehydrate_root_filtered(&root, &|path| {
            path.to_string_lossy()
                .replace('\\', "/")
                .contains("/.obsidian/")
        })
        .unwrap();

        assert_eq!(summary.attempted_count, 0);
        assert_eq!(summary.dehydrated_count, 0);
        assert_eq!(summary.failed_count, 0);
        assert!(excluded.exists());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dehydrated_root_cleanup_removes_excluded_ordinary_cache_tree() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root_mount");
        let excluded_dir = root.join(".obsidian");
        let excluded = excluded_dir.join("app.json");
        fs::create_dir_all(&excluded_dir).unwrap();
        fs::write(&excluded, br#"{"theme":"dark"}"#).unwrap();

        platform::clear_dehydrated_root_filtered(&root, &|path| {
            path.to_string_lossy()
                .replace('\\', "/")
                .contains("/.obsidian")
        })
        .unwrap();

        assert!(root.exists());
        assert!(!excluded_dir.exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn dehydrated_root_cleanup_removes_empty_namespace_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root_mount");
        let nested = root.join("docs/archive");
        fs::create_dir_all(&nested).unwrap();

        platform::clear_dehydrated_root(&root).unwrap();

        assert!(root.exists());
        assert!(fs::read_dir(&root).unwrap().next().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn runtime_cleanup_removes_writer_lock_while_cleanup_lease_is_held() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().join("users/test-user"),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        let writer = host.root_writer_access(root_id, &paths).unwrap();
        assert!(paths.writer_lock_path.exists());

        host.remove_runtime_artifacts(root_id).unwrap();

        assert!(!paths.writer_lock_path.exists());
        drop(writer);
    }

    struct RecordingProjectionBridge {
        entry: ProviderEntry,
        writeback: Mutex<Option<(String, FileIdentityV1)>>,
    }

    #[async_trait]
    impl ProviderBridge for RecordingProjectionBridge {
        async fn inventory(
            &self,
            _root_id: Uuid,
            _encrypted_root: &Path,
        ) -> ProviderResult<Vec<ProviderEntry>> {
            Ok(vec![self.entry.clone()])
        }

        async fn hydrate_file(&self, _entry: &ProviderEntry) -> ProviderResult<Vec<u8>> {
            Ok(Vec::new())
        }

        async fn writeback_file_checked(
            &self,
            _root_id: Uuid,
            _encrypted_root: &Path,
            relative_path: &str,
            _plaintext_path: &Path,
            existing_identity: Option<&FileIdentityV1>,
            _expected_version: &ExpectedProviderVersion,
        ) -> ProviderResult<ProviderEntry> {
            *self.writeback.lock().unwrap() = Some((
                relative_path.to_string(),
                existing_identity.cloned().unwrap(),
            ));
            Ok(self.entry.clone())
        }
    }

    #[test]
    fn windows_inventory_projects_incompatible_macos_file_names_stably() {
        let root_id = Uuid::new_v4();
        let entries = vec![
            ProviderEntry::cache_file_with_identity(
                root_id,
                "Todo's/Change encrypted data to read only?.md",
                PathBuf::from("question.encrypted"),
                1,
                2,
                Utc::now(),
                None,
                Some("question-file-id".to_string()),
                Some(1),
            ),
            ProviderEntry::cache_file_with_identity(
                root_id,
                "Hcipher_wiki/public _repo_sync verfify.md.",
                PathBuf::from("trailing-dot.encrypted"),
                1,
                2,
                Utc::now(),
                None,
                Some("trailing-dot-file-id".to_string()),
                Some(1),
            ),
        ];

        let first = project_windows_inventory(entries.clone()).unwrap();
        let second = project_windows_inventory(entries).unwrap();

        assert_eq!(
            first
                .iter()
                .map(|entry| entry.relative_path.clone())
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|entry| entry.relative_path.clone())
                .collect::<Vec<_>>()
        );
        assert!(first.iter().all(|entry| entry
            .relative_path
            .split('/')
            .all(windows_component_is_compatible)));
        assert!(first
            .iter()
            .all(|entry| entry.relative_path.contains("~hc-")));
        assert!(first
            .iter()
            .all(|entry| entry.relative_path.ends_with(".md")));
    }

    #[test]
    fn windows_inventory_leaves_compatible_paths_unchanged() {
        let root_id = Uuid::new_v4();
        let entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            1,
            2,
            Utc::now(),
            None,
            Some("report-file-id".to_string()),
            Some(1),
        );

        let projected = project_windows_inventory(vec![entry]).unwrap();

        assert_eq!(projected[0].relative_path, "docs/report.txt");
    }

    #[tokio::test]
    async fn projected_bridge_translates_same_path_writeback_to_original_identity() {
        let root_id = Uuid::new_v4();
        let raw_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "Todo's/Change encrypted data to read only?.md",
            PathBuf::from("question.encrypted"),
            1,
            2,
            Utc::now(),
            None,
            Some("question-file-id".to_string()),
            Some(1),
        );
        let inner = Arc::new(RecordingProjectionBridge {
            entry: raw_entry.clone(),
            writeback: Mutex::new(None),
        });
        let bridge = WindowsProjectedBridge::new(inner.clone());
        let projected = bridge
            .inventory(root_id, Path::new("encrypted"))
            .await
            .unwrap()
            .remove(0);

        let result = bridge
            .writeback_file_checked(
                root_id,
                Path::new("encrypted"),
                &projected.relative_path,
                Path::new("plaintext"),
                Some(&projected.identity),
                &ExpectedProviderVersion::Unchecked,
            )
            .await
            .unwrap();

        let (written_path, written_identity) = inner.writeback.lock().unwrap().clone().unwrap();
        assert_eq!(written_path, raw_entry.relative_path);
        assert_eq!(written_identity, raw_entry.identity);
        assert_eq!(result.relative_path, projected.relative_path);
        assert_eq!(result.identity, projected.identity);
    }

    fn test_identity(root_id: Uuid) -> hybridcipher_provider_core::FileIdentityV1 {
        hybridcipher_provider_core::FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            "docs/report.txt",
            Some("file-1".to_string()),
            Some(7),
        )
    }

    fn health_test_time(seconds: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + seconds, 0).expect("valid health test time")
    }

    fn running_health_telemetry() -> (RootHealthTelemetry, u64) {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        let generation = telemetry.record_starting(health_test_time(1)).unwrap();
        telemetry
            .record_running(generation, health_test_time(2))
            .unwrap();
        telemetry.record_heartbeat(generation, health_test_time(3));
        (telemetry, generation)
    }

    fn health_test_paths(directory: &Path, root_id: Uuid) -> (PathBuf, PathBuf) {
        (
            directory.join(format!("cloud_provider_health_{root_id}.json")),
            directory.join(format!("cloud_provider_writer_{root_id}.lock")),
        )
    }

    fn new_persisted_health(
        directory: &Path,
        root_id: Uuid,
        owner_instance_id: Uuid,
        owner_process_id: u32,
        now: DateTime<Utc>,
        heartbeat_stale_after: Duration,
    ) -> (RootHealthTelemetry, u64, Arc<RootWriterLease>, PathBuf) {
        let (path, lock_path) = health_test_paths(directory, root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            owner_instance_id,
            owner_process_id,
            now,
            heartbeat_stale_after,
            path.clone(),
            &lease,
        )
        .unwrap();
        (telemetry, generation, lease, path)
    }

    fn registered_health_fixture(
        directory: &Path,
        root_id: Uuid,
    ) -> (CloudProviderHost, CloudRuntimePaths) {
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: directory.to_path_buf(),
            pipe_name: None,
        });
        host.save_registration(&CloudRootRegistration {
            root_id,
            sync_root_path: directory.join("sync"),
            encrypted_root: directory.join("encrypted"),
            display_name: "Operational Health Fixture".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        })
        .unwrap();
        let paths = host.runtime_paths(root_id).unwrap();
        let writer = host.root_writer_access(root_id, &paths).unwrap();
        host.ensure_health_safety_sources(root_id, &paths, writer.as_ref())
            .unwrap();
        (host, paths)
    }

    fn health_temp_files(directory: &Path, health_path: &Path) -> Vec<PathBuf> {
        let prefix = format!(
            "{}",
            health_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap()
        );
        fs::read_dir(directory)
            .unwrap()
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(&prefix) && name.contains(".tmp-"))
            })
            .collect()
    }

    #[derive(Serialize)]
    struct LegacyCloudRootOperationalHealthV1 {
        root_id: Uuid,
        owner_instance_id: Uuid,
        owner_process_id: u32,
        connection_generation: u64,
        snapshot_revision: u64,
        lifecycle: CloudRootConnectionState,
        lifecycle_changed_at: DateTime<Utc>,
        last_start_attempt_at: Option<DateTime<Utc>>,
        last_start_success_at: Option<DateTime<Utc>>,
        last_start_failure_at: Option<DateTime<Utc>>,
        last_start_failure: Option<String>,
        stop_count: u64,
        last_stopped_at: Option<DateTime<Utc>>,
        last_heartbeat_at: Option<DateTime<Utc>>,
        callback_health: Vec<CloudCallbackHealth>,
        hydration_success_observed: bool,
        last_hydration_success_at: Option<DateTime<Utc>>,
        hydration_failure: Option<String>,
        last_hydration_failure_at: Option<DateTime<Utc>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        persistence_error: Option<String>,
        assessed_at: DateTime<Utc>,
        healthy: bool,
        unhealthy_evidence: Vec<String>,
    }

    impl From<&CloudRootOperationalHealth> for LegacyCloudRootOperationalHealthV1 {
        fn from(snapshot: &CloudRootOperationalHealth) -> Self {
            Self {
                root_id: snapshot.root_id,
                owner_instance_id: snapshot.owner_instance_id,
                owner_process_id: snapshot.owner_process_id,
                connection_generation: snapshot.connection_generation,
                snapshot_revision: snapshot.snapshot_revision,
                lifecycle: snapshot.lifecycle,
                lifecycle_changed_at: snapshot.lifecycle_changed_at,
                last_start_attempt_at: snapshot.last_start_attempt_at,
                last_start_success_at: snapshot.last_start_success_at,
                last_start_failure_at: snapshot.last_start_failure_at,
                last_start_failure: snapshot.last_start_failure.clone(),
                stop_count: snapshot.stop_count,
                last_stopped_at: snapshot.last_stopped_at,
                last_heartbeat_at: snapshot.last_heartbeat_at,
                callback_health: snapshot.callback_health.clone(),
                hydration_success_observed: snapshot.hydration_success_observed,
                last_hydration_success_at: snapshot.last_hydration_success_at,
                hydration_failure: snapshot.hydration_failure.clone(),
                last_hydration_failure_at: snapshot.last_hydration_failure_at,
                persistence_error: snapshot.persistence_error.clone(),
                assessed_at: snapshot.assessed_at,
                healthy: snapshot.healthy,
                unhealthy_evidence: snapshot.unhealthy_evidence.clone(),
            }
        }
    }

    #[derive(Serialize)]
    struct LegacyCloudHealthSnapshotEnvelopeV1 {
        schema_version: u16,
        persisted_generation: u64,
        persisted_revision: u64,
        checksum_hex: String,
        snapshot: LegacyCloudRootOperationalHealthV1,
    }

    fn legacy_health_snapshot_v1_bytes(snapshot: &CloudRootOperationalHealth) -> Vec<u8> {
        let legacy = LegacyCloudRootOperationalHealthV1::from(snapshot);
        let checksum_hex = Sha256::digest(serde_json::to_vec(&legacy).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        serde_json::to_vec_pretty(&LegacyCloudHealthSnapshotEnvelopeV1 {
            schema_version: 1,
            persisted_generation: snapshot.connection_generation,
            persisted_revision: snapshot.snapshot_revision,
            checksum_hex,
            snapshot: legacy,
        })
        .unwrap()
    }

    fn legacy_health_snapshot_v2_bytes(snapshot: &CloudRootOperationalHealth) -> Vec<u8> {
        let legacy = LegacyPersistedRootOperationalHealthV2::from(snapshot);
        let checksum_hex = legacy_health_snapshot_v2_checksum(&legacy).unwrap();
        serde_json::to_vec_pretty(&LegacyPersistedHealthSnapshotEnvelopeV2 {
            schema_version: LEGACY_CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION_V2,
            persisted_generation: snapshot.connection_generation,
            persisted_revision: snapshot.snapshot_revision,
            checksum_hex,
            snapshot: legacy,
        })
        .unwrap()
    }

    #[test]
    fn health_snapshot_legacy_v1_envelope_defaults_reassesses_and_rewrites_as_v3() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        fs::write(&path, legacy_health_snapshot_v1_bytes(&snapshot)).unwrap();

        let loaded =
            load_health_snapshot_recovery_capable_at(&path, snapshot.root_id, health_test_time(40))
                .unwrap();

        assert_eq!(
            loaded.heartbeat_stale_after_millis,
            DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS
        );
        assert!(!loaded.healthy);
        assert!(loaded
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is stale")));

        let mut next = loaded;
        next.snapshot_revision += 1;
        write_health_snapshot(&path, &next).unwrap();
        let current: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(current["schema_version"], serde_json::json!(3));
        assert_eq!(
            parse_health_snapshot_validated(&fs::read(&path).unwrap(), snapshot.root_id)
                .unwrap()
                .snapshot_revision,
            next.snapshot_revision
        );
    }

    #[test]
    fn health_snapshot_legacy_v2_migrates_transfer_health_fields() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Err("decrypt failed".into()), None, health_test_time(5));
        let snapshot = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        let migrated = parse_health_snapshot_validated(
            &legacy_health_snapshot_v2_bytes(&snapshot),
            snapshot.root_id,
        )
        .unwrap();

        assert_eq!(
            migrated.transfer_health_state,
            CloudTransferHealthState::TransferDegraded
        );
        assert_eq!(
            migrated.hydration_failure.as_deref(),
            Some("decrypt failed")
        );
        assert!(migrated.last_hydration_transfer.is_none());
    }

    #[test]
    fn health_snapshot_v3_rejects_unknown_snapshot_fields_without_weakening_checksum() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &snapshot).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["snapshot"]["unknown_future_field"] = serde_json::json!("not checksummed");
        let bytes = serde_json::to_vec_pretty(&envelope).unwrap();

        assert!(parse_health_snapshot_validated(&bytes, snapshot.root_id).is_err());
    }

    #[test]
    fn health_snapshot_v3_rejects_unknown_callback_health_fields_with_original_checksum() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &snapshot).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["snapshot"]["callback_health"][0]["unknown_callback_field"] =
            serde_json::json!("not covered after permissive deserialization");
        let bytes = serde_json::to_vec_pretty(&envelope).unwrap();

        assert!(parse_health_snapshot_validated(&bytes, snapshot.root_id).is_err());
    }

    #[test]
    fn health_snapshot_v3_rejects_duplicate_envelope_fields() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &snapshot).unwrap();
        let current = String::from_utf8(fs::read(&path).unwrap()).unwrap();
        let duplicated = current.replacen(
            "\"checksum_hex\":",
            "\"checksum_hex\": \"ignored duplicate\", \"checksum_hex\":",
            1,
        );

        assert!(parse_health_snapshot_validated(duplicated.as_bytes(), snapshot.root_id).is_err());
    }

    #[test]
    fn health_snapshot_writer_claim_excludes_second_telemetry_until_all_clones_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, lock_path) = health_test_paths(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let (first, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            1,
            health_test_time(0),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        first
            .record_running(generation, health_test_time(1))
            .unwrap();
        assert!(first.record_heartbeat(generation, health_test_time(2)));
        let prior =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(2)).unwrap();
        let remaining_clone = first.clone();
        drop(first);
        let shared_lease = lease.clone();
        let before_rejected_start = fs::read(&path).unwrap();

        assert!(RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            2,
            health_test_time(3),
            Duration::from_secs(30),
            path.clone(),
            &shared_lease,
        )
        .is_err());
        assert_eq!(fs::read(&path).unwrap(), before_rejected_start);

        drop(remaining_clone);
        let (next, next_generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            3,
            health_test_time(4),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        let durable =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(4)).unwrap();
        assert_eq!(next_generation, prior.connection_generation + 1);
        assert!(durable.snapshot_revision > prior.snapshot_revision);
        drop(next);
    }

    #[test]
    fn health_snapshot_cleanup_waits_for_telemetry_claim_to_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, lock_path) = health_test_paths(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            1,
            health_test_time(0),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        telemetry
            .record_running(generation, health_test_time(1))
            .unwrap();
        assert!(telemetry.record_stopped(generation, health_test_time(2)));

        assert!(cleanup_health_snapshots(&path, &lease).is_err());
        assert!(path.exists());

        drop(telemetry);
        cleanup_health_snapshots(&path, &lease).unwrap();
        assert!(!path.exists());
        assert!(!health_backup_path(&path).exists());
    }

    #[test]
    fn health_snapshot_runtime_owner_retains_exclusive_writer_claim() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let root_id = Uuid::new_v4();
            let (path, lock_path) = health_test_paths(temp.path(), root_id);
            let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
            let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
                root_id,
                Uuid::new_v4(),
                1,
                Utc::now(),
                Duration::from_secs(30),
                path.clone(),
                &lease,
            )
            .unwrap();
            let mut startup = StartupHealthOwner::start(
                telemetry.clone(),
                generation,
                Duration::from_secs(3_600),
            );
            drop(telemetry);
            assert!(RootHealthTelemetry::new_persisted_starting(
                root_id,
                Uuid::new_v4(),
                2,
                Utc::now(),
                Duration::from_secs(30),
                path.clone(),
                &lease,
            )
            .is_err());
            startup.mark_running_durable(Utc::now()).unwrap();
            let runtime_owner = startup.transfer_to_runtime().unwrap();
            drop(startup);

            assert!(RootHealthTelemetry::new_persisted_starting(
                root_id,
                Uuid::new_v4(),
                3,
                Utc::now(),
                Duration::from_secs(30),
                path.clone(),
                &lease,
            )
            .is_err());

            drop(runtime_owner);
            assert!(RootHealthTelemetry::new_persisted_starting(
                root_id,
                Uuid::new_v4(),
                4,
                Utc::now(),
                Duration::from_secs(30),
                path,
                &lease,
            )
            .is_ok());
        });
    }

    #[test]
    fn health_snapshot_persisted_running_without_heartbeat_is_unhealthy() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let mut forged = telemetry.snapshot(Utc::now(), Duration::from_secs(30));
        forged.last_heartbeat_at = None;
        forged.healthy = true;
        forged.unhealthy_evidence.clear();
        write_health_snapshot(&path, &forged).unwrap();

        let loaded = parse_health_snapshot_at(
            &fs::read(&path).unwrap(),
            forged.root_id,
            health_test_time(5),
        )
        .unwrap();

        assert!(!loaded.healthy);
        assert!(loaded
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is missing")));
    }

    #[test]
    fn health_snapshot_stale_after_serde_default_is_conservative() {
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(7));
        let mut value = serde_json::to_value(&snapshot).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("heartbeat_stale_after_millis");

        let decoded: CloudRootOperationalHealth = serde_json::from_value(value).unwrap();

        assert_eq!(
            decoded.heartbeat_stale_after_millis,
            DEFAULT_HEALTH_HEARTBEAT_STALE_AFTER_MILLIS
        );
    }

    #[test]
    fn health_snapshot_constructor_rejects_mismatched_root_or_health_path_lease() {
        let temp = tempfile::tempdir().unwrap();
        let first_root = Uuid::new_v4();
        let second_root = Uuid::new_v4();
        let (first_path, first_lock_path) = health_test_paths(temp.path(), first_root);
        let (second_path, _) = health_test_paths(temp.path(), second_root);
        let lease = Arc::new(RootWriterLease::acquire(first_root, &first_lock_path).unwrap());

        assert!(RootHealthTelemetry::new_persisted_starting(
            second_root,
            Uuid::new_v4(),
            1,
            health_test_time(0),
            Duration::from_secs(30),
            second_path,
            &lease,
        )
        .is_err());
        assert!(RootHealthTelemetry::new_persisted_starting(
            first_root,
            Uuid::new_v4(),
            1,
            health_test_time(0),
            Duration::from_secs(30),
            temp.path().join("wrong-health.json"),
            &lease,
        )
        .is_err());
        assert!(!first_path.exists());
    }

    #[test]
    fn health_snapshot_failed_start_publish_cannot_reexpose_prior_running_as_current() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, lock_path) = health_test_paths(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let (prior, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            1,
            Utc::now(),
            Duration::from_millis(1),
            path.clone(),
            &lease,
        )
        .unwrap();
        prior.record_running(generation, Utc::now()).unwrap();
        assert!(prior.record_heartbeat(generation, Utc::now()));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        drop(prior);

        assert!(RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            2,
            Utc::now(),
            Duration::from_millis(1),
            path.clone(),
            &lease,
        )
        .is_err());
        assert!(load_health_snapshot_recovery_capable(&path, root_id).is_err());
        assert!(health_temp_files(temp.path(), &path).is_empty());
    }

    #[test]
    fn health_snapshot_primary_replacement_failure_preserves_valid_prior_generation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let backup = health_backup_path(&path);
        let (telemetry, _) = running_health_telemetry();
        let prior = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &prior).unwrap();
        let mut intermediate = prior.clone();
        intermediate.snapshot_revision += 1;
        write_health_snapshot(&path, &intermediate).unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let mut next = intermediate.clone();
        next.snapshot_revision += 1;

        assert!(write_health_snapshot(&path, &next).is_err());

        let preserved =
            parse_health_snapshot_validated(&fs::read(&backup).unwrap(), prior.root_id).unwrap();
        assert_eq!(preserved.snapshot_revision, prior.snapshot_revision);
        assert!(health_temp_files(temp.path(), &path).is_empty());
    }

    #[test]
    fn health_snapshot_cleanup_refuses_failed_or_corrupt_serialized_state() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        assert!(telemetry.record_start_failure(generation, health_test_time(1), "connect failed"));
        drop(telemetry);
        assert!(cleanup_health_snapshots(&path, &lease).is_err());
        assert!(path.exists());

        fs::write(&path, b"{corrupt").unwrap();
        let _ = fs::remove_file(health_backup_path(&path));
        assert!(cleanup_health_snapshots(&path, &lease).is_err());
        assert!(path.exists());
    }

    #[test]
    fn health_snapshot_new_owner_continues_durable_generation_and_revision_without_zero_reset() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, lock_path) = health_test_paths(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let first_owner = Uuid::new_v4();
        let (first, first_generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            first_owner,
            1_111,
            health_test_time(0),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        first
            .record_running(first_generation, health_test_time(2))
            .unwrap();
        assert!(first.record_heartbeat(first_generation, health_test_time(3)));
        let prior = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
        assert_eq!(prior.lifecycle, CloudRootConnectionState::Running);
        drop(first);

        let second_owner = Uuid::new_v4();
        let (second, second_generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            second_owner,
            2_222,
            health_test_time(4),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        let durable =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(4)).unwrap();

        assert_eq!(durable.lifecycle, CloudRootConnectionState::Starting);
        assert_eq!(durable.owner_instance_id, second_owner);
        assert_eq!(durable.owner_process_id, 2_222);
        assert_eq!(
            durable.connection_generation,
            prior.connection_generation + 1
        );
        assert!(durable.snapshot_revision > prior.snapshot_revision);
        assert_eq!(second.lock_state().connection_generation, second_generation);
    }

    #[test]
    fn health_snapshot_new_owner_seeds_from_valid_newer_backup_when_primary_is_corrupt() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, lock_path) = health_test_paths(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let backup = path.with_file_name(format!(
            "{}.bak",
            path.file_name().unwrap().to_string_lossy()
        ));
        let (telemetry, _) = running_health_telemetry();
        let mut prior = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        prior.root_id = root_id;
        prior.connection_generation = 7;
        prior.snapshot_revision = 41;
        write_health_snapshot(&path, &prior).unwrap();
        fs::copy(&path, &backup).unwrap();
        fs::write(&path, b"{corrupt").unwrap();

        let owner = Uuid::new_v4();
        let _started = RootHealthTelemetry::new_persisted_starting(
            root_id,
            owner,
            9_999,
            health_test_time(5),
            Duration::from_secs(30),
            path.clone(),
            &lease,
        )
        .unwrap();
        let durable =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(5)).unwrap();

        assert_eq!(durable.lifecycle, CloudRootConnectionState::Starting);
        assert_eq!(durable.owner_instance_id, owner);
        assert_eq!(durable.connection_generation, 8);
        assert!(durable.snapshot_revision > 41);
    }

    #[test]
    fn health_snapshot_loaded_after_stale_after_reassesses_running_heartbeat() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let assessed_at = Utc::now();
        let mut persisted = telemetry.snapshot(assessed_at, Duration::from_secs(30));
        persisted.last_heartbeat_at = Some(assessed_at - chrono::Duration::seconds(10));
        assert!(persisted.healthy);
        write_health_snapshot(&path, &persisted).unwrap();

        let loaded = load_health_snapshot_recovery_capable_at(
            &path,
            persisted.root_id,
            assessed_at + chrono::Duration::seconds(31),
        )
        .unwrap();

        assert!(!loaded.healthy);
        assert!(loaded
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is stale")));
    }

    #[test]
    fn health_snapshot_parser_recomputes_forged_derived_health_and_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .unwrap()
            .finish_at(Err("forged-away failure".into()), None, health_test_time(5));
        let mut forged = telemetry.snapshot(health_test_time(5), Duration::from_secs(30));
        forged.healthy = true;
        forged.unhealthy_evidence.clear();
        write_health_snapshot(&path, &forged).unwrap();

        let loaded = load_health_snapshot_recovery_capable(&path, forged.root_id).unwrap();

        assert!(!loaded.healthy);
        assert!(loaded
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("forged-away failure")));
    }

    #[test]
    fn health_snapshot_loaded_callback_uses_utc_deadline_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, generation) = running_health_telemetry();
        let observation = telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchPlaceholders,
                health_test_time(4),
                health_test_time(14),
            )
            .unwrap();
        let persisted = telemetry.snapshot(health_test_time(5), Duration::from_secs(30));
        write_health_snapshot(&path, &persisted).unwrap();

        let loaded = load_health_snapshot_recovery_capable_at(
            &path,
            persisted.root_id,
            health_test_time(15),
        )
        .unwrap();

        assert!(!loaded.healthy);
        assert!(loaded.unhealthy_evidence.iter().any(|evidence| {
            evidence.contains("FetchPlaceholders") && evidence.contains("operation deadline")
        }));
        observation.finish_at(Ok(()), Some(Ok(())), health_test_time(6));
    }

    #[test]
    fn health_snapshot_future_heartbeat_is_conservatively_unhealthy_after_load() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let mut forged = telemetry.snapshot(Utc::now(), Duration::from_secs(30));
        forged.last_heartbeat_at = Some(Utc::now() + chrono::Duration::hours(1));
        forged.healthy = true;
        forged.unhealthy_evidence.clear();
        write_health_snapshot(&path, &forged).unwrap();

        let loaded = load_health_snapshot_recovery_capable(&path, forged.root_id).unwrap();

        assert!(!loaded.healthy);
        assert!(loaded
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("future")));
    }

    #[test]
    fn health_snapshot_forged_cleanup_capability_cannot_delete_state() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (path, _lock_path) = health_test_paths(temp.path(), root_id);
        let (telemetry, generation) = running_health_telemetry();
        telemetry.record_stopped(generation, health_test_time(4));
        let mut stopped = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        stopped.root_id = root_id;
        write_health_snapshot(&path, &stopped).unwrap();

        let mismatched_root = Uuid::new_v4();
        let (_, mismatched_lock_path) = health_test_paths(temp.path(), mismatched_root);
        let mismatched =
            Arc::new(RootWriterLease::acquire(mismatched_root, &mismatched_lock_path).unwrap());
        assert!(cleanup_health_snapshots(&path, &mismatched).is_err());
        assert!(path.exists());
    }

    #[test]
    fn health_snapshot_write_never_replaces_valid_backup_with_corrupt_primary() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let backup = path.with_file_name("health.json.bak");
        let (telemetry, _) = running_health_telemetry();
        let prior = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &prior).unwrap();
        fs::copy(&path, &backup).unwrap();
        fs::write(&path, b"{corrupt").unwrap();
        let mut next = prior.clone();
        next.snapshot_revision += 1;

        write_health_snapshot(&path, &next).unwrap();

        assert_eq!(
            parse_health_snapshot_validated(&fs::read(&backup).unwrap(), prior.root_id).unwrap(),
            prior
        );
    }

    #[test]
    fn health_snapshot_write_error_removes_unique_temp_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let snapshot = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        fs::create_dir(&path).unwrap();

        assert!(write_health_snapshot(&path, &snapshot).is_err());
        assert!(health_temp_files(temp.path(), &path).is_empty());
    }

    #[test]
    fn health_snapshot_repeated_heartbeat_failures_do_not_accumulate_temp_files() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        telemetry
            .record_running(generation, health_test_time(2))
            .unwrap();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        for second in 3..8 {
            assert!(telemetry
                .try_record_heartbeat(generation, health_test_time(second))
                .is_err());
        }

        assert!(health_temp_files(temp.path(), &path).is_empty());
    }

    #[test]
    fn health_snapshot_paths_are_distinct_per_root() {
        let temp = tempfile::tempdir().unwrap();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let first_root = Uuid::new_v4();
        let second_root = Uuid::new_v4();

        let first = host.runtime_paths(first_root).unwrap();
        let second = host.runtime_paths(second_root).unwrap();

        assert_ne!(first.health_path, second.health_path);
        assert_eq!(
            first.health_path.file_name().and_then(|name| name.to_str()),
            Some(format!("cloud_provider_health_{first_root}.json").as_str())
        );
        assert_eq!(
            second
                .health_path
                .file_name()
                .and_then(|name| name.to_str()),
            Some(format!("cloud_provider_health_{second_root}.json").as_str())
        );
    }

    #[test]
    fn health_snapshot_round_trips_in_checked_versioned_envelope() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let expected = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));

        write_health_snapshot(&path, &expected).unwrap();
        let loaded =
            load_health_snapshot_recovery_capable_at(&path, expected.root_id, expected.assessed_at)
                .unwrap();
        let envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

        assert_eq!(loaded, expected);
        assert_eq!(
            envelope["schema_version"],
            serde_json::json!(CLOUD_HEALTH_SNAPSHOT_SCHEMA_VERSION)
        );
        assert_eq!(
            envelope["persisted_generation"],
            serde_json::json!(expected.connection_generation)
        );
        assert_eq!(
            envelope["persisted_revision"],
            serde_json::json!(expected.snapshot_revision)
        );
        assert_eq!(envelope["checksum_hex"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn health_snapshot_recovery_selects_newer_valid_backup_generation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let mut newer = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        newer.connection_generation = 2;
        newer.snapshot_revision = 1;
        let mut older = newer.clone();
        older.connection_generation = 1;
        older.snapshot_revision = 99;

        write_health_snapshot(&path, &newer).unwrap();
        write_health_snapshot(&path, &older).unwrap();
        let recovered =
            load_health_snapshot_recovery_capable_at(&path, newer.root_id, newer.assessed_at)
                .unwrap();

        assert_eq!(recovered, newer);
        assert_eq!(
            parse_health_snapshot_validated(&fs::read(&path).unwrap(), newer.root_id).unwrap(),
            newer
        );
    }

    #[test]
    fn health_snapshot_recovery_rejects_trailing_primary_and_uses_valid_backup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let backup = path.with_file_name("health.json.bak");
        let (telemetry, _) = running_health_telemetry();
        let expected = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &expected).unwrap();
        fs::copy(&path, &backup).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{}"#)
            .unwrap();

        let recovered =
            load_health_snapshot_recovery_capable_at(&path, expected.root_id, expected.assessed_at)
                .unwrap();
        assert_eq!(recovered, expected);

        fs::remove_file(&backup).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(br#"{}"#)
            .unwrap();
        assert!(load_health_snapshot_recovery_capable(&path, expected.root_id).is_err());
    }

    #[test]
    fn health_snapshot_recovery_rejects_truncated_or_checksum_mismatched_data() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("health.json");
        let (telemetry, _) = running_health_telemetry();
        let expected = telemetry.snapshot(health_test_time(4), Duration::from_secs(30));
        write_health_snapshot(&path, &expected).unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(load_health_snapshot_recovery_capable(&path, expected.root_id).is_err());

        write_health_snapshot(&path, &expected).unwrap();
        let mut envelope: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope["snapshot"]["owner_process_id"] = serde_json::json!(9_999);
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();
        let _ = fs::remove_file(path.with_file_name("health.json.bak"));
        assert!(load_health_snapshot_recovery_capable(&path, expected.root_id).is_err());
    }

    #[test]
    fn health_snapshot_persists_owner_generation_and_monotonic_mutation_revision() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let owner_instance_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            owner_instance_id,
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );

        telemetry
            .record_running(generation, health_test_time(2))
            .unwrap();
        assert!(telemetry.record_heartbeat(generation, health_test_time(3)));
        let persisted =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(3)).unwrap();

        assert_eq!(persisted.owner_instance_id, owner_instance_id);
        assert_eq!(persisted.owner_process_id, 4_242);
        assert_eq!(persisted.connection_generation, generation);
        assert_eq!(persisted.snapshot_revision, 3);
    }

    #[test]
    fn active_probe_success_is_durable_and_clears_same_generation_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        telemetry
            .record_running(generation, health_test_time(1))
            .unwrap();
        telemetry.record_heartbeat(generation, health_test_time(1));

        assert_eq!(
            telemetry.begin_active_probe(health_test_time(2)).unwrap(),
            generation
        );
        telemetry
            .finish_active_probe(
                generation,
                health_test_time(3),
                Err("probe failed".to_string()),
            )
            .unwrap();
        assert!(
            !telemetry
                .snapshot(health_test_time(3), Duration::from_secs(30))
                .healthy
        );

        telemetry.begin_active_probe(health_test_time(4)).unwrap();
        telemetry
            .finish_active_probe(
                generation,
                health_test_time(5),
                Ok(CloudRootProbeKind::Hydration),
            )
            .unwrap();
        let persisted =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(5)).unwrap();
        assert!(persisted.healthy);
        assert!(persisted.active_probe.success_observed);
        assert_eq!(persisted.active_probe.attempt_count, 2);
        assert_eq!(persisted.active_probe.success_count, 1);
        assert_eq!(persisted.active_probe.failure_count, 1);
        assert_eq!(
            persisted.active_probe.last_kind,
            Some(CloudRootProbeKind::Hydration)
        );
        assert!(persisted.active_probe.last_failure.is_none());
    }

    #[test]
    fn active_probe_rejects_non_running_and_stale_generation_results() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        assert!(telemetry.begin_active_probe(health_test_time(1)).is_err());
        let generation = telemetry.record_starting(health_test_time(2)).unwrap();
        telemetry
            .record_running(generation, health_test_time(3))
            .unwrap();
        telemetry.begin_active_probe(health_test_time(4)).unwrap();
        assert!(!telemetry
            .finish_active_probe(
                generation.saturating_add(1),
                health_test_time(5),
                Ok(CloudRootProbeKind::Namespace),
            )
            .unwrap());
        assert!(
            telemetry
                .snapshot(health_test_time(5), Duration::from_secs(30))
                .active_probe
                .in_flight
        );
    }

    #[test]
    fn health_snapshot_failed_running_write_blocks_readiness_and_ordered_retry_recovers() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        let backup = health_backup_path(&path);
        assert!(telemetry.record_heartbeat(generation, health_test_time(1)));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        assert!(telemetry
            .record_running(generation, health_test_time(2))
            .is_err());
        let failed = telemetry.snapshot(health_test_time(2), Duration::from_secs(30));
        assert_eq!(failed.lifecycle, CloudRootConnectionState::Running);
        assert!(failed.persistence_error.is_some());
        assert!(!failed.healthy);
        let durable_before_retry =
            parse_health_snapshot_validated(&fs::read(&backup).unwrap(), root_id).unwrap();
        assert_eq!(
            durable_before_retry.lifecycle,
            CloudRootConnectionState::Starting
        );

        fs::remove_dir(&path).unwrap();
        assert!(telemetry.record_heartbeat(generation, health_test_time(3)));
        let recovered =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(3)).unwrap();
        assert_eq!(recovered.lifecycle, CloudRootConnectionState::Running);
        assert_eq!(recovered.snapshot_revision, 4);
        assert!(recovered.persistence_error.is_none());
        assert!(recovered.healthy);
    }

    #[test]
    fn health_snapshot_concurrent_mutations_publish_only_the_latest_revision() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(300),
        );
        telemetry
            .record_running(generation, health_test_time(2))
            .unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(17));
        let mut threads = Vec::new();
        for index in 0..16 {
            let telemetry = telemetry.clone();
            let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                if index % 2 == 0 {
                    assert!(telemetry.record_heartbeat(generation, health_test_time(3 + index)));
                } else {
                    telemetry
                        .begin_callback(
                            generation,
                            CloudCallbackKind::Close,
                            health_test_time(3 + index),
                            health_test_time(30 + index),
                        )
                        .unwrap()
                        .finish_at(Ok(()), None, health_test_time(20 + index));
                }
            }));
        }
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        let memory = telemetry.snapshot(health_test_time(60), Duration::from_secs(300));
        let durable =
            load_health_snapshot_recovery_capable_at(&path, root_id, health_test_time(60)).unwrap();
        assert_eq!(durable.snapshot_revision, memory.snapshot_revision);
        assert_eq!(durable.connection_generation, memory.connection_generation);
        assert_eq!(durable.owner_instance_id, memory.owner_instance_id);
    }

    #[test]
    fn health_snapshot_checked_ids_reject_before_uniqueness_is_lost() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        {
            let mut state = telemetry.lock_state();
            state.connection_generation = u64::MAX;
        }
        assert!(telemetry.record_starting(health_test_time(1)).is_err());

        {
            let mut state = telemetry.lock_state();
            state.connection_generation = 1;
            state.lifecycle = CloudRootConnectionState::Running;
            state.next_observation_id = u64::MAX;
        }
        assert!(telemetry
            .begin_callback(
                1,
                CloudCallbackKind::Close,
                health_test_time(2),
                health_test_time(12),
            )
            .is_err());

        {
            let mut state = telemetry.lock_state();
            state.next_observation_id = 0;
            state.snapshot_revision = u64::MAX;
        }
        assert!(telemetry
            .try_record_heartbeat(1, health_test_time(3))
            .is_err());
        assert_eq!(telemetry.lock_state().snapshot_revision, u64::MAX);
    }

    #[test]
    fn health_snapshot_startup_owner_drop_aborts_heartbeat_and_persists_owner_lost() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let root_id = Uuid::new_v4();
            let (telemetry, generation, _lease, path) = new_persisted_health(
                temp.path(),
                root_id,
                Uuid::new_v4(),
                4_242,
                Utc::now(),
                Duration::from_secs(30),
            );
            let owner =
                StartupHealthOwner::start(telemetry.clone(), generation, Duration::from_millis(10));
            tokio::time::sleep(Duration::from_millis(25)).await;

            drop(owner);
            let terminal = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
            assert_eq!(terminal.lifecycle, CloudRootConnectionState::Failed);
            assert!(terminal
                .last_start_failure
                .as_deref()
                .is_some_and(|failure| failure.contains("owner lost")));
            let terminal_revision = terminal.snapshot_revision;

            tokio::time::sleep(Duration::from_millis(30)).await;
            let after_wait = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
            assert_eq!(after_wait.snapshot_revision, terminal_revision);
        });
    }

    #[test]
    fn health_snapshot_startup_owner_transfers_only_after_durable_running() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let root_id = Uuid::new_v4();
            let (telemetry, generation, _lease, path) = new_persisted_health(
                temp.path(),
                root_id,
                Uuid::new_v4(),
                4_242,
                Utc::now(),
                Duration::from_secs(30),
            );
            let mut startup =
                StartupHealthOwner::start(telemetry.clone(), generation, Duration::from_millis(10));

            assert!(startup.transfer_to_runtime().is_err());
            startup.mark_running_durable(Utc::now()).unwrap();
            let runtime_owner = startup.transfer_to_runtime().unwrap();
            let running = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
            assert_eq!(running.lifecycle, CloudRootConnectionState::Running);
            let running_revision = running.snapshot_revision;

            tokio::time::sleep(Duration::from_millis(25)).await;
            let heartbeat = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
            assert!(heartbeat.snapshot_revision > running_revision);
            drop(runtime_owner);
        });
    }

    #[test]
    fn health_snapshot_owner_lost_write_failure_leaves_last_heartbeat_to_age_stale() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let root_id = Uuid::new_v4();
            let (telemetry, generation, _lease, path) = new_persisted_health(
                temp.path(),
                root_id,
                Uuid::new_v4(),
                4_242,
                Utc::now(),
                Duration::from_millis(10),
            );
            let backup = health_backup_path(&path);
            let mut startup =
                StartupHealthOwner::start(telemetry.clone(), generation, Duration::from_millis(10));
            startup.mark_running_durable(Utc::now()).unwrap();
            assert!(telemetry.record_heartbeat(generation, Utc::now()));
            assert!(telemetry.record_heartbeat(generation, Utc::now()));
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();

            drop(startup);
            let memory = telemetry.snapshot(Utc::now(), Duration::from_millis(10));
            assert_eq!(memory.lifecycle, CloudRootConnectionState::Failed);
            assert!(memory.persistence_error.is_some());
            let durable =
                parse_health_snapshot_validated(&fs::read(&backup).unwrap(), root_id).unwrap();
            assert_eq!(durable.lifecycle, CloudRootConnectionState::Running);
            let heartbeat_at = durable.last_heartbeat_at.expect("durable heartbeat");
            tokio::time::sleep(Duration::from_millis(15)).await;
            assert!(
                Utc::now().signed_duration_since(heartbeat_at) > chrono::Duration::milliseconds(10)
            );
        });
    }

    #[test]
    fn health_snapshot_multiple_concurrent_roots_never_share_path_or_state() {
        let temp = tempfile::tempdir().unwrap();
        let first_root = Uuid::new_v4();
        let second_root = Uuid::new_v4();
        let (first, first_generation, _first_lease, first_path) = new_persisted_health(
            temp.path(),
            first_root,
            Uuid::new_v4(),
            1,
            health_test_time(0),
            Duration::from_secs(30),
        );
        let (second, second_generation, _second_lease, second_path) = new_persisted_health(
            temp.path(),
            second_root,
            Uuid::new_v4(),
            2,
            health_test_time(0),
            Duration::from_secs(30),
        );
        let first_thread = std::thread::spawn(move || {
            assert!(first.record_start_failure(
                first_generation,
                health_test_time(2),
                "first root only"
            ));
        });
        let second_thread = std::thread::spawn(move || {
            second
                .record_running(second_generation, health_test_time(2))
                .unwrap();
            assert!(second.record_heartbeat(second_generation, health_test_time(3)));
        });
        first_thread.join().unwrap();
        second_thread.join().unwrap();

        let first_health = load_health_snapshot_recovery_capable(&first_path, first_root).unwrap();
        let second_health =
            load_health_snapshot_recovery_capable(&second_path, second_root).unwrap();
        assert_eq!(first_health.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(first_health.owner_process_id, 1);
        assert_eq!(second_health.lifecycle, CloudRootConnectionState::Running);
        assert_eq!(second_health.owner_process_id, 2);
        assert_ne!(
            first_health.owner_instance_id,
            second_health.owner_instance_id
        );
    }

    #[test]
    fn health_snapshot_cleanup_requires_stopped_root_writer_and_removes_primary_and_backup() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        let backup = health_backup_path(&path);
        telemetry
            .record_running(generation, health_test_time(1))
            .unwrap();

        assert!(cleanup_health_snapshots(&path, &lease).is_err());
        assert!(path.exists());
        assert!(backup.exists());

        assert!(telemetry.record_stopped(generation, health_test_time(2)));
        drop(telemetry);
        cleanup_health_snapshots(&path, &lease).unwrap();
        assert!(!path.exists());
        assert!(!backup.exists());
    }

    #[test]
    fn health_snapshot_callback_deadline_uses_monotonic_time_despite_wall_clock_jump() {
        let (telemetry, generation) = running_health_telemetry();
        let observation = telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchPlaceholders,
                Utc::now(),
                Utc::now() + chrono::Duration::seconds(30),
            )
            .unwrap();

        let jumped_wall_clock = telemetry.snapshot(
            Utc::now() + chrono::Duration::hours(1),
            Duration::from_secs(30),
        );

        assert_eq!(
            jumped_wall_clock
                .callback(CloudCallbackKind::FetchPlaceholders)
                .unwrap()
                .overdue_in_flight_count,
            0
        );
        observation.finish_at(Ok(()), Some(Ok(())), Utc::now());
    }

    #[test]
    fn root_health_retains_start_failure_and_stop_history() {
        let (telemetry, first_generation) = running_health_telemetry();
        telemetry.record_stopped(first_generation, health_test_time(4));
        let second_generation = telemetry.record_starting(health_test_time(5)).unwrap();
        telemetry.record_start_failure(
            second_generation,
            health_test_time(6),
            "native connect failed",
        );

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));

        assert_eq!(health.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(health.stop_count, 1);
        assert_eq!(health.last_stopped_at, Some(health_test_time(4)));
        assert_eq!(
            health.last_start_failure.as_deref(),
            Some("native connect failed")
        );
        assert_eq!(health.last_start_failure_at, Some(health_test_time(6)));
    }

    #[test]
    fn root_health_stale_running_heartbeat_is_unhealthy() {
        let (telemetry, _) = running_health_telemetry();

        let health = telemetry.snapshot(health_test_time(34), Duration::from_secs(30));

        assert!(!health.healthy);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is stale")));
    }

    #[test]
    fn root_health_new_connection_generation_clears_callback_but_retains_hydration_failure() {
        let (telemetry, first_generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                first_generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Err("decrypt failed".into()), None, health_test_time(5));
        telemetry.record_stopped(first_generation, health_test_time(6));
        let second_generation = telemetry.record_starting(health_test_time(7)).unwrap();
        telemetry
            .record_running(second_generation, health_test_time(8))
            .unwrap();
        telemetry.record_heartbeat(second_generation, health_test_time(9));

        let health = telemetry.snapshot(health_test_time(10), Duration::from_secs(30));

        assert_eq!(health.connection_generation, 2);
        assert!(health.healthy);
        assert!(health
            .callback_health
            .iter()
            .all(|callback| callback.failure_count == 0));
        assert_eq!(health.hydration_failure.as_deref(), Some("decrypt failed"));
        assert_eq!(
            health.transfer_health_state,
            CloudTransferHealthState::TransferDegraded
        );
    }

    #[test]
    fn root_health_ignores_stale_generation_lifecycle_and_heartbeat_updates() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        let first_generation = telemetry.record_starting(health_test_time(1)).unwrap();
        let second_generation = telemetry.record_starting(health_test_time(2)).unwrap();
        telemetry
            .record_running(second_generation, health_test_time(3))
            .unwrap();
        telemetry.record_heartbeat(second_generation, health_test_time(4));

        telemetry.record_start_failure(
            first_generation,
            health_test_time(5),
            "delayed first-generation failure",
        );
        telemetry.record_stopped(first_generation, health_test_time(6));
        telemetry.record_heartbeat(first_generation, health_test_time(39));

        let health = telemetry.snapshot(health_test_time(40), Duration::from_secs(30));

        assert_eq!(health.connection_generation, second_generation);
        assert_eq!(health.lifecycle, CloudRootConnectionState::Running);
        assert_eq!(health.stop_count, 0);
        assert!(health.last_start_failure.is_none());
        assert_eq!(health.last_heartbeat_at, Some(health_test_time(4)));
        assert!(!health.healthy);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is stale")));
    }

    #[test]
    fn root_health_terminal_stop_rejects_delayed_same_generation_updates() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry.record_stopped(generation, health_test_time(4));

        telemetry
            .record_running(generation, health_test_time(5))
            .unwrap();
        telemetry.record_heartbeat(generation, health_test_time(6));

        let health = telemetry.snapshot(health_test_time(7), Duration::from_secs(30));
        assert_eq!(health.lifecycle, CloudRootConnectionState::Disconnected);
        assert_eq!(health.last_heartbeat_at, None);
        assert_eq!(health.stop_count, 1);
        assert_eq!(health.last_stopped_at, Some(health_test_time(4)));
    }

    #[test]
    fn root_health_stop_is_idempotent() {
        let (telemetry, generation) = running_health_telemetry();

        telemetry.record_stopped(generation, health_test_time(4));
        telemetry.record_stopped(generation, health_test_time(5));

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        assert_eq!(health.stop_count, 1);
        assert_eq!(health.last_stopped_at, Some(health_test_time(4)));
    }

    #[tokio::test]
    async fn root_health_lifecycle_shutdown_records_only_confirmed_disconnect_and_is_idempotent() {
        let (telemetry, generation) = running_health_telemetry();
        let mut owner = RuntimeHealthOwner {
            telemetry: telemetry.clone(),
            generation,
            heartbeat: None,
            disconnected: false,
        };
        let disconnect_calls = std::cell::Cell::new(0);

        owner
            .shutdown_with(|| {
                disconnect_calls.set(disconnect_calls.get() + 1);
                async { Ok(()) }
            })
            .await
            .unwrap();
        owner
            .shutdown_with(|| {
                disconnect_calls.set(disconnect_calls.get() + 1);
                async { Ok(()) }
            })
            .await
            .unwrap();

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        assert_eq!(disconnect_calls.get(), 1);
        assert_eq!(health.lifecycle, CloudRootConnectionState::Disconnected);
        assert_eq!(health.stop_count, 1);
        assert!(health.last_disconnect_failure.is_none());
    }

    #[tokio::test]
    async fn root_health_lifecycle_shutdown_failure_is_durable_and_retryable() {
        let (telemetry, generation) = running_health_telemetry();
        let mut owner = RuntimeHealthOwner {
            telemetry: telemetry.clone(),
            generation,
            heartbeat: None,
            disconnected: false,
        };

        let failure = owner
            .shutdown_with(|| async {
                Err(CloudProviderError::Callback("disconnect rejected".into()))
            })
            .await
            .unwrap_err();
        assert!(failure.to_string().contains("disconnect rejected"));
        let failed = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        assert_eq!(failed.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(
            failed.last_disconnect_failure.as_deref(),
            Some("Cloud Files callback failed: disconnect rejected")
        );
        assert!(failed.last_disconnect_failure_at.is_some());
        assert_eq!(failed.stop_count, 0);

        owner.shutdown_with(|| async { Ok(()) }).await.unwrap();
        let recovered = telemetry.snapshot(health_test_time(7), Duration::from_secs(30));
        assert_eq!(recovered.lifecycle, CloudRootConnectionState::Disconnected);
        assert_eq!(recovered.stop_count, 1);
    }

    #[tokio::test]
    async fn health_snapshot_persists_disconnect_failure_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        telemetry
            .record_running(generation, health_test_time(1))
            .unwrap();
        let mut owner = RuntimeHealthOwner {
            telemetry,
            generation,
            heartbeat: None,
            disconnected: false,
        };

        owner
            .shutdown_with(|| async {
                Err(CloudProviderError::Callback(
                    "native disconnect failed".into(),
                ))
            })
            .await
            .unwrap_err();

        let persisted = load_health_snapshot_recovery_capable(&path, root_id).unwrap();
        assert_eq!(persisted.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(
            persisted.last_disconnect_failure.as_deref(),
            Some("Cloud Files callback failed: native disconnect failed")
        );
        assert!(persisted.last_disconnect_failure_at.is_some());
        assert_eq!(persisted.stop_count, 0);
    }

    #[tokio::test]
    async fn root_health_lifecycle_startup_owner_transitions_starting_before_running() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        let generation = telemetry.record_starting(health_test_time(1)).unwrap();
        let mut startup_owner =
            StartupHealthOwner::start(telemetry.clone(), generation, Duration::from_secs(60));
        assert_eq!(
            telemetry
                .snapshot(health_test_time(1), Duration::from_secs(30))
                .lifecycle,
            CloudRootConnectionState::Starting
        );

        startup_owner
            .mark_running_durable(health_test_time(2))
            .unwrap();
        assert_eq!(
            telemetry
                .snapshot(health_test_time(2), Duration::from_secs(30))
                .lifecycle,
            CloudRootConnectionState::Running
        );
        let mut runtime_owner = startup_owner.transfer_to_runtime().unwrap();
        runtime_owner
            .shutdown_with(|| async { Ok(()) })
            .await
            .unwrap();
    }

    #[test]
    fn callback_health_adapter_rejects_non_success_handler_status() {
        let handler = actionable_callback_handler_outcome(None, -1);
        let outcome =
            CallbackOutcomeAdapter::select(CloudCallbackClass::Actionable, handler, Some(Ok(())));

        assert!(matches!(
            outcome,
            CallbackOutcome::Failed(failure) if failure.contains("non-success NTSTATUS")
        ));
    }

    #[test]
    fn callback_health_adapter_requires_success_status_and_completion() {
        assert!(matches!(
            CallbackOutcomeAdapter::select(
                CloudCallbackClass::Actionable,
                actionable_callback_handler_outcome(None, 1),
                Some(Ok(())),
            ),
            CallbackOutcome::Succeeded
        ));
        assert!(matches!(
            CallbackOutcomeAdapter::select(
                CloudCallbackClass::Actionable,
                actionable_callback_handler_outcome(None, 0),
                Some(Err("CfExecute rejected completion".into())),
            ),
            CallbackOutcome::Failed(failure) if failure == "CfExecute rejected completion"
        ));
        assert!(matches!(
            CallbackOutcomeAdapter::select(
                CloudCallbackClass::Actionable,
                actionable_callback_handler_outcome(
                    Some("handler rejected request".into()),
                    0,
                ),
                Some(Ok(())),
            ),
            CallbackOutcome::Failed(failure) if failure == "handler rejected request"
        ));
    }

    #[test]
    fn callback_health_adapter_fetch_abort_status_never_counts_as_hydration_success() {
        let handler = actionable_callback_handler_outcome(None, 0xC000_0120u32 as i32);
        assert!(matches!(
            CallbackOutcomeAdapter::select(CloudCallbackClass::Actionable, handler, Some(Ok(()))),
            CallbackOutcome::Failed(_)
        ));
    }

    #[test]
    fn root_health_lifecycle_new_connect_uses_new_owner_instance_id() {
        assert_ne!(
            new_health_owner_instance_id(),
            new_health_owner_instance_id()
        );
    }

    #[test]
    fn root_health_lifecycle_unconfirmed_native_disconnect_retains_backing() {
        #[derive(Clone)]
        struct DropSpy(Arc<AtomicU64>);
        impl Drop for DropSpy {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let retained_drops = Arc::new(AtomicU64::new(0));
        let mut retained = NativeConnectionBacking::new(DropSpy(retained_drops.clone()));
        retained.retain_after_unconfirmed_disconnect();
        drop(retained);
        assert_eq!(retained_drops.load(Ordering::SeqCst), 0);

        let released_drops = Arc::new(AtomicU64::new(0));
        let mut released = NativeConnectionBacking::new(DropSpy(released_drops.clone()));
        released.release_after_confirmed_disconnect();
        drop(released);
        assert_eq!(released_drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_health_lifecycle_background_task_drain_is_async_on_current_thread() {
        let task = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        let mut tasks = vec![task];

        drain_provider_background_tasks(&mut tasks, Duration::from_millis(20))
            .await
            .unwrap();
        assert!(tasks.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn root_health_lifecycle_background_task_drain_timeout_is_retryable() {
        struct SlowDropFuture {
            started: Arc<AtomicBool>,
        }

        impl std::future::Future for SlowDropFuture {
            type Output = ();

            fn poll(
                self: std::pin::Pin<&mut Self>,
                _context: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Self::Output> {
                self.started.store(true, Ordering::SeqCst);
                std::task::Poll::Pending
            }
        }

        impl Drop for SlowDropFuture {
            fn drop(&mut self) {
                std::thread::sleep(Duration::from_millis(50));
            }
        }

        let completed = tokio::spawn(async {});
        let started = Arc::new(AtomicBool::new(false));
        let pending = tokio::spawn(SlowDropFuture {
            started: started.clone(),
        });
        while !completed.is_finished() || !started.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        let mut tasks = vec![completed, pending];

        assert!(
            drain_provider_background_tasks(&mut tasks, Duration::from_millis(1))
                .await
                .is_err()
        );
        assert_eq!(tasks.len(), 1);
        drain_provider_background_tasks(&mut tasks, Duration::from_millis(100))
            .await
            .unwrap();
        assert!(tasks.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_health_lifecycle_native_disconnect_runs_off_current_thread_runtime() {
        let mut attempt = OffThreadDisconnectAttempt::default();
        let finished = Arc::new(AtomicBool::new(false));
        let worker_finished = finished.clone();

        let (result, timer_observed_worker_running) = tokio::join!(
            attempt.run(move || {
                std::thread::sleep(Duration::from_millis(50));
                worker_finished.store(true, Ordering::SeqCst);
                Ok(())
            }),
            async {
                tokio::time::sleep(Duration::from_millis(5)).await;
                !finished.load(Ordering::SeqCst)
            }
        );

        result.unwrap();
        assert!(timer_observed_worker_running);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_health_lifecycle_cancelled_disconnect_reuses_exact_in_flight_attempt() {
        let mut attempt = OffThreadDisconnectAttempt::default();
        let calls = Arc::new(AtomicU64::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let worker_calls = calls.clone();
        let worker_started = started.clone();
        let worker_release = release.clone();
        let mut first = Box::pin(attempt.run(move || {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok(())
        }));

        while !started.load(Ordering::SeqCst) {
            tokio::select! {
                result = &mut first => panic!("disconnect completed unexpectedly: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        drop(first);
        assert!(attempt.has_in_flight());
        release.store(true, Ordering::SeqCst);

        let retry_calls = calls.clone();
        attempt
            .run(move || {
                retry_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!attempt.has_in_flight());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_health_lifecycle_drop_during_disconnect_never_starts_second_attempt() {
        let mut attempt = OffThreadDisconnectAttempt::default();
        let calls = Arc::new(AtomicU64::new(0));
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let worker_calls = calls.clone();
        let worker_started = started.clone();
        let worker_release = release.clone();
        let worker_finished = finished.clone();
        let mut running = Box::pin(attempt.run(move || {
            worker_calls.fetch_add(1, Ordering::SeqCst);
            worker_started.store(true, Ordering::SeqCst);
            while !worker_release.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
            worker_finished.store(true, Ordering::SeqCst);
            Ok(())
        }));

        while !started.load(Ordering::SeqCst) {
            tokio::select! {
                result = &mut running => panic!("disconnect completed unexpectedly: {result:?}"),
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
        }
        drop(running);
        drop(attempt);
        release.store(true, Ordering::SeqCst);
        while !finished.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn root_health_lifecycle_failed_disconnect_allows_sequential_retry() {
        let mut attempt = OffThreadDisconnectAttempt::default();
        let calls = Arc::new(AtomicU64::new(0));
        let first_calls = calls.clone();

        assert_eq!(
            attempt
                .run(move || {
                    first_calls.fetch_add(1, Ordering::SeqCst);
                    Err("native disconnect failed".to_string())
                })
                .await,
            Err("native disconnect failed".to_string())
        );
        assert!(!attempt.has_in_flight());

        let retry_calls = calls.clone();
        attempt
            .run(move || {
                retry_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn root_health_lifecycle_startup_cleanup_failure_retains_both_errors() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        let generation = telemetry.record_starting(health_test_time(1)).unwrap();

        assert!(telemetry.record_startup_cleanup_failure(
            generation,
            health_test_time(2),
            "inventory recovery failed",
            "native disconnect failed",
        ));

        let health = telemetry.snapshot(health_test_time(3), Duration::from_secs(30));
        assert_eq!(health.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(
            health.last_start_failure.as_deref(),
            Some("inventory recovery failed")
        );
        assert_eq!(
            health.last_disconnect_failure.as_deref(),
            Some("native disconnect failed")
        );
    }

    #[test]
    fn root_health_ignores_invalid_lifecycle_transitions() {
        let telemetry =
            RootHealthTelemetry::new(Uuid::new_v4(), Uuid::new_v4(), 4_242, health_test_time(0));
        let generation = telemetry.record_starting(health_test_time(1)).unwrap();
        telemetry.record_shutting_down(generation, health_test_time(2));
        telemetry.record_start_failure(generation, health_test_time(3), "connect failed");
        telemetry
            .record_running(generation, health_test_time(4))
            .unwrap();
        telemetry.record_heartbeat(generation, health_test_time(5));

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        assert_eq!(health.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(health.lifecycle_changed_at, health_test_time(3));
        assert_eq!(health.last_heartbeat_at, None);
    }

    #[test]
    fn callback_health_old_or_terminal_generation_observations_are_noops() {
        let (telemetry, first_generation) = running_health_telemetry();
        let old_observation = telemetry.begin_callback(
            first_generation,
            CloudCallbackKind::FetchData,
            health_test_time(4),
            health_test_time(14),
        );
        telemetry.record_stopped(first_generation, health_test_time(5));
        let second_generation = telemetry.record_starting(health_test_time(6)).unwrap();
        telemetry
            .record_running(second_generation, health_test_time(7))
            .unwrap();
        telemetry.record_heartbeat(second_generation, health_test_time(8));

        old_observation.finish_at(Err("old failure".into()), None, health_test_time(9));
        telemetry
            .begin_callback(
                first_generation,
                CloudCallbackKind::FetchData,
                health_test_time(10),
                health_test_time(20),
            )
            .finish_at(Err("mismatched failure".into()), None, health_test_time(11));
        telemetry.record_stopped(second_generation, health_test_time(12));
        drop(telemetry.begin_callback(
            second_generation,
            CloudCallbackKind::FetchData,
            health_test_time(13),
            health_test_time(23),
        ));

        let health = telemetry.snapshot(health_test_time(14), Duration::from_secs(30));
        let fetch_data = health
            .callback(CloudCallbackKind::FetchData)
            .expect("fetch-data health");
        assert_eq!(fetch_data.attempt_count, 0);
        assert_eq!(fetch_data.failure_count, 0);
        assert_eq!(fetch_data.in_flight_count, 0);
        assert!(health.hydration_failure.is_none());
    }

    #[test]
    fn callback_health_actionable_success_requires_handler_and_completion_success() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::ValidateData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(
                Ok(()),
                Some(Err("completion rejected".into())),
                health_test_time(5),
            );

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::ValidateData)
            .expect("validate-data health");

        assert!(!callback.callback_success_observed);
        assert_eq!(callback.failure_count, 1);
        assert_eq!(
            callback.last_failure.as_deref(),
            Some("completion rejected")
        );
        assert!(!health.healthy);
    }

    #[test]
    fn callback_health_each_actionable_operation_finalizes_exactly_once() {
        let (telemetry, generation) = running_health_telemetry();
        let actionable_kinds = [
            CloudCallbackKind::FetchData,
            CloudCallbackKind::ValidateData,
            CloudCallbackKind::FetchPlaceholders,
            CloudCallbackKind::Dehydrate,
            CloudCallbackKind::Delete,
            CloudCallbackKind::Rename,
        ];
        for (index, kind) in actionable_kinds.into_iter().enumerate() {
            telemetry
                .begin_callback(
                    generation,
                    kind,
                    health_test_time(4 + index as i64),
                    health_test_time(14 + index as i64),
                )
                .finish_at(Ok(()), Some(Ok(())), health_test_time(5 + index as i64));
        }

        let health = telemetry.snapshot(health_test_time(12), Duration::from_secs(30));
        for kind in actionable_kinds {
            let callback = health.callback(kind).expect("actionable callback health");
            assert_eq!(callback.attempt_count, 1, "{kind:?}");
            assert_eq!(callback.success_count, 1, "{kind:?}");
            assert_eq!(callback.failure_count, 0, "{kind:?}");
            assert_eq!(callback.in_flight_count, 0, "{kind:?}");
        }
    }

    #[test]
    fn callback_health_notification_success_requires_handler_only() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::Close,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Ok(()), None, health_test_time(5));

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::Close)
            .expect("close health");

        assert!(callback.callback_success_observed);
        assert_eq!(callback.success_count, 1);
        assert_eq!(callback.failure_count, 0);
        assert!(health.healthy);
    }

    #[test]
    fn callback_health_cancellation_observation_is_not_transaction_success() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::CancelFetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Ok(()), None, health_test_time(5));

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::CancelFetchData)
            .expect("cancel-fetch-data health");

        assert_eq!(callback.attempt_count, 1);
        assert!(!callback.callback_success_observed);
        assert_eq!(callback.success_count, 0);
        assert!(!health.hydration_success_observed);
    }

    #[test]
    fn callback_health_cancellation_observation_does_not_recover_handler_failure() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::CancelFetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(
                Err("cancellation handler failed".into()),
                None,
                health_test_time(5),
            );
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::CancelFetchData,
                health_test_time(6),
                health_test_time(16),
            )
            .finish_at(Ok(()), None, health_test_time(7));

        let health = telemetry.snapshot(health_test_time(8), Duration::from_secs(30));
        let cancellation = health
            .callback(CloudCallbackKind::CancelFetchData)
            .expect("cancel-fetch-data health");

        assert_eq!(cancellation.attempt_count, 2);
        assert_eq!(cancellation.failure_count, 1);
        assert_eq!(
            cancellation.unresolved_failure.as_deref(),
            Some("cancellation handler failed")
        );
        assert!(!cancellation.callback_success_observed);
        assert!(!health.healthy);
    }

    #[test]
    fn callback_health_unrelated_success_does_not_clear_fetch_data_failure() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Err("decrypt failed".into()), None, health_test_time(5));
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::Close,
                health_test_time(6),
                health_test_time(16),
            )
            .finish_at(Ok(()), None, health_test_time(7));

        let health = telemetry.snapshot(health_test_time(8), Duration::from_secs(30));

        assert_eq!(
            health
                .callback(CloudCallbackKind::FetchData)
                .expect("fetch-data health")
                .last_failure
                .as_deref(),
            Some("decrypt failed")
        );
        assert_eq!(health.hydration_failure.as_deref(), Some("decrypt failed"));
        assert!(!health.healthy);
    }

    #[test]
    fn callback_health_same_kind_success_recovers_current_failure() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .finish_at(Err("decrypt failed".into()), None, health_test_time(5));
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(6),
                health_test_time(16),
            )
            .finish_at(Ok(()), Some(Ok(())), health_test_time(7));

        let health = telemetry.snapshot(health_test_time(8), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::FetchData)
            .expect("fetch-data health");

        assert!(callback.callback_success_observed);
        assert!(callback.unresolved_failure.is_none());
        assert_eq!(callback.failure_count, 1);
        assert_eq!(callback.success_count, 1);
        assert!(health.hydration_success_observed);
        assert!(health.hydration_failure.is_none());
        assert!(health.healthy);
    }

    #[test]
    fn hydration_failure_and_transfer_telemetry_survive_provider_restart() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (first, generation, first_lease, _) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4_242,
            health_test_time(0),
            Duration::from_secs(30),
        );
        first
            .record_running(generation, health_test_time(1))
            .unwrap();
        first
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(2),
                health_test_time(12),
            )
            .finish_at(
                Err("authenticated decryption failed".into()),
                None,
                health_test_time(3),
            );
        first
            .record_hydration_transfer(
                generation,
                CloudHydrationTransferTelemetry {
                    requested_offset: 4096,
                    requested_length: 8192,
                    transferred_bytes: 0,
                    elapsed_millis: 27,
                    cancellation_observed: false,
                    completed_at: health_test_time(3),
                    execute_results: vec![CloudHydrationExecuteResult {
                        offset: 4096,
                        length: 8192,
                        completion_status: -1,
                        cf_execute_succeeded: true,
                    }],
                },
            )
            .unwrap();
        drop(first);
        drop(first_lease);

        let (second, _, _second_lease, _) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            8_484,
            health_test_time(4),
            Duration::from_secs(30),
        );
        let health = second.snapshot(health_test_time(5), Duration::from_secs(30));

        assert_eq!(
            health.hydration_failure.as_deref(),
            Some("authenticated decryption failed")
        );
        assert_eq!(
            health.transfer_health_state,
            CloudTransferHealthState::TransferDegraded
        );
        assert_eq!(
            health
                .last_hydration_transfer
                .as_ref()
                .map(|transfer| (transfer.requested_offset, transfer.requested_length)),
            Some((4096, 8192))
        );
        assert_eq!(
            health
                .callback(CloudCallbackKind::FetchData)
                .expect("new-generation callback health")
                .attempt_count,
            0
        );
    }

    #[test]
    fn caller_cancellation_is_neutral_hydration_health() {
        let (telemetry, generation) = running_health_telemetry();
        telemetry
            .begin_callback(
                generation,
                CloudCallbackKind::FetchData,
                health_test_time(4),
                health_test_time(14),
            )
            .expect("begin cancelled callback observation")
            .finish_observed_at(health_test_time(5));

        let health = telemetry.snapshot(health_test_time(6), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::FetchData)
            .expect("fetch-data health");
        assert_eq!(callback.attempt_count, 1);
        assert_eq!(callback.success_count, 0);
        assert_eq!(callback.failure_count, 0);
        assert!(!health.hydration_success_observed);
        assert!(health.hydration_failure.is_none());
        assert!(health.healthy);
    }

    #[test]
    fn callback_health_older_success_cannot_clear_newer_failure() {
        let (telemetry, generation) = running_health_telemetry();
        let older = telemetry.begin_callback(
            generation,
            CloudCallbackKind::FetchData,
            health_test_time(4),
            health_test_time(14),
        );
        let newer = telemetry.begin_callback(
            generation,
            CloudCallbackKind::FetchData,
            health_test_time(5),
            health_test_time(15),
        );

        newer.finish_at(Err("newer failure".into()), None, health_test_time(8));
        older.finish_at(Ok(()), Some(Ok(())), health_test_time(9));

        let health = telemetry.snapshot(health_test_time(10), Duration::from_secs(30));
        let fetch_data = health
            .callback(CloudCallbackKind::FetchData)
            .expect("fetch-data health");
        assert_eq!(
            fetch_data.unresolved_failure.as_deref(),
            Some("newer failure")
        );
        assert_eq!(health.hydration_failure.as_deref(), Some("newer failure"));
        assert!(health.hydration_success_observed);
        assert_eq!(health.last_hydration_success_at, Some(health_test_time(9)));
        assert!(!health.healthy);
    }

    #[test]
    fn callback_health_older_failure_cannot_override_newer_success() {
        let (telemetry, generation) = running_health_telemetry();
        let older = telemetry.begin_callback(
            generation,
            CloudCallbackKind::FetchData,
            health_test_time(4),
            health_test_time(14),
        );
        let newer = telemetry.begin_callback(
            generation,
            CloudCallbackKind::FetchData,
            health_test_time(5),
            health_test_time(15),
        );

        newer.finish_at(Ok(()), Some(Ok(())), health_test_time(9));
        older.finish_at(Err("older failure".into()), None, health_test_time(8));

        let health = telemetry.snapshot(health_test_time(10), Duration::from_secs(30));
        let fetch_data = health
            .callback(CloudCallbackKind::FetchData)
            .expect("fetch-data health");
        assert!(fetch_data.unresolved_failure.is_none());
        assert!(health.hydration_failure.is_none());
        assert_eq!(health.last_hydration_failure_at, Some(health_test_time(8)));
        assert_eq!(fetch_data.last_success_at, Some(health_test_time(9)));
        assert_eq!(fetch_data.last_failure_at, Some(health_test_time(8)));
        assert!(health.healthy);
    }

    #[test]
    fn callback_health_poisoned_mutex_does_not_panic_snapshot_finish_or_drop() {
        let (telemetry, generation) = running_health_telemetry();
        let finish_observation = telemetry.begin_callback(
            generation,
            CloudCallbackKind::Close,
            health_test_time(4),
            health_test_time(14),
        );
        let drop_observation = telemetry.begin_callback(
            generation,
            CloudCallbackKind::Dehydrate,
            health_test_time(5),
            health_test_time(15),
        );
        let poison_target = telemetry.clone();
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = poison_target.state.lock().expect("lock before poisoning");
            panic!("poison telemetry lock");
        }));
        assert!(poisoned.is_err());

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            finish_observation.finish_at(Ok(()), None, health_test_time(6));
            drop(drop_observation);
            telemetry.snapshot(health_test_time(7), Duration::from_secs(30))
        }));

        assert!(result.is_ok());
        let health = result.expect("poison recovery result");
        assert_eq!(
            health
                .callback(CloudCallbackKind::Close)
                .expect("close health")
                .success_count,
            1
        );
        assert_eq!(
            health
                .callback(CloudCallbackKind::Dehydrate)
                .expect("dehydrate health")
                .in_flight_count,
            0
        );
    }

    #[test]
    fn callback_health_in_flight_is_unhealthy_only_after_deadline() {
        let (telemetry, generation) = running_health_telemetry();
        let monotonic_base = Instant::now();
        let observation = telemetry.begin_callback_at(
            generation,
            CloudCallbackKind::FetchPlaceholders,
            health_test_time(4),
            health_test_time(14),
            monotonic_base,
        );

        let before_deadline = telemetry.snapshot_at(
            health_test_time(13),
            Duration::from_secs(30),
            monotonic_base + Duration::from_secs(9),
        );
        let after_deadline = telemetry.snapshot_at(
            health_test_time(15),
            Duration::from_secs(30),
            monotonic_base + Duration::from_secs(11),
        );

        assert_eq!(
            before_deadline
                .callback(CloudCallbackKind::FetchPlaceholders)
                .expect("fetch-placeholders health")
                .in_flight_count,
            1
        );
        assert!(before_deadline.healthy);
        assert_eq!(
            after_deadline
                .callback(CloudCallbackKind::FetchPlaceholders)
                .expect("fetch-placeholders health")
                .overdue_in_flight_count,
            1
        );
        assert!(!after_deadline.healthy);
        observation.finish_at(Ok(()), Some(Ok(())), health_test_time(16));
    }

    #[test]
    fn callback_health_dropping_unfinished_observation_records_failure() {
        let (telemetry, generation) = running_health_telemetry();
        drop(telemetry.begin_callback(
            generation,
            CloudCallbackKind::Dehydrate,
            health_test_time(4),
            health_test_time(14),
        ));

        let health = telemetry.snapshot(Utc::now(), Duration::from_secs(30));
        let callback = health
            .callback(CloudCallbackKind::Dehydrate)
            .expect("dehydrate health");

        assert_eq!(callback.in_flight_count, 0);
        assert_eq!(
            callback.last_failure.as_deref(),
            Some("completion outcome was not selected")
        );
        assert!(!health.healthy);
    }

    #[test]
    fn mutation_journal_round_trips_and_blocks_safe_unmount() {
        let root_id = Uuid::new_v4();
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.plaintext_path = Some(PathBuf::from(r"C:\cache\report.txt"));
        record.last_error = Some("writeback retry pending".to_string());

        let mut journal = CloudMutationJournal::empty(root_id);
        journal.records.push(record);

        let encoded = serde_json::to_vec(&journal).expect("serialize journal");
        let decoded: CloudMutationJournal =
            serde_json::from_slice(&encoded).expect("deserialize journal");

        assert_eq!(decoded.root_id, root_id);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].kind, CloudMutationKind::Writeback);

        let status = CloudProviderHost::status_from_journal(root_id, &decoded, None);
        assert!(!status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 1);
        assert_eq!(status.pending_writeback_paths, vec!["docs/report.txt"]);
        assert_eq!(
            status.last_error.as_deref(),
            Some("writeback retry pending")
        );
        assert!(matches!(
            status.unsafe_reasons.first(),
            Some(MountSafetyReason::PendingWriteback { count: 1, .. })
        ));
    }

    #[test]
    fn identical_pending_renames_are_coalesced_without_touching_other_mutations() {
        let root_id = Uuid::new_v4();
        let mut first = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            root_id,
            "docs/old.txt",
            Some(test_identity(root_id)),
        );
        first.target_relative_path = Some("docs/new.txt".to_string());
        first.target_plaintext_path = Some(PathBuf::from(r"C:\mount\docs\new.txt"));
        let retained_id = first.id;

        let mut duplicate = first.clone();
        duplicate.id = Uuid::new_v4();
        duplicate.sequence = 2;
        duplicate.attempts = 4;
        duplicate.last_error = Some("previous retry failed".to_string());
        let mut unrelated = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs/other.txt",
            Some(FileIdentityV1::new(
                root_id,
                ProviderEntryKind::File,
                "docs/other.txt",
                Some("different-object".into()),
                Some(1),
            )),
        );
        unrelated.sequence = 3;
        let candidate = first.clone();
        let mut records = vec![first, duplicate, unrelated];

        let existing = coalesce_matching_pending_renames(&mut records, &candidate);

        assert_eq!(existing, Some(retained_id));
        assert_eq!(records.len(), 2);
        assert_eq!(
            records
                .iter()
                .filter(|record| same_pending_rename(record, &candidate))
                .count(),
            1
        );
        assert!(records
            .iter()
            .any(|record| record.kind == CloudMutationKind::Delete));
    }

    #[test]
    fn state_parser_recovers_first_json_value_when_file_has_trailing_json() {
        let root_id = Uuid::new_v4();
        let mut first = CloudMutationJournal::empty(root_id);
        first.records.push(CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        ));
        let second = CloudMutationJournal::empty(root_id);

        let mut corrupted = serde_json::to_vec_pretty(&first).expect("serialize first");
        corrupted.extend_from_slice(&serde_json::to_vec_pretty(&second).expect("serialize second"));

        let strict_error = serde_json::from_slice::<CloudMutationJournal>(&corrupted)
            .expect_err("strict parser should reject trailing JSON");
        assert!(
            strict_error.to_string().contains("trailing characters"),
            "unexpected strict error: {strict_error}"
        );

        let (recovered, repaired) =
            parse_json_state_bytes::<CloudMutationJournal>(&corrupted).expect("recover journal");
        assert!(repaired);
        assert_eq!(recovered.root_id, root_id);
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.records[0].relative_path, "docs/report.txt");
    }

    #[test]
    fn json_state_recovery_preserves_valid_backup_for_future_writes() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal.json");
        let root_id = Uuid::new_v4();
        let first = CloudMutationJournal::empty(root_id);
        let mut second = CloudMutationJournal::empty(root_id);
        second.records.push(CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        ));

        write_json_file_pretty(&path, &first).unwrap();
        write_json_file_pretty(&path, &second).unwrap();
        fs::write(&path, b"truncated").unwrap();

        let recovered: CloudMutationJournal = read_json_state_file(&path).unwrap();
        assert!(recovered.records.is_empty());

        let mut repaired = recovered;
        repaired.records.push(CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs/old.txt",
            Some(test_identity(root_id)),
        ));
        write_json_file_pretty(&path, &repaired).unwrap();
        let reloaded: CloudMutationJournal = read_json_state_file(&path).unwrap();
        assert_eq!(reloaded.records.len(), 1);
        assert_eq!(reloaded.records[0].kind, CloudMutationKind::Delete);
    }

    #[test]
    fn mutation_journal_uses_checksummed_generations_and_recovers_backup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("journal.json");
        let root_id = Uuid::new_v4();
        let first = CloudMutationJournal::empty(root_id);
        write_mutation_journal(&path, &first).unwrap();
        let first_generation = recover_mutation_journal_for_writer(&path, root_id).unwrap();
        assert_eq!(first_generation.generation, 1);

        let mut second = first_generation;
        second.next_sequence = 1;
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.sequence = 1;
        second.records.push(record);
        write_mutation_journal(&path, &second).unwrap();
        assert_eq!(
            recover_mutation_journal_for_writer(&path, root_id)
                .unwrap()
                .generation,
            2
        );

        fs::write(&path, b"truncated").unwrap();
        let recovered = recover_mutation_journal_for_writer(&path, root_id).unwrap();
        assert_eq!(recovered.generation, 2);
        assert!(recovered.records.is_empty());
        assert_eq!(
            recover_mutation_journal_for_writer(&path, root_id)
                .unwrap()
                .generation,
            2
        );
    }

    #[test]
    fn empty_mutation_journal_is_safe_to_unmount() {
        let root_id = Uuid::new_v4();
        let journal = CloudMutationJournal::empty(root_id);

        let status = CloudProviderHost::status_from_journal(root_id, &journal, None);

        assert!(status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 0);
        assert!(status.unsafe_reasons.is_empty());
    }

    #[test]
    fn replay_expected_version_requires_absence_for_new_writeback() {
        let root_id = Uuid::new_v4();
        let record =
            CloudMutationRecord::new(CloudMutationKind::Writeback, root_id, "docs/new.txt", None);

        assert_eq!(
            replay_expected_version(&record, root_id).unwrap(),
            ExpectedProviderVersion::Absent
        );
    }

    #[test]
    fn replay_expected_version_uses_stored_exact_version() {
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.expected_version = Some(version.clone());

        assert_eq!(
            replay_expected_version(&record, root_id).unwrap(),
            ExpectedProviderVersion::Exact(version)
        );
    }

    #[test]
    fn replay_expected_version_rejects_existing_object_without_version() {
        let root_id = Uuid::new_v4();
        for kind in [
            CloudMutationKind::Writeback,
            CloudMutationKind::Delete,
            CloudMutationKind::Rename,
        ] {
            let record = CloudMutationRecord::new(
                kind,
                root_id,
                "docs/report.txt",
                Some(test_identity(root_id)),
            );

            let error = replay_expected_version(&record, root_id)
                .unwrap_err()
                .to_string();
            assert!(error.contains("refusing unsafe replay"), "{error}");
            assert!(error.contains("docs/report.txt"), "{error}");
        }
    }

    #[test]
    fn replay_expected_version_rejects_malformed_identityless_records() {
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut versioned_create =
            CloudMutationRecord::new(CloudMutationKind::Writeback, root_id, "docs/new.txt", None);
        versioned_create.expected_version = Some(version.clone());
        let identityless_delete =
            CloudMutationRecord::new(CloudMutationKind::Delete, root_id, "docs/report.txt", None);
        let mut delete_with_rename_target = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        delete_with_rename_target.expected_version = Some(version);
        delete_with_rename_target.target_relative_path = Some("archive/report.txt".to_string());

        for record in [
            versioned_create,
            identityless_delete,
            delete_with_rename_target,
        ] {
            let error = replay_expected_version(&record, root_id)
                .unwrap_err()
                .to_string();
            assert!(error.contains("refusing unsafe replay"), "{error}");
            assert!(error.contains(&record.relative_path), "{error}");
        }
    }

    #[test]
    fn replay_expected_version_rejects_cross_root_invalid_and_traversing_records() {
        let root_id = Uuid::new_v4();
        let other_root = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut cross_root = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            other_root,
            "docs/report.txt",
            Some(test_identity(other_root)),
        );
        cross_root.expected_version = Some(version.clone());
        let mut invalid_hash = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        invalid_hash.identity.as_mut().unwrap().path_hash_hex = "invalid".to_string();
        invalid_hash.expected_version = Some(version);
        let traversal = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "../outside.txt",
            None,
        );

        for record in [cross_root, invalid_hash, traversal] {
            let error = replay_expected_version(&record, root_id)
                .unwrap_err()
                .to_string();
            assert!(error.contains("refusing unsafe replay"), "{error}");
        }
    }

    #[test]
    fn replay_expected_version_rejects_non_file_or_unstable_existing_identity() {
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut directory = CloudMutationRecord::new(
            CloudMutationKind::Delete,
            root_id,
            "docs",
            Some(hybridcipher_provider_core::FileIdentityV1::new(
                root_id,
                ProviderEntryKind::Directory,
                "docs",
                None,
                None,
            )),
        );
        directory.expected_version = Some(version.clone());
        let mut unstable_file = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(hybridcipher_provider_core::FileIdentityV1::new(
                root_id,
                ProviderEntryKind::File,
                "docs/report.txt",
                None,
                Some(7),
            )),
        );
        unstable_file.expected_version = Some(version);

        for record in [directory, unstable_file] {
            assert!(replay_expected_version(&record, root_id).is_err());
        }
    }

    #[test]
    fn replay_plaintext_path_must_match_the_registered_sync_root_path() {
        let temp = tempfile::tempdir().unwrap();
        let sync_root = temp.path().join("sync");
        let outside = temp.path().join("outside.txt");
        let expected = sync_root.join("docs/report.txt");
        let wrong_inside = sync_root.join("docs/other.txt");
        fs::create_dir_all(expected.parent().unwrap()).unwrap();
        fs::write(&expected, b"expected").unwrap();
        fs::write(&wrong_inside, b"wrong").unwrap();
        fs::write(&outside, b"outside").unwrap();
        let root_id = Uuid::new_v4();
        let record = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            None,
        );

        validate_replay_plaintext_path(&record, &sync_root, &expected, "docs/report.txt").unwrap();
        assert!(validate_replay_plaintext_path(
            &record,
            &sync_root,
            &wrong_inside,
            "docs/report.txt"
        )
        .is_err());
        assert!(
            validate_replay_plaintext_path(&record, &sync_root, &outside, "docs/report.txt")
                .is_err()
        );

        #[cfg(unix)]
        {
            let symlink = sync_root.join("docs/symlink.txt");
            std::os::unix::fs::symlink(&outside, &symlink).unwrap();
            assert!(validate_replay_plaintext_path(
                &record,
                &sync_root,
                &symlink,
                "docs/report.txt"
            )
            .is_err());
        }
    }

    #[test]
    fn rename_replay_accepts_source_plaintext_path_before_target_exists() {
        let temp = tempfile::tempdir().unwrap();
        let sync_root = temp.path().join("sync");
        let source = sync_root.join("docs/report.txt");
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::write(&source, b"rename source").unwrap();
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.target_relative_path = Some("docs/renamed.txt".to_string());
        record.plaintext_path = Some(source);
        record.expected_version = Some(version);

        validate_replay_plaintext_paths(&record, &sync_root).unwrap();
        assert!(matches!(
            replay_expected_version(&record, root_id).unwrap(),
            ExpectedProviderVersion::Exact(_)
        ));
    }

    #[test]
    fn rename_replay_accepts_target_plaintext_path_after_local_move() {
        let temp = tempfile::tempdir().unwrap();
        let sync_root = temp.path().join("sync");
        let target = sync_root.join("docs/renamed.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"renamed source").unwrap();
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "file-1",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.target_relative_path = Some("docs/renamed.txt".to_string());
        record.target_plaintext_path = Some(target);
        record.expected_version = Some(version);

        validate_replay_plaintext_paths(&record, &sync_root).unwrap();
        assert!(matches!(
            replay_expected_version(&record, root_id).unwrap(),
            ExpectedProviderVersion::Exact(_)
        ));
    }

    #[test]
    fn directory_rename_replay_uses_unchecked_precondition() {
        let root_id = Uuid::new_v4();
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            root_id,
            "docs",
            Some(hybridcipher_provider_core::FileIdentityV1::new(
                root_id,
                ProviderEntryKind::Directory,
                "docs",
                None,
                None,
            )),
        );
        record.target_relative_path = Some("archive".to_string());

        assert!(matches!(
            replay_expected_version(&record, root_id).unwrap(),
            ExpectedProviderVersion::Unchecked
        ));
    }

    #[test]
    fn v2_identity_is_stable_across_rename() {
        let root_id = Uuid::new_v4();
        let identity =
            CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "stable-file-id");

        let before = identity.to_bytes().unwrap();
        let after = CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "stable-file-id")
            .to_bytes()
            .unwrap();

        assert_eq!(before, after);
        assert!(!String::from_utf8(before).unwrap().contains("report.txt"));
    }

    #[test]
    fn legacy_file_identity_migrates_to_stable_v2_object_id() {
        let root_id = Uuid::new_v4();
        let legacy = test_identity(root_id);

        let migrated = CloudObjectIdentityV2::from_legacy(&legacy, None).unwrap();

        assert_eq!(migrated.root_id, root_id);
        assert_eq!(migrated.kind, ProviderEntryKind::File);
        assert_eq!(migrated.object_id, "file-1");
    }

    #[test]
    fn legacy_directory_identity_requires_persisted_object_id() {
        let root_id = Uuid::new_v4();
        let legacy = hybridcipher_provider_core::FileIdentityV1::new(
            root_id,
            ProviderEntryKind::Directory,
            "docs",
            None,
            None,
        );
        let directory_id = Uuid::new_v4();

        assert!(CloudObjectIdentityV2::from_legacy(&legacy, None).is_err());
        let migrated = CloudObjectIdentityV2::from_legacy(&legacy, Some(directory_id)).unwrap();
        assert_eq!(migrated.object_id, directory_id.to_string());
    }

    #[test]
    fn state_store_recovers_last_valid_backup_generation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = CloudStateStore::new(temp.path().join("state.json"), root_id);
        store
            .transaction(|state| {
                state.items.insert(
                    "file-1".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-1"),
                        "docs/report.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();
        store
            .transaction(|state| {
                state.items.insert(
                    "file-2".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-2"),
                        "docs/second.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();

        fs::write(store.path(), b"truncated").unwrap();
        let recovered = store.load().unwrap();

        assert_eq!(recovered.generation, 1);
        assert!(recovered.items.contains_key("file-1"));
        assert!(!recovered.items.contains_key("file-2"));

        store
            .transaction(|state| {
                state.items.insert(
                    "file-3".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-3"),
                        "docs/third.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();
        let after_recovery_write = store.load().unwrap();
        assert_eq!(after_recovery_write.generation, 2);
        assert!(after_recovery_write.items.contains_key("file-1"));
        assert!(after_recovery_write.items.contains_key("file-3"));
    }

    #[test]
    fn state_store_serializes_concurrent_transactions_without_lost_items() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = Arc::new(CloudStateStore::new(
            temp.path().join("state.json"),
            root_id,
        ));
        let mut threads = Vec::new();
        for index in 0..12 {
            let store = store.clone();
            threads.push(std::thread::spawn(move || {
                store
                    .transaction(|state| {
                        let object_id = format!("file-{index}");
                        state.items.insert(
                            object_id.clone(),
                            CloudItemState::new(
                                CloudObjectIdentityV2::new(
                                    root_id,
                                    ProviderEntryKind::File,
                                    object_id,
                                ),
                                format!("docs/{index}.txt"),
                                None,
                            ),
                        );
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let state = store.load().unwrap();
        assert_eq!(state.items.len(), 12);
        assert_eq!(state.generation, 12);
    }

    #[test]
    fn state_store_generation_checked_replace_rejects_stale_plan() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = CloudStateStore::new(temp.path().join("state.json"), root_id);
        store
            .transaction(|state| {
                state.items.insert(
                    "file-1".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-1"),
                        "docs/report.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();

        let planned_from = store.load().unwrap();
        let mut replacement = planned_from.clone();
        replacement.items.insert(
            "remote-file".to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "remote-file"),
                "docs/remote.txt",
                None,
            ),
        );
        store
            .transaction(|state| {
                state.items.insert(
                    "callback-file".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(
                            root_id,
                            ProviderEntryKind::File,
                            "callback-file",
                        ),
                        "docs/callback.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();

        let error = store
            .replace_if_generation(planned_from.generation, replacement)
            .expect_err("stale reconciliation plan must be rejected");
        assert!(error.to_string().contains("generation changed"));

        let current = store.load().unwrap();
        assert!(current.items.contains_key("callback-file"));
        assert!(!current.items.contains_key("remote-file"));
    }

    #[test]
    fn state_store_generation_checked_replace_commits_current_plan() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = CloudStateStore::new(temp.path().join("state.json"), root_id);
        let planned_from = store.load().unwrap();
        let mut replacement = planned_from.clone();
        replacement.items.insert(
            "remote-file".to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "remote-file"),
                "docs/remote.txt",
                None,
            ),
        );

        store
            .replace_if_generation(planned_from.generation, replacement)
            .unwrap();

        let current = store.load().unwrap();
        assert_eq!(current.generation, planned_from.generation + 1);
        assert!(current.items.contains_key("remote-file"));
    }

    #[test]
    fn cache_path_is_versioned_by_stable_identity_not_relative_path() {
        let root_id = Uuid::new_v4();
        let identity =
            CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "stable-file-id");
        let version = hybridcipher_provider_core::ProviderContentVersion::from_components(
            "stable-file-id",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let cache_root = Path::new("cache");

        let before = versioned_cache_path(cache_root, &identity, &version);
        let renamed = versioned_cache_path(cache_root, &identity, &version);

        assert_eq!(before, renamed);
        assert!(before.to_string_lossy().contains("stable-file-id"));
        assert!(before.to_string_lossy().contains(version.as_str()));
    }

    #[test]
    fn inventory_upsert_preserves_file_object_id_across_rename() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let first = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            4,
            64,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(7),
        );
        let renamed = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "archive/report.txt",
            PathBuf::from("report.txt.encrypted"),
            4,
            64,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(7),
        );

        let before = state.upsert_inventory_entry(&first).unwrap();
        let after = state.upsert_inventory_entry(&renamed).unwrap();

        assert_eq!(before.object_id, after.object_id);
        assert_eq!(state.items.len(), 1);
        assert_eq!(
            state.items["stable-file-id"].relative_path,
            "archive/report.txt"
        );
    }

    #[test]
    fn inventory_upsert_preserves_stable_directory_object_id_across_remote_rename() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let first = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            PathBuf::from("encrypted/docs"),
            Utc::now(),
            "stable-directory-id",
            7,
        );
        let renamed = ProviderEntry::cache_directory_with_identity(
            root_id,
            "archive",
            PathBuf::from("encrypted/archive"),
            Utc::now(),
            "stable-directory-id",
            7,
        );

        let before = state.upsert_inventory_entry(&first).unwrap();
        let after = state.upsert_inventory_entry(&renamed).unwrap();

        assert_eq!(before.object_id, "stable-directory-id");
        assert_eq!(before.object_id, after.object_id);
        assert_eq!(state.items.len(), 1);
        assert_eq!(state.items["stable-directory-id"].relative_path, "archive");
        assert!(state.directory_ids.is_empty());
    }

    #[test]
    fn inventory_upsert_keeps_legacy_directory_path_uuid_fallback() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let entry = ProviderEntry::cache_directory(
            root_id,
            "docs",
            PathBuf::from("encrypted/docs"),
            Utc::now(),
        );

        let first = state.upsert_inventory_entry(&entry).unwrap();
        let second = state.upsert_inventory_entry(&entry).unwrap();

        assert_eq!(first.object_id, second.object_id);
        assert_eq!(state.directory_ids["docs"].to_string(), first.object_id);
    }

    #[test]
    fn inventory_upsert_rejects_cross_kind_object_id_collision() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let file = ProviderEntry::cache_file_with_identity(
            root_id,
            "report.txt",
            PathBuf::from("report.txt.encrypted"),
            0,
            64,
            Utc::now(),
            None,
            Some("shared-object-id".to_string()),
            Some(7),
        );
        let directory = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            PathBuf::from("docs"),
            Utc::now(),
            "shared-object-id",
            7,
        );
        state.upsert_inventory_entry(&file).unwrap();

        let error = state.upsert_inventory_entry(&directory).unwrap_err();

        assert!(matches!(error, CloudProviderError::Callback(_)));
        assert_eq!(
            state.items["shared-object-id"].identity.kind,
            ProviderEntryKind::File
        );
    }

    #[test]
    fn dirty_inventory_item_keeps_expected_version_during_remote_scan() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let first = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            4,
            64,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(7),
        );
        let changed = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "remote/report-renamed.txt",
            PathBuf::from("report.txt.encrypted"),
            99,
            128,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(8),
        );

        state.upsert_inventory_entry(&first).unwrap();
        let expected = state.items["stable-file-id"].content_version.clone();
        state.items.get_mut("stable-file-id").unwrap().dirty = true;
        state.upsert_inventory_entry(&changed).unwrap();

        assert_eq!(state.items["stable-file-id"].content_version, expected);
        assert!(state.items["stable-file-id"].dirty);
        assert_eq!(
            state.items["stable-file-id"].relative_path,
            "docs/report.txt"
        );
    }

    #[test]
    fn committed_inventory_upsert_clears_dirty_state_after_local_writeback() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let first = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            4,
            64,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(7),
        );
        let committed = hybridcipher_provider_core::ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            99,
            128,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(8),
        );

        state.upsert_inventory_entry(&first).unwrap();
        state.items.get_mut("stable-file-id").unwrap().dirty = true;
        state.upsert_committed_inventory_entry(&committed).unwrap();

        let item = &state.items["stable-file-id"];
        assert!(!item.dirty);
        assert_eq!(item.content_version, committed.content_version());
        assert_eq!(item.relative_path, "docs/report.txt");
    }

    #[test]
    fn local_directory_rename_migrates_descendants_without_changing_ids() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        let directory_id = Uuid::new_v4();
        state.directory_ids.insert("docs".to_string(), directory_id);
        state.items.insert(
            directory_id.to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(
                    root_id,
                    ProviderEntryKind::Directory,
                    directory_id.to_string(),
                ),
                "docs",
                None,
            ),
        );
        state.items.insert(
            "file-1".to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-1"),
                "docs/nested/report.txt",
                None,
            ),
        );

        state.migrate_directory_path("docs", "archive").unwrap();

        assert_eq!(state.directory_ids["archive"], directory_id);
        assert_eq!(
            state.items[&directory_id.to_string()].relative_path,
            "archive"
        );
        assert_eq!(
            state.items["file-1"].relative_path,
            "archive/nested/report.txt"
        );
    }

    #[test]
    fn local_directory_rename_migrates_stable_identity_without_legacy_path_map() {
        let root_id = Uuid::new_v4();
        let mut state = CloudRootPersistentState::empty(root_id);
        state.items.insert(
            "stable-directory-id".to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(
                    root_id,
                    ProviderEntryKind::Directory,
                    "stable-directory-id",
                ),
                "docs",
                None,
            ),
        );
        state.items.insert(
            "file-1".to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "file-1"),
                "docs/report.txt",
                None,
            ),
        );

        state.migrate_directory_path("docs", "archive").unwrap();

        assert_eq!(state.items["stable-directory-id"].relative_path, "archive");
        assert_eq!(state.items["file-1"].relative_path, "archive/report.txt");
        assert!(state.directory_ids.is_empty());
    }

    #[test]
    fn startup_placeholder_restore_falls_back_to_pre_upgrade_directory_uuid() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Upgrade Restore Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let paths = host.runtime_paths(root_id).unwrap();
        let legacy_id = Uuid::new_v4();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|state| {
                state.directory_ids.insert("docs".to_string(), legacy_id);
                state.items.insert(
                    legacy_id.to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(
                            root_id,
                            ProviderEntryKind::Directory,
                            legacy_id.to_string(),
                        ),
                        "docs",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();
        let entry = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
            "stable-directory-id",
            7,
        );

        let restored = host
            .load_existing_placeholder_entries(&registration, vec![entry], &paths)
            .unwrap();

        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].identity.object_id, legacy_id.to_string());
    }

    #[test]
    fn startup_placeholder_restore_rejects_cross_kind_stable_id_collision() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Cross-kind Restore Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let paths = host.runtime_paths(root_id).unwrap();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|state| {
                state.items.insert(
                    "shared-object-id".to_string(),
                    CloudItemState::new(
                        CloudObjectIdentityV2::new(
                            root_id,
                            ProviderEntryKind::File,
                            "shared-object-id",
                        ),
                        "removed-file.txt",
                        None,
                    ),
                );
                Ok(())
            })
            .unwrap();
        let entry = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
            "shared-object-id",
            7,
        );

        let error = host
            .load_existing_placeholder_entries(&registration, vec![entry], &paths)
            .unwrap_err();

        assert!(matches!(error, CloudProviderError::Callback(_)));
    }

    #[test]
    fn safe_cache_cleanup_removes_plaintext_but_preserves_identity_state() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("secret.plain"), b"secret").unwrap();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|state| {
                state
                    .directory_ids
                    .insert("docs".to_string(), Uuid::new_v4());
                Ok(())
            })
            .unwrap();
        write_mutation_journal(&paths.journal_path, &CloudMutationJournal::empty(root_id)).unwrap();

        host.cleanup_plaintext_cache(root_id).unwrap();

        assert!(!paths.cache_dir.exists());
        assert!(paths.state_path.exists());
    }

    #[test]
    fn root_writer_lease_excludes_other_owners_until_every_shared_owner_drops() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let lock_path = temp.path().join("root.writer.lock");
        let first = Arc::new(RootWriterLease::acquire(root_id, &lock_path).unwrap());
        let shared = first.clone();

        assert!(RootWriterLease::acquire(root_id, &lock_path).is_err());
        drop(first);
        assert!(RootWriterLease::acquire(root_id, &lock_path).is_err());
        drop(shared);

        RootWriterLease::acquire(root_id, &lock_path).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writer_quiescence_waits_without_blocking_current_thread_and_times_out_safely() {
        let temp = tempfile::tempdir().unwrap();
        let lease = Arc::new(
            RootWriterLease::acquire(Uuid::new_v4(), &temp.path().join("writer.lock")).unwrap(),
        );
        let worker_lease = lease.clone();
        let worker = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(worker_lease);
        });

        assert!(wait_for_writer_quiescence(&lease, Duration::from_millis(250)).await);
        worker.await.unwrap();

        let retained = lease.clone();
        assert!(!wait_for_writer_quiescence(&lease, Duration::from_millis(20)).await);
        drop(retained);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recovery_waits_for_callback_lease_longer_than_old_retry_window() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let path = temp.path().join("writer.lock");
        let lease = Arc::new(RootWriterLease::acquire(root_id, &path).unwrap());
        let callback_lease = lease.clone();
        let callback = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1500)).await;
            drop(callback_lease);
        });
        // The former three attempts finished after just 250 + 500 milliseconds.
        assert!(!wait_for_writer_quiescence(&lease, Duration::from_millis(750)).await);
        assert!(RootWriterLease::acquire(root_id, &path).is_err());
        assert!(wait_for_writer_quiescence(&lease, Duration::from_secs(3)).await);
        callback.await.unwrap();
        drop(lease);
        RootWriterLease::acquire(root_id, &path).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_barrier_drains_active_work_before_rejecting_new_callbacks() {
        let activity = Arc::new(StartupRecoveryActivity::default());
        activity.mark_running();
        let operation_lock = Arc::new(tokio::sync::Mutex::new(()));
        let active_operation = operation_lock.lock().await;
        let barrier_activity = activity.clone();
        let barrier_lock = operation_lock.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let barrier = tokio::spawn(async move {
            let _ = started_tx.send(());
            begin_provider_shutdown_barrier(&barrier_activity, &barrier_lock).await;
        });

        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert!(!barrier.is_finished());
        activity.ensure_running().unwrap();

        drop(active_operation);
        barrier.await.unwrap();
        assert!(activity.ensure_running().is_err());

        activity.mark_running();
        activity.ensure_running().unwrap();
    }

    #[test]
    fn startup_cache_preparation_removes_plaintext_without_touching_durable_state() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("versioned.plain"), b"plaintext").unwrap();
        fs::write(paths.cache_dir.join("abandoned.tmp"), b"snapshot").unwrap();
        fs::write(&paths.journal_path, b"journal sentinel").unwrap();
        fs::write(&paths.state_path, b"state sentinel").unwrap();

        prepare_plaintext_cache_for_startup(&paths).unwrap();

        assert!(paths.cache_dir.is_dir());
        assert_eq!(fs::read_dir(&paths.cache_dir).unwrap().count(), 0);
        assert_eq!(fs::read(&paths.journal_path).unwrap(), b"journal sentinel");
        assert_eq!(fs::read(&paths.state_path).unwrap(), b"state sentinel");
    }

    #[test]
    fn callback_operation_completion_is_attempted_once_for_success_and_error() {
        let completions = Arc::new(Mutex::new(Vec::new()));
        let success_completions = completions.clone();
        let success_error = complete_callback_once::<_, &str>(Ok(7), 99, move |value| {
            success_completions.lock().unwrap().push(value);
        });
        let failure_completions = completions.clone();
        let failure_error = complete_callback_once(Err("failed"), 99, move |value| {
            failure_completions.lock().unwrap().push(value);
        });

        assert_eq!(success_error, None);
        assert_eq!(failure_error, Some("failed"));
        assert_eq!(*completions.lock().unwrap(), vec![7, 99]);
    }

    #[test]
    fn hydration_request_policy_accepts_large_ranges_and_rejects_invalid_ones() {
        let accepted = validate_hydration_request(8192, 4096, 4096).unwrap();
        assert_eq!(accepted.offset, 4096);
        assert_eq!(accepted.length, 4096);
        let eof = validate_hydration_request(4097, 4096, 1).unwrap();
        assert_eq!(eof.offset, 4096);
        assert_eq!(eof.length, 1);

        let large_length = (16 * 1024 * 1024) + 4097;
        let large = validate_hydration_request(large_length as u64, 0, large_length as i64)
            .expect("requests larger than the former 16 MiB cap must be accepted");
        let transfers = hydration_transfer_ranges(large).unwrap();
        assert!(transfers.len() > 4);
        assert_eq!(
            transfers.iter().map(|range| range.length).sum::<usize>(),
            large_length
        );
        assert!(transfers[..transfers.len() - 1]
            .iter()
            .all(|range| range.length % HYDRATION_TRANSFER_ALIGNMENT_BYTES == 0));

        for (file_size, offset, length) in [
            (1024, -1, 1),
            (1024, 0, 0),
            (1024, 1000, 25),
            (8192, 128, 4096),
            (8192, 0, 4097),
            (1024, i64::MAX, 2),
        ] {
            assert!(
                validate_hydration_request(file_size, offset, length).is_err(),
                "unsafe hydration request unexpectedly passed: size={file_size}, offset={offset}, length={length}"
            );
        }

        assert_eq!(hydration_completion_range(8192, 4096, 4096), (4096, 4096));
        assert_eq!(hydration_completion_range(1024, 128, 256), (0, 4096));
        assert_eq!(hydration_completion_range(0, -1, 0), (0, 4096));
    }

    #[test]
    fn hydration_cancellation_aborts_intersecting_transfer_ranges() {
        let registry = HydrationCancellationRegistry::default();
        let first = registry.register(11, 100, 100);
        let same_transfer_other_range = registry.register(11, 400, 50);
        let other_transfer = registry.register(12, 100, 100);

        assert_eq!(registry.cancel_intersecting(11, 110, 10), 1);
        assert!(!first.is_cancelled());
        assert_eq!(first.cancelled_ranges(100, 100), vec![(110, 120)]);
        assert!(!same_transfer_other_range.is_cancelled());
        assert!(!other_transfer.is_cancelled());
        assert_eq!(registry.cancel_intersecting(11, 250, 10), 0);
        assert_eq!(registry.cancel_intersecting(11, 100, 100), 1);
        assert!(first.is_cancelled());
        assert_eq!(registry.cancel_intersecting(12, 90, 120), 1);
        assert!(other_transfer.is_cancelled());
        assert_eq!(registry.active_count(), 3);

        drop(first);
        drop(same_transfer_other_range);
        drop(other_transfer);
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn hydration_worker_gate_allows_two_workers_and_bounds_the_queue() {
        let gate = HydrationWorkerGate::default();
        let first = gate.try_begin().unwrap();
        let second = gate.try_begin().unwrap();

        assert!(gate.try_begin().is_err());
        drop(first);
        assert!(gate.try_begin().is_ok());
        drop(second);
    }

    #[test]
    fn hydration_temporary_file_is_always_removed_on_drop() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let lease =
            Arc::new(RootWriterLease::acquire(root_id, &temp.path().join("writer.lock")).unwrap());
        let abandoned_path = temp.path().join("abandoned.plain.tmp");
        fs::write(&abandoned_path, b"plaintext").unwrap();

        drop(HydrationTemporaryFile::new(
            abandoned_path.clone(),
            lease.clone(),
        ));
        assert!(!abandoned_path.exists());

        let completed_path = temp.path().join("completed.plain.tmp");
        fs::write(&completed_path, b"plaintext").unwrap();
        drop(HydrationTemporaryFile::new(completed_path.clone(), lease));
        assert!(!completed_path.exists());
    }

    #[test]
    fn successful_startup_recovery_clears_abandoned_operation_markers() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = CloudStateStore::new(temp.path().join("state.json"), root_id);
        let identity =
            CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "stable-file-id");
        store
            .transaction(|state| {
                state.items.insert(
                    identity.object_id.clone(),
                    CloudItemState::new(identity.clone(), "docs/report.txt", None),
                );
                state.conflicts.push(CloudConflictRecord {
                    id: Uuid::new_v4(),
                    object_id: identity.object_id.clone(),
                    relative_path: "docs/report.txt".to_string(),
                    expected_version: None,
                    actual_version: None,
                    local_plaintext_path: Some(temp.path().join("report.txt")),
                    created_at: Utc::now(),
                });
                state.ingestion_in_progress = 2;
                state.reconciliation_in_progress = true;
                Ok(())
            })
            .unwrap();

        assert!(store.complete_startup_recovery().unwrap());
        let recovered = store.load().unwrap();

        assert_eq!(recovered.ingestion_in_progress, 0);
        assert!(!recovered.reconciliation_in_progress);
        assert_eq!(recovered.items.len(), 1);
        assert_eq!(recovered.conflicts.len(), 1);
        assert_eq!(recovered.root_id, root_id);

        let recovered_generation = recovered.generation;
        assert!(!store.complete_startup_recovery().unwrap());
        assert_eq!(store.load().unwrap().generation, recovered_generation);
    }

    #[test]
    fn failed_startup_recovery_rearms_unsafe_marker() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = CloudStateStore::new(temp.path().join("state.json"), root_id);

        store.require_startup_recovery().unwrap();
        let state = store.load().unwrap();

        assert!(state.reconciliation_in_progress);
        assert!(state.has_operation_in_progress());
        assert!(!state.safe_to_unmount(0));
    }

    #[test]
    fn failed_startup_gate_rejects_waiting_mutation_work() {
        let gate = StartupRecoveryActivity::default();
        gate.ensure_wait_allowed().unwrap();
        assert!(gate.ensure_running().is_err());

        gate.mark_running();
        gate.ensure_running().unwrap();

        gate.begin_shutdown();

        assert!(gate.ensure_wait_allowed().is_err());
        let error = gate.ensure_running().unwrap_err().to_string();
        assert!(error.contains("not accepting provider work"), "{error}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hydration_waiter_survives_startup_and_wakes_when_running() {
        let activity = Arc::new(StartupRecoveryActivity::default());
        let waiting_activity = activity.clone();
        let waiter = tokio::spawn(async move { waiting_activity.wait_until_running().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        activity.mark_running();

        tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("startup waiter should wake")
            .expect("startup waiter task should complete")
            .expect("running transition should be accepted");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hydration_waiter_wakes_with_error_when_startup_aborts() {
        let activity = Arc::new(StartupRecoveryActivity::default());
        let waiting_activity = activity.clone();
        let waiter = tokio::spawn(async move { waiting_activity.wait_until_running().await });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        activity.begin_shutdown();

        let error = tokio::time::timeout(Duration::from_millis(100), waiter)
            .await
            .expect("startup waiter should wake")
            .expect("startup waiter task should complete")
            .expect_err("aborted startup must reject hydration");
        assert!(matches!(
            error,
            CloudProviderError::StartupRecoveryUnavailable
        ));
    }

    #[test]
    fn ingestion_scan_descends_through_placeholder_directories() {
        let temp = tempfile::tempdir().unwrap();
        let placeholder_directory = temp.path().join("existing-placeholder");
        let nested_file = placeholder_directory.join("new-child.txt");
        fs::create_dir_all(&placeholder_directory).unwrap();
        fs::write(&nested_file, b"new plaintext").unwrap();

        let candidates = collect_ingestion_candidates(temp.path(), &|path, _metadata| {
            path == placeholder_directory
        })
        .unwrap();

        assert!(candidates.contains(&nested_file));
        assert!(!candidates.contains(&placeholder_directory));
    }

    #[test]
    fn same_path_file_requires_checked_writeback() {
        let root_id = Uuid::new_v4();
        let version = ProviderContentVersion::from_components(
            "stable-file-id",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[9; 12]),
            None,
        );
        let item = CloudItemState::new(
            CloudObjectIdentityV2::new(root_id, ProviderEntryKind::File, "stable-file-id"),
            "docs/report.txt",
            Some(version.clone()),
        );

        assert_eq!(
            existing_file_ingestion_expected_version(&item).unwrap(),
            ExpectedProviderVersion::Exact(version)
        );
    }

    #[test]
    fn failed_restored_root_start_preserves_recovery_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Recovery Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();

        let paths = host.runtime_paths(root_id).unwrap();
        let mut journal = CloudMutationJournal::empty(root_id);
        journal.records.push(CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        ));
        write_mutation_journal(&paths.journal_path, &journal).unwrap();
        write_mutation_journal(&paths.journal_path, &journal).unwrap();
        let store = CloudStateStore::new(paths.state_path.clone(), root_id);
        store
            .transaction(|state| {
                state.ingestion_in_progress = 1;
                Ok(())
            })
            .unwrap();
        store
            .transaction(|state| {
                state.reconciliation_in_progress = true;
                Ok(())
            })
            .unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("recovery.plain"), b"pending plaintext").unwrap();

        host.cleanup_failed_root_start(root_id, true).unwrap();

        assert!(host.root_state_path(root_id).unwrap().exists());
        assert!(paths.journal_path.exists());
        assert!(paths.journal_path.with_extension("json.bak").exists());
        assert!(paths.state_path.exists());
        assert!(paths.state_path.with_extension("json.bak").exists());
        assert!(paths.cache_dir.join("recovery.plain").exists());
    }

    #[test]
    fn failed_new_root_start_removes_new_runtime_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "New Root Failure Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        let paths = host.runtime_paths(root_id).unwrap();
        write_mutation_journal(&paths.journal_path, &CloudMutationJournal::empty(root_id)).unwrap();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|_| Ok(()))
            .unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(
            paths.cache_dir.join("temporary.plain"),
            b"temporary plaintext",
        )
        .unwrap();

        host.cleanup_failed_root_start(root_id, false).unwrap();

        assert!(!host.root_state_path(root_id).unwrap().exists());
        assert!(!paths.journal_path.exists());
        assert!(!paths.state_path.exists());
        assert!(!paths.cache_dir.exists());
    }

    #[test]
    fn failed_start_cleanup_preserves_existing_state() {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_observer = cleanup_called.clone();

        let error = orchestrate_failed_start_cleanup(
            "Cloud Files startup failed: native connect failed".into(),
            StartupCleanupDisposition::NeverConnected,
            true,
            move || {
                cleanup_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        );

        assert!(cleanup_called.load(Ordering::SeqCst));
        assert!(error.contains("native connect failed"));
        assert!(error.contains("existing recovery state was preserved"));
    }

    #[test]
    fn failed_start_with_unconfirmed_disconnect_never_runs_destructive_cleanup() {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_observer = cleanup_called.clone();

        let error = orchestrate_failed_start_cleanup(
            "Cloud Files startup failed: native disconnect could not be confirmed".into(),
            StartupCleanupDisposition::DisconnectUnconfirmed,
            false,
            move || {
                cleanup_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        );

        assert!(!cleanup_called.load(Ordering::SeqCst));
        assert!(error.contains("native disconnect could not be confirmed"));
        assert!(error.contains("recovery state was preserved"));
    }

    #[tokio::test]
    async fn failed_start_with_unconfirmed_disconnect_preserves_new_root_artifacts() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Unconfirmed Disconnect Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        let paths = host.runtime_paths(root_id).unwrap();
        write_mutation_journal(&paths.journal_path, &CloudMutationJournal::empty(root_id)).unwrap();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|_| Ok(()))
            .unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("retained.plain"), b"recovery").unwrap();

        let error = host
            .cleanup_failed_root_start_after_error(
                root_id,
                false,
                StartupCleanupDisposition::DisconnectUnconfirmed,
                "Cloud Files startup failed: native disconnect unconfirmed",
            )
            .await;

        assert!(error.contains("recovery state was preserved"));
        assert!(host.root_state_path(root_id).unwrap().exists());
        assert!(paths.journal_path.exists());
        assert!(paths.state_path.exists());
        assert!(paths.cache_dir.join("retained.plain").exists());
    }

    #[test]
    fn failed_start_with_confirmed_disconnect_cleans_new_registration() {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_observer = cleanup_called.clone();

        let error = orchestrate_failed_start_cleanup(
            "Cloud Files startup failed after native connect".into(),
            StartupCleanupDisposition::DisconnectConfirmed,
            false,
            move || {
                cleanup_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        );

        assert!(cleanup_called.load(Ordering::SeqCst));
        assert_eq!(error, "Cloud Files startup failed after native connect");
    }

    #[test]
    fn startup_error_retains_structured_cleanup_disposition_and_display() {
        let error = startup_error_after_disconnect(
            CloudProviderError::Callback("startup cleanup disconnect failed".into()),
            Err(CloudProviderError::Callback(
                "native disconnect unconfirmed".into(),
            )),
        );

        assert_eq!(
            error.cleanup_disposition(),
            StartupCleanupDisposition::DisconnectUnconfirmed
        );
        assert!(error
            .to_string()
            .contains("startup cleanup disconnect failed"));
        assert!(error.to_string().contains("native disconnect unconfirmed"));
    }

    #[tokio::test]
    async fn failed_readiness_stop_failure_skips_cleanup_and_preserves_recovery() {
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let cleanup_observer = cleanup_called.clone();

        let error = orchestrate_failed_root_readiness_cleanup(
            "Cloud Files startup health check failed: snapshot unreadable".into(),
            false,
            || async {
                Err(CloudProviderError::Callback(
                    "native disconnect failed".into(),
                ))
            },
            move || {
                cleanup_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(!cleanup_called.load(Ordering::SeqCst));
        assert!(error.contains("snapshot unreadable"));
        assert!(error.contains("native disconnect failed"));
        assert!(error.contains("recovery state was preserved"));
    }

    #[tokio::test]
    async fn failed_readiness_cleanup_failure_combines_context() {
        let error = orchestrate_failed_root_readiness_cleanup(
            "Cloud Files startup readiness failed: heartbeat stale".into(),
            false,
            || async { Ok(()) },
            || {
                Err(CloudProviderError::Callback(
                    "registration cleanup failed".into(),
                ))
            },
        )
        .await;

        assert!(error.contains("heartbeat stale"));
        assert!(error.contains("registration cleanup failed"));
        assert!(error.contains("recovery state was preserved"));
    }

    #[tokio::test]
    async fn failed_readiness_new_registration_stops_and_cleans_without_extra_error() {
        let stop_called = Arc::new(AtomicBool::new(false));
        let cleanup_called = Arc::new(AtomicBool::new(false));
        let stop_observer = stop_called.clone();
        let cleanup_observer = cleanup_called.clone();

        let error = orchestrate_failed_root_readiness_cleanup(
            "Cloud Files startup readiness failed: callback overdue".into(),
            false,
            move || async move {
                stop_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
            move || {
                cleanup_observer.store(true, Ordering::SeqCst);
                Ok(())
            },
        )
        .await;

        assert!(stop_called.load(Ordering::SeqCst));
        assert!(cleanup_called.load(Ordering::SeqCst));
        assert_eq!(
            error,
            "Cloud Files startup readiness failed: callback overdue"
        );
    }

    #[test]
    fn root_health_unregistered_is_structured_unhealthy() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });

        let health = host.check_root_health(root_id).unwrap();

        assert!(!health.registered);
        assert!(health.operational.is_none());
        assert!(!health.lifecycle_healthy);
        assert!(!health.durable_state_readable);
        assert!(!health.safe_to_unmount);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("not registered")));
    }

    #[test]
    fn root_health_registered_missing_snapshot_is_structured_unhealthy() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (host, _) = registered_health_fixture(temp.path(), root_id);

        let health = host.check_root_health(root_id).unwrap();

        assert!(health.registered);
        assert!(health.operational.is_none());
        assert!(!health.lifecycle_healthy);
        assert!(!health.heartbeat_fresh);
        assert!(health.durable_state_readable);
        assert!(!health.safe_to_unmount);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("snapshot is missing")));
    }

    #[test]
    fn root_health_failed_start_boundary_retains_error() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (host, paths) = registered_health_fixture(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &paths.writer_lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
            paths.health_path,
            &lease,
        )
        .unwrap();
        telemetry.record_start_failure(generation, Utc::now(), "connect failed");

        let health = host.check_root_health(root_id).unwrap();

        let operational = health.operational.unwrap();
        assert_eq!(operational.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(
            operational.last_start_failure.as_deref(),
            Some("connect failed")
        );
        assert!(!health.lifecycle_healthy);
    }

    #[test]
    fn root_health_disconnected_cannot_certify_unscanned_local_files() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (host, paths) = registered_health_fixture(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &paths.writer_lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
            paths.health_path,
            &lease,
        )
        .unwrap();
        telemetry.record_running(generation, Utc::now()).unwrap();
        telemetry.record_heartbeat(generation, Utc::now());
        assert!(host.read_runtime_status(root_id).unwrap().safe_to_unmount);
        assert!(telemetry.record_shutting_down(generation, Utc::now()));
        assert!(telemetry.record_stopped(generation, Utc::now()));

        let health = host.check_root_health(root_id).unwrap();

        assert_eq!(
            health.operational.as_ref().unwrap().lifecycle,
            CloudRootConnectionState::Disconnected
        );
        assert!(!health.lifecycle_healthy);
        assert!(!health.safe_to_unmount);
        let status = host.read_runtime_status(root_id).unwrap();
        assert!(!status.safe_to_unmount);
        assert!(status.last_error.unwrap().contains("local changes"));
        // Cleanup's journal check remains available after a confirmed disconnect.
        assert!(
            host.read_durable_runtime_status(root_id)
                .unwrap()
                .safe_to_unmount
        );
    }

    #[test]
    fn root_health_failed_disconnect_boundary_retains_error() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (host, paths) = registered_health_fixture(temp.path(), root_id);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &paths.writer_lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
            paths.health_path,
            &lease,
        )
        .unwrap();
        telemetry.record_running(generation, Utc::now()).unwrap();
        telemetry.record_heartbeat(generation, Utc::now());
        assert!(telemetry.record_shutting_down(generation, Utc::now()));
        assert!(telemetry.record_disconnect_failure(
            generation,
            Utc::now(),
            "CfDisconnectSyncRoot failed",
        ));

        let health = host.check_root_health(root_id).unwrap();

        let operational = health.operational.unwrap();
        assert_eq!(operational.lifecycle, CloudRootConnectionState::Failed);
        assert_eq!(
            operational.last_disconnect_failure.as_deref(),
            Some("CfDisconnectSyncRoot failed")
        );
        assert!(!health.lifecycle_healthy);
    }

    #[test]
    fn root_health_stale_owner_boundary_is_unhealthy() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (host, paths) = registered_health_fixture(temp.path(), root_id);
        let stale_time = Utc::now() - chrono::Duration::seconds(60);
        let lease = Arc::new(RootWriterLease::acquire(root_id, &paths.writer_lock_path).unwrap());
        let (telemetry, generation) = RootHealthTelemetry::new_persisted_starting(
            root_id,
            Uuid::new_v4(),
            4242,
            stale_time,
            Duration::from_secs(1),
            paths.health_path,
            &lease,
        )
        .unwrap();
        telemetry.record_running(generation, stale_time).unwrap();
        telemetry.record_heartbeat(generation, stale_time);

        let health = host.check_root_health(root_id).unwrap();

        assert_eq!(
            health.operational.as_ref().unwrap().lifecycle,
            CloudRootConnectionState::Running
        );
        assert!(!health.heartbeat_fresh);
        assert!(!health.lifecycle_healthy);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("heartbeat is stale")));
    }

    #[test]
    fn root_health_live_heartbeat_does_not_override_pending_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Health Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        let paths = host.runtime_paths(root_id).unwrap();
        let mut journal = CloudMutationJournal::empty(root_id);
        journal.records.push(CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        ));
        write_mutation_journal(&paths.journal_path, &journal).unwrap();
        CloudStateStore::new(paths.state_path.clone(), root_id)
            .transaction(|state| {
                state.conflicts.push(CloudConflictRecord {
                    id: Uuid::new_v4(),
                    object_id: "file-1".into(),
                    relative_path: "docs/report.txt".into(),
                    expected_version: None,
                    actual_version: None,
                    local_plaintext_path: None,
                    created_at: Utc::now(),
                });
                Ok(())
            })
            .unwrap();
        let (telemetry, generation, _lease, _) = new_persisted_health(
            temp.path().join("mount_states").as_path(),
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
        );
        telemetry.record_running(generation, Utc::now()).unwrap();
        telemetry.record_heartbeat(generation, Utc::now());

        let health = host.check_root_health(root_id).unwrap();

        assert!(health.registered);
        assert!(
            health.lifecycle_healthy,
            "operational health: {:?}",
            health.operational
        );
        assert_eq!(health.pending_mutation_count, Some(1));
        assert_eq!(health.pending_refresh_count, Some(0));
        assert_eq!(health.conflict_count, Some(1));
        assert!(!health.safe_to_unmount);
        assert!(health.durable_state_readable);
        assert!(health.durable_observed_at <= Utc::now());
        assert_eq!(
            health.health_snapshot_source,
            Some(DurableInspectionSource::Primary)
        );
    }

    #[tokio::test]
    async fn root_health_ipc_uses_snapshot_backed_host_check() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let request = serde_json::json!({
            "command": "root-health",
            "root_id": root_id,
        })
        .to_string();

        let response = ipc::handle_request(&host, &request).await;

        assert!(response.ok);
        assert_eq!(response.root_health.unwrap().root_id, root_id);
    }

    #[test]
    fn root_health_inspection_selects_health_backup_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
        );
        telemetry.record_running(generation, Utc::now()).unwrap();
        let backup_path = health_backup_path(&path);
        fs::write(&path, b"{corrupt").unwrap();
        let primary_before = fs::read(&path).unwrap();
        let backup_before = fs::read(&backup_path).unwrap();
        let primary_mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        let backup_mtime_before = fs::metadata(&backup_path).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(temp.path()).unwrap().count();

        let inspected = inspect_health_snapshot_sources(&path, root_id, Utc::now())
            .unwrap()
            .unwrap();

        assert_eq!(inspected.source, DurableInspectionSource::Backup);
        assert_eq!(fs::read(&path).unwrap(), primary_before);
        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            primary_mtime_before
        );
        assert_eq!(
            fs::metadata(&backup_path).unwrap().modified().unwrap(),
            backup_mtime_before
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), entries_before);
    }

    #[test]
    fn root_health_durable_corruption_is_structured_unhealthy() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        host.save_registration(&CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Corrupt Durable Test".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        })
        .unwrap();
        let paths = host.runtime_paths(root_id).unwrap();
        fs::write(&paths.journal_path, b"{corrupt").unwrap();
        fs::write(&paths.state_path, b"{corrupt").unwrap();

        let health = host.check_root_health(root_id).unwrap();

        assert!(health.registered);
        assert!(!health.durable_state_readable);
        assert!(!health.safe_to_unmount);
        assert_eq!(health.pending_mutation_count, None);
        assert_eq!(health.pending_refresh_count, None);
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("journal is unreadable")));
        assert!(health
            .unhealthy_evidence
            .iter()
            .any(|evidence| evidence.contains("state is unreadable")));
    }

    #[test]
    fn root_health_registration_backup_inspection_is_non_mutating() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Registration Backup Test".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        host.save_registration(&registration).unwrap();
        let primary_path = host.root_state_path(root_id).unwrap();
        let backup_path = primary_path.with_file_name(format!("{root_id}.json.bak"));
        fs::write(&primary_path, b"{corrupt").unwrap();
        let primary_before = fs::read(&primary_path).unwrap();
        let backup_before = fs::read(&backup_path).unwrap();
        let primary_mtime_before = fs::metadata(&primary_path).unwrap().modified().unwrap();
        let backup_mtime_before = fs::metadata(&backup_path).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(primary_path.parent().unwrap())
            .unwrap()
            .count();

        let health = host.check_root_health(root_id).unwrap();

        assert!(health.registered);
        assert_eq!(
            health.registration_source,
            Some(DurableInspectionSource::Backup)
        );
        assert_eq!(health.registration_generation, Some(1));
        assert_eq!(fs::read(&primary_path).unwrap(), primary_before);
        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
        assert_eq!(
            fs::metadata(&primary_path).unwrap().modified().unwrap(),
            primary_mtime_before
        );
        assert_eq!(
            fs::metadata(&backup_path).unwrap().modified().unwrap(),
            backup_mtime_before
        );
        assert_eq!(
            fs::read_dir(primary_path.parent().unwrap())
                .unwrap()
                .count(),
            entries_before
        );
    }

    #[test]
    fn root_health_registration_legacy_is_inspected_then_writer_migrated() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Legacy Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let path = host.root_state_path(root_id).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            serde_json::to_vec(&serde_json::json!({
                "root_id": registration.root_id,
                "sync_root_path": registration.sync_root_path,
                "encrypted_root": registration.encrypted_root,
                "display_name": registration.display_name,
            }))
            .unwrap(),
        )
        .unwrap();

        let legacy = host.inspect_registration(root_id).unwrap().unwrap();
        assert_eq!(legacy.generation, 0);
        assert!(legacy.legacy);
        let bytes_before = fs::read(&path).unwrap();
        let modified_before = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(
            host.load_registrations().unwrap(),
            vec![registration.clone()]
        );
        assert_eq!(fs::read(&path).unwrap(), bytes_before);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            modified_before
        );
        assert!(host.inspect_registration(root_id).unwrap().unwrap().legacy);

        host.save_registration(&registration).unwrap();
        let migrated = host.inspect_registration(root_id).unwrap().unwrap();
        assert_eq!(migrated.generation, 1);
        assert!(!migrated.legacy);
        assert_eq!(host.load_registrations().unwrap(), vec![registration]);
    }

    #[test]
    fn shell_registration_schema_round_trips_stable_sync_root_id() {
        let root_id = Uuid::new_v4();
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: PathBuf::from(r"C:\HybridCipher\mount"),
            encrypted_root: PathBuf::from(r"C:\HybridCipher\encrypted"),
            display_name: "HybridCipher — Vault".into(),
            registration_kind: CloudRootRegistrationKind::ShellIntegrated,
            shell_sync_root_id: Some(format!("HybridCipher!S-1-5-21-test!{root_id}")),
        };

        let bytes = encode_registration(&registration, 7).unwrap();
        let (decoded, generation, legacy) = parse_registration(&bytes, root_id).unwrap();

        assert_eq!(decoded, registration);
        assert_eq!(generation, 7);
        assert!(!legacy);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["schema_version"],
            serde_json::json!(2)
        );
    }

    #[test]
    fn root_health_registration_listing_discovers_backup_only_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Backup-only Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let primary = host.root_state_path(root_id).unwrap();
        let directory = primary.parent().unwrap();
        let backup = primary.with_file_name(format!("{root_id}.json.bak"));
        fs::create_dir_all(directory).unwrap();
        fs::write(&backup, encode_registration(&registration, 9).unwrap()).unwrap();
        fs::write(directory.join("not-a-registration.json"), b"{}").unwrap();
        fs::write(directory.join("notes.txt"), b"operator notes").unwrap();
        let backup_before = fs::read(&backup).unwrap();
        let backup_mtime_before = fs::metadata(&backup).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(directory).unwrap().count();

        assert_eq!(
            host.load_registrations().unwrap(),
            vec![registration.clone()]
        );
        assert!(!primary.exists());
        assert_eq!(fs::read(&backup).unwrap(), backup_before);
        assert_eq!(
            fs::metadata(&backup).unwrap().modified().unwrap(),
            backup_mtime_before
        );
        assert_eq!(fs::read_dir(directory).unwrap().count(), entries_before);
    }

    #[test]
    fn root_health_registration_listing_deduplicates_primary_and_backup() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let mut registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Primary Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let primary = host.root_state_path(root_id).unwrap();
        let backup = primary.with_file_name(format!("{root_id}.json.bak"));
        fs::create_dir_all(primary.parent().unwrap()).unwrap();
        fs::write(&primary, encode_registration(&registration, 4).unwrap()).unwrap();
        registration.display_name = "Newer Backup Registration".into();
        fs::write(&backup, encode_registration(&registration, 5).unwrap()).unwrap();

        let registrations = host.load_registrations().unwrap();

        assert_eq!(registrations, vec![registration]);
    }

    #[test]
    fn root_health_registration_save_requires_exact_root_writer_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Lease-bound Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let paths = host.runtime_paths(root_id).unwrap();
        let registration_path = host.root_state_path(root_id).unwrap();

        let wrong_root = RootWriterLease::acquire(Uuid::new_v4(), &paths.writer_lock_path).unwrap();
        assert!(matches!(
            host.save_registration_locked(&registration, &wrong_root),
            Err(CloudProviderError::StartupRecoveryUnavailable)
        ));
        assert!(!registration_path.exists());
        drop(wrong_root);

        let wrong_path = temp.path().join("forged-writer.lock");
        let same_root_wrong_path = RootWriterLease::acquire(root_id, &wrong_path).unwrap();
        assert!(matches!(
            host.save_registration_locked(&registration, &same_root_wrong_path),
            Err(CloudProviderError::StartupRecoveryUnavailable)
        ));
        assert!(!registration_path.exists());
    }

    #[test]
    fn root_health_safety_source_recovery_requires_exact_root_writer_lease() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();

        let wrong_root = RootWriterLease::acquire(Uuid::new_v4(), &paths.writer_lock_path).unwrap();
        assert!(matches!(
            host.ensure_health_safety_sources(root_id, &paths, &wrong_root),
            Err(CloudProviderError::StartupRecoveryUnavailable)
        ));
        assert!(!paths.journal_path.exists());
        assert!(!paths.state_path.exists());
        drop(wrong_root);

        let wrong_path = temp.path().join("forged-safety-writer.lock");
        let same_root_wrong_path = RootWriterLease::acquire(root_id, &wrong_path).unwrap();
        assert!(matches!(
            host.ensure_health_safety_sources(root_id, &paths, &same_root_wrong_path),
            Err(CloudProviderError::StartupRecoveryUnavailable)
        ));
        assert!(!paths.journal_path.exists());
        assert!(!paths.state_path.exists());
    }

    #[test]
    fn root_health_safety_source_recovery_rejects_forged_paths_with_exact_lock() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let expected = host.runtime_paths(root_id).unwrap();
        let writer = RootWriterLease::acquire(root_id, &expected.writer_lock_path).unwrap();
        let mut forged = expected.clone();
        forged.journal_path = temp.path().join("forged-journal.json");
        forged.state_path = temp.path().join("forged-state.json");
        let legacy = serde_json::to_vec(&CloudMutationJournal::empty(root_id)).unwrap();
        fs::write(&forged.journal_path, &legacy).unwrap();
        let journal_mtime = fs::metadata(&forged.journal_path)
            .unwrap()
            .modified()
            .unwrap();
        let entries_before = fs::read_dir(temp.path()).unwrap().count();

        assert!(matches!(
            host.ensure_health_safety_sources(root_id, &forged, &writer),
            Err(CloudProviderError::StartupRecoveryUnavailable)
        ));
        assert_eq!(fs::read(&forged.journal_path).unwrap(), legacy);
        assert_eq!(
            fs::metadata(&forged.journal_path)
                .unwrap()
                .modified()
                .unwrap(),
            journal_mtime
        );
        assert!(!forged.state_path.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), entries_before);
    }

    #[test]
    fn public_runtime_status_uses_valid_backups_without_mutating_sources() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        let journal_backup = paths
            .journal_path
            .with_file_name(format!("cloud_mutations_{root_id}.json.bak"));
        write_mutation_journal(&paths.journal_path, &CloudMutationJournal::empty(root_id)).unwrap();
        let mut journal = CloudMutationJournal::empty(root_id);
        journal.generation = 1;
        write_mutation_journal(&paths.journal_path, &journal).unwrap();
        fs::write(&paths.journal_path, b"{corrupt journal").unwrap();

        let store = CloudStateStore::new(paths.state_path.clone(), root_id);
        store.transaction(|_| Ok(())).unwrap();
        store.transaction(|_| Ok(())).unwrap();
        let state_backup = paths.state_path.with_extension("json.bak");
        fs::write(&paths.state_path, b"{corrupt state").unwrap();

        let sources = [
            paths.journal_path.clone(),
            journal_backup,
            paths.state_path.clone(),
            state_backup,
        ];
        let before = sources
            .iter()
            .map(|path| {
                (
                    fs::read(path).unwrap(),
                    fs::metadata(path).unwrap().modified().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let entries_before = fs::read_dir(paths.journal_path.parent().unwrap())
            .unwrap()
            .count();

        let status = host.read_runtime_status(root_id).unwrap();
        assert!(!status.safe_to_unmount);
        assert_eq!(host.unsafe_pending_mutation_count(root_id).unwrap(), 0);
        for (path, (bytes, modified)) in sources.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
        }
        assert_eq!(
            fs::read_dir(paths.journal_path.parent().unwrap())
                .unwrap()
                .count(),
            entries_before
        );
    }

    #[test]
    fn public_runtime_status_rejects_missing_or_invalid_sources_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });

        assert!(host.read_runtime_status(root_id).is_err());
        assert!(host.unsafe_pending_mutation_count(root_id).is_err());

        let paths = host.runtime_paths(root_id).unwrap();
        let journal_backup = paths
            .journal_path
            .with_file_name(format!("cloud_mutations_{root_id}.json.bak"));
        let state_backup = paths.state_path.with_extension("json.bak");
        for path in [
            &paths.journal_path,
            &journal_backup,
            &paths.state_path,
            &state_backup,
        ] {
            fs::write(path, b"{invalid").unwrap();
        }
        let sources = [
            paths.journal_path.clone(),
            journal_backup,
            paths.state_path.clone(),
            state_backup,
        ];
        let before = sources
            .iter()
            .map(|path| {
                (
                    fs::read(path).unwrap(),
                    fs::metadata(path).unwrap().modified().unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let entries_before = fs::read_dir(paths.journal_path.parent().unwrap())
            .unwrap()
            .count();

        assert!(host.read_runtime_status(root_id).is_err());
        assert!(host.unsafe_pending_mutation_count(root_id).is_err());
        for (path, (bytes, modified)) in sources.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), bytes);
            assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
        }
        assert_eq!(
            fs::read_dir(paths.journal_path.parent().unwrap())
                .unwrap()
                .count(),
            entries_before
        );
    }

    #[test]
    fn root_health_registration_selects_newer_valid_backup_generation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Newer Backup".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        host.save_registration(&registration).unwrap();
        let path = host.root_state_path(root_id).unwrap();
        let backup = path.with_file_name(format!("{root_id}.json.bak"));
        let generation_two = fs::read(&path).unwrap();
        let generation_one = fs::read(&backup).unwrap();
        fs::write(&path, generation_one).unwrap();
        fs::write(&backup, generation_two).unwrap();

        let inspected = host.inspect_registration(root_id).unwrap().unwrap();

        assert_eq!(inspected.source, DurableInspectionSource::Backup);
        assert_eq!(inspected.generation, 2);
        assert_eq!(inspected.value.root_id, root_id);
    }

    #[test]
    fn root_health_registration_rejects_forged_generation_and_checksum() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        host.save_registration(&CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Forged Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        })
        .unwrap();
        let path = host.root_state_path(root_id).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["generation"] = serde_json::json!(99);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

        assert!(host.inspect_registration(root_id).is_err());
    }

    #[test]
    fn root_health_registration_rejects_wrong_root_and_unknown_fields() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let other_root = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let path = host.root_state_path(root_id).unwrap();
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let other = CloudRootRegistration {
            root_id: other_root,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Wrong Root".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        fs::write(&path, encode_registration(&other, 1).unwrap()).unwrap();
        assert!(host.inspect_registration(root_id).is_err());

        let mut legacy = serde_json::to_value(CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Unknown Field".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        })
        .unwrap();
        legacy["unexpected"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(host.inspect_registration(root_id).is_err());
    }

    #[test]
    fn root_health_journal_backup_inspection_is_non_mutating() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let path = temp.path().join("journal.json");
        let mut journal = CloudMutationJournal::empty(root_id);
        write_mutation_journal(&path, &journal).unwrap();
        journal.generation = 1;
        write_mutation_journal(&path, &journal).unwrap();
        let backup_path = path.with_file_name("journal.json.bak");
        fs::write(&path, b"{corrupt").unwrap();
        let primary_before = fs::read(&path).unwrap();
        let backup_before = fs::read(&backup_path).unwrap();
        let primary_mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        let backup_mtime_before = fs::metadata(&backup_path).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(temp.path()).unwrap().count();

        let inspected = inspect_mutation_journal_sources(&path, root_id)
            .unwrap()
            .unwrap();

        assert_eq!(inspected.source, DurableInspectionSource::Backup);
        assert_eq!(inspected.generation, 1);
        assert_eq!(fs::read(&path).unwrap(), primary_before);
        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            primary_mtime_before
        );
        assert_eq!(
            fs::metadata(&backup_path).unwrap().modified().unwrap(),
            backup_mtime_before
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), entries_before);
    }

    #[test]
    fn root_health_startup_seeds_checked_empty_durable_generations() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        let writer = host.root_writer_access(root_id, &paths).unwrap();

        host.ensure_health_safety_sources(root_id, &paths, writer.as_ref())
            .unwrap();

        assert!(
            inspect_mutation_journal_sources(&paths.journal_path, root_id)
                .unwrap()
                .is_some()
        );
        assert!(CloudStateStore::new(paths.state_path, root_id)
            .inspect()
            .unwrap()
            .is_some());
    }

    #[test]
    fn root_health_startup_migrates_legacy_primary_journal_to_checked_envelope() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::write(
            &paths.journal_path,
            serde_json::to_vec(&CloudMutationJournal::empty(root_id)).unwrap(),
        )
        .unwrap();
        let writer = host.root_writer_access(root_id, &paths).unwrap();

        host.ensure_health_safety_sources(root_id, &paths, writer.as_ref())
            .unwrap();

        let inspected = inspect_mutation_journal_sources(&paths.journal_path, root_id)
            .unwrap()
            .unwrap();
        assert_eq!(inspected.source, DurableInspectionSource::Primary);
        assert_eq!(inspected.generation, 1);
    }

    #[test]
    fn root_health_startup_migrates_legacy_backup_after_corrupt_primary() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::write(&paths.journal_path, b"{corrupt").unwrap();
        let backup_path = paths
            .journal_path
            .with_file_name(format!("cloud_mutations_{root_id}.json.bak"));
        fs::write(
            backup_path,
            serde_json::to_vec(&CloudMutationJournal::empty(root_id)).unwrap(),
        )
        .unwrap();
        let writer = host.root_writer_access(root_id, &paths).unwrap();

        host.ensure_health_safety_sources(root_id, &paths, writer.as_ref())
            .unwrap();

        let inspected = inspect_mutation_journal_sources(&paths.journal_path, root_id)
            .unwrap()
            .unwrap();
        assert_eq!(inspected.source, DurableInspectionSource::Primary);
        assert_eq!(inspected.generation, 1);
    }

    #[test]
    fn root_health_registration_inspection_during_writes_is_complete() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = CloudProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            pipe_name: None,
        });
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: temp.path().join("sync"),
            encrypted_root: temp.path().join("encrypted"),
            display_name: "Concurrent Registration".into(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        host.save_registration(&registration).unwrap();
        let writer = {
            let host = host.clone();
            let registration = registration.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    host.save_registration(&registration).unwrap();
                }
            })
        };

        for _ in 0..100 {
            let inspected = host.inspect_registration(root_id).unwrap().unwrap();
            assert_eq!(inspected.value.root_id, root_id);
            assert!(inspected.generation >= 1);
            assert!(!inspected.legacy);
        }
        writer.join().unwrap();
    }

    #[test]
    fn root_health_journal_inspection_during_writes_is_complete() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let path = temp.path().join("journal.json");
        write_mutation_journal(&path, &CloudMutationJournal::empty(root_id)).unwrap();
        let writer = {
            let path = path.clone();
            std::thread::spawn(move || {
                for generation in 1..=25 {
                    let mut journal = CloudMutationJournal::empty(root_id);
                    journal.generation = generation;
                    write_mutation_journal(&path, &journal).unwrap();
                }
            })
        };

        for _ in 0..100 {
            let inspected = inspect_mutation_journal_sources(&path, root_id)
                .unwrap()
                .unwrap();
            assert_eq!(inspected.value.root_id, root_id);
            assert_eq!(inspected.generation, inspected.value.generation);
        }
        writer.join().unwrap();
    }

    #[test]
    fn root_health_snapshot_inspection_during_writes_is_complete() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let (telemetry, generation, _lease, path) = new_persisted_health(
            temp.path(),
            root_id,
            Uuid::new_v4(),
            4242,
            Utc::now(),
            Duration::from_secs(30),
        );
        telemetry.record_running(generation, Utc::now()).unwrap();
        telemetry.record_heartbeat(generation, Utc::now());
        let writer = {
            let telemetry = telemetry.clone();
            std::thread::spawn(move || {
                for _ in 0..25 {
                    telemetry.record_heartbeat(generation, Utc::now());
                }
            })
        };

        for _ in 0..100 {
            let inspected = inspect_health_snapshot_sources(&path, root_id, Utc::now())
                .unwrap()
                .unwrap();
            assert_eq!(inspected.value.root_id, root_id);
            assert_eq!(inspected.generation, generation);
            assert!(inspected.value.snapshot_revision > 0);
        }
        writer.join().unwrap();
    }

    fn reconciliation_fixture() -> (
        CloudRootRegistration,
        CloudRootPersistentState,
        HashMap<String, ProviderEntry>,
        ProviderEntry,
    ) {
        let root_id = Uuid::new_v4();
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: PathBuf::from("sync"),
            encrypted_root: PathBuf::from("encrypted"),
            display_name: "Reconciliation Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let old_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            4,
            64,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(7),
        );
        let remote_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            PathBuf::from("report.txt.encrypted"),
            99,
            128,
            Utc::now(),
            None,
            Some("stable-file-id".to_string()),
            Some(8),
        );
        let mut state = CloudRootPersistentState::empty(root_id);
        state.upsert_inventory_entry(&old_entry).unwrap();
        state
            .items
            .get_mut("stable-file-id")
            .unwrap()
            .content_version = Some(ProviderContentVersion::from_components(
            "stable-file-id",
            Some(root_id),
            7,
            Some(2),
            4,
            64,
            Some(&[1; 12]),
            None,
        ));
        let inventory = HashMap::from([("stable-file-id".to_string(), old_entry)]);
        (registration, state, inventory, remote_entry)
    }

    #[test]
    fn reconciliation_safe_item_plans_new_version_without_mutating_current_state() {
        let (registration, current, inventory, remote) = reconciliation_fixture();
        let old_version = current.items["stable-file-id"].content_version.clone();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Safe)]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[remote.clone()],
            &dispositions,
        )
        .unwrap();

        assert_eq!(current.items["stable-file-id"].content_version, old_version);
        assert_eq!(
            plan.proposed_state.items["stable-file-id"].content_version,
            remote.content_version()
        );
        assert_eq!(plan.placeholders.len(), 1);
    }

    #[test]
    fn reconciliation_recreates_unchanged_placeholder_missing_from_disk() {
        let (registration, current, inventory, _) = reconciliation_fixture();
        let unchanged = inventory["stable-file-id"].clone();
        let dispositions = HashMap::from([(
            "stable-file-id".to_string(),
            LocalRefreshDisposition::Missing,
        )]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[unchanged],
            &dispositions,
        )
        .unwrap();

        assert_eq!(plan.placeholders.len(), 1);
        assert_eq!(plan.placeholders[0].identity.object_id, "stable-file-id");
        assert!(plan.removed_items.is_empty());
    }

    #[test]
    fn reconciliation_migrates_legacy_directory_uuid_and_retires_path_binding() {
        let root_id = Uuid::new_v4();
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: PathBuf::from("sync"),
            encrypted_root: PathBuf::from("encrypted"),
            display_name: "Directory Upgrade Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let legacy_id = Uuid::new_v4();
        let legacy_entry = ProviderEntry::cache_directory(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
        );
        let stable_entry = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
            "stable-directory-id",
            7,
        );
        let mut current = CloudRootPersistentState::empty(root_id);
        current.directory_ids.insert("docs".to_string(), legacy_id);
        current.items.insert(
            legacy_id.to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(
                    root_id,
                    ProviderEntryKind::Directory,
                    legacy_id.to_string(),
                ),
                "docs",
                None,
            ),
        );
        let inventory = HashMap::from([(legacy_id.to_string(), legacy_entry)]);
        let dispositions = HashMap::from([(legacy_id.to_string(), LocalRefreshDisposition::Safe)]);

        let mut plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[stable_entry],
            &dispositions,
        )
        .unwrap();

        assert!(!plan
            .proposed_state
            .items
            .contains_key(&legacy_id.to_string()));
        assert!(plan
            .proposed_state
            .items
            .contains_key("stable-directory-id"));
        assert_eq!(
            plan.placeholder_guard_ids["stable-directory-id"],
            legacy_id.to_string()
        );
        assert!(!plan.proposed_state.directory_ids.contains_key("docs"));

        let reused_path = ProviderEntry::cache_directory(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
        );
        let replacement = plan
            .proposed_state
            .upsert_inventory_entry(&reused_path)
            .unwrap();
        assert_ne!(replacement.object_id, legacy_id.to_string());
    }

    #[test]
    fn reconciliation_correlates_remote_directory_rename_by_stable_id() {
        let root_id = Uuid::new_v4();
        let registration = CloudRootRegistration {
            root_id,
            sync_root_path: PathBuf::from("sync"),
            encrypted_root: PathBuf::from("encrypted"),
            display_name: "Directory Rename Test".to_string(),
            registration_kind: CloudRootRegistrationKind::LegacyCfApi,
            shell_sync_root_id: None,
        };
        let old_entry = ProviderEntry::cache_directory_with_identity(
            root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
            "stable-directory-id",
            7,
        );
        let renamed_entry = ProviderEntry::cache_directory_with_identity(
            root_id,
            "archive",
            registration.encrypted_root.join("archive"),
            Utc::now(),
            "stable-directory-id",
            7,
        );
        let mut current = CloudRootPersistentState::empty(root_id);
        current.upsert_inventory_entry(&old_entry).unwrap();
        let inventory = HashMap::from([("stable-directory-id".to_string(), old_entry)]);
        let dispositions = HashMap::from([(
            "stable-directory-id".to_string(),
            LocalRefreshDisposition::Safe,
        )]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[renamed_entry],
            &dispositions,
        )
        .unwrap();

        assert_eq!(
            plan.proposed_state.items["stable-directory-id"].relative_path,
            "archive"
        );
        assert_eq!(
            plan.removed_items,
            vec![("stable-directory-id".to_string(), "docs".to_string())]
        );
    }

    #[test]
    fn reconciliation_busy_item_defers_remote_version() {
        let (registration, current, inventory, remote) = reconciliation_fixture();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Busy)]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[remote],
            &dispositions,
        )
        .unwrap();

        assert_eq!(plan.proposed_state, current);
        assert!(plan.placeholders.is_empty());
        assert!(plan.proposed_state.conflicts.is_empty());
    }

    #[test]
    fn reconciliation_dirty_item_preserves_base_and_records_conflict() {
        let (registration, current, inventory, remote) = reconciliation_fixture();
        let old_version = current.items["stable-file-id"].content_version.clone();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Dirty)]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[remote.clone()],
            &dispositions,
        )
        .unwrap();

        assert_eq!(
            plan.proposed_state.items["stable-file-id"].content_version,
            old_version
        );
        assert!(plan.proposed_state.items["stable-file-id"].dirty);
        assert_eq!(plan.proposed_state.conflicts.len(), 1);
        assert_eq!(
            plan.proposed_state.conflicts[0].actual_version,
            remote.content_version()
        );
        assert!(plan.placeholders.is_empty());
    }

    #[test]
    fn reconciliation_busy_item_defers_remote_delete() {
        let (registration, current, inventory, _) = reconciliation_fixture();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Busy)]);

        let plan =
            plan_remote_reconciliation(&registration, &current, &inventory, &[], &dispositions)
                .unwrap();

        assert_eq!(plan.proposed_state, current);
        assert!(plan.removed_items.is_empty());
        assert!(plan.proposed_state.conflicts.is_empty());
    }

    #[test]
    fn reconciliation_dirty_item_turns_remote_delete_into_conflict() {
        let (registration, current, inventory, _) = reconciliation_fixture();
        let old_version = current.items["stable-file-id"].content_version.clone();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Dirty)]);

        let plan =
            plan_remote_reconciliation(&registration, &current, &inventory, &[], &dispositions)
                .unwrap();

        assert_eq!(
            plan.proposed_state.items["stable-file-id"].content_version,
            old_version
        );
        assert!(plan.proposed_state.items["stable-file-id"].dirty);
        assert_eq!(plan.proposed_state.conflicts.len(), 1);
        assert!(plan.removed_items.is_empty());
    }

    #[test]
    fn reconciliation_safe_item_plans_guarded_remote_delete() {
        let (registration, current, inventory, _) = reconciliation_fixture();
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Safe)]);

        let plan =
            plan_remote_reconciliation(&registration, &current, &inventory, &[], &dispositions)
                .unwrap();

        assert!(!plan.proposed_state.items.contains_key("stable-file-id"));
        assert_eq!(
            plan.removed_items,
            vec![("stable-file-id".to_string(), "docs/report.txt".to_string())]
        );
    }

    #[test]
    fn reconciliation_busy_descendant_defers_remote_directory_delete() {
        let (registration, mut current, mut inventory, _) = reconciliation_fixture();
        let directory_id = Uuid::new_v4();
        current
            .directory_ids
            .insert("docs".to_string(), directory_id);
        current.items.insert(
            directory_id.to_string(),
            CloudItemState::new(
                CloudObjectIdentityV2::new(
                    registration.root_id,
                    ProviderEntryKind::Directory,
                    directory_id.to_string(),
                ),
                "docs",
                None,
            ),
        );
        let directory_entry = ProviderEntry::cache_directory(
            registration.root_id,
            "docs",
            registration.encrypted_root.join("docs"),
            Utc::now(),
        );
        inventory.insert(directory_id.to_string(), directory_entry);
        let dispositions = HashMap::from([
            ("stable-file-id".to_string(), LocalRefreshDisposition::Busy),
            (directory_id.to_string(), LocalRefreshDisposition::Safe),
        ]);

        let plan =
            plan_remote_reconciliation(&registration, &current, &inventory, &[], &dispositions)
                .unwrap();

        assert!(plan.proposed_state.items.contains_key("stable-file-id"));
        assert!(plan
            .proposed_state
            .items
            .contains_key(&directory_id.to_string()));
        assert!(plan.removed_items.is_empty());
        assert!(plan.proposed_state.conflicts.is_empty());
    }

    #[test]
    fn reconciliation_same_path_replacement_reuses_old_guard_without_deleting_path() {
        let (registration, current, inventory, _) = reconciliation_fixture();
        let replacement = ProviderEntry::cache_file_with_identity(
            registration.root_id,
            "docs/report.txt",
            PathBuf::from("replacement.encrypted"),
            33,
            96,
            Utc::now(),
            None,
            Some("replacement-file-id".to_string()),
            Some(9),
        );
        let dispositions =
            HashMap::from([("stable-file-id".to_string(), LocalRefreshDisposition::Safe)]);

        let plan = plan_remote_reconciliation(
            &registration,
            &current,
            &inventory,
            &[replacement],
            &dispositions,
        )
        .unwrap();

        assert!(!plan.proposed_state.items.contains_key("stable-file-id"));
        assert!(plan
            .proposed_state
            .items
            .contains_key("replacement-file-id"));
        assert_eq!(
            plan.placeholder_guard_ids.get("replacement-file-id"),
            Some(&"stable-file-id".to_string())
        );
        assert!(plan.removed_items.is_empty());
        assert_eq!(plan.placeholders.len(), 1);
    }
}

mod ipc {
    use super::{CloudProviderHost, ProviderIpcRequest, ProviderIpcResponse, Result};

    #[cfg(target_os = "windows")]
    pub async fn serve(host: CloudProviderHost) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

        let pipe_name = host
            .config()
            .pipe_name
            .clone()
            .unwrap_or_else(|| super::default_pipe_name().to_string());

        loop {
            let mut pipe = ServerOptions::new()
                .pipe_mode(PipeMode::Message)
                .create(&pipe_name)?;
            pipe.connect().await?;

            let mut request = String::new();
            {
                let mut reader = BufReader::new(&mut pipe);
                reader.read_line(&mut request).await?;
            }
            let response = handle_request(&host, request.trim()).await;
            let mut response_bytes = serde_json::to_vec(&response)?;
            response_bytes.push(b'\n');
            pipe.write_all(&response_bytes).await?;
            pipe.flush().await?;
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn serve(_host: CloudProviderHost) -> Result<()> {
        Err(super::CloudProviderError::UnsupportedPlatform)
    }

    pub(crate) async fn handle_request(
        host: &CloudProviderHost,
        request: &str,
    ) -> ProviderIpcResponse {
        let parsed = match serde_json::from_str::<ProviderIpcRequest>(request) {
            Ok(parsed) => parsed,
            Err(err) => return ProviderIpcResponse::error(err),
        };

        match parsed {
            ProviderIpcRequest::Status => {
                let mut response = ProviderIpcResponse::ok();
                response.status = Some(host.status());
                response
            }
            ProviderIpcRequest::RegisterRoot {
                registration,
                sync_placeholders,
            } => match host.register_root(&registration) {
                Ok(()) if sync_placeholders => match host.sync_placeholders(&registration) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.placeholder_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                },
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::SyncPlaceholders { registration } => {
                match host.sync_placeholders(&registration) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.placeholder_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
            ProviderIpcRequest::UnregisterRoot { sync_root_path } => {
                match host.unregister_root_path(&sync_root_path) {
                    Ok(()) => ProviderIpcResponse::ok(),
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
            ProviderIpcRequest::ResetRoot { root_id } => match host.reset_root(root_id).await {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::StartRoot { root_id } => match host.start_root(root_id).await {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::StopRoot { root_id } => match host.stop_root(root_id).await {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::RootHealth { root_id } => match host.check_root_health(root_id) {
                Ok(health) => {
                    let mut response = ProviderIpcResponse::ok();
                    response.root_health = Some(health);
                    response
                }
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::ProbeRoot { root_id } => match host.probe_root(root_id).await {
                Ok(probe) => {
                    let mut response = ProviderIpcResponse::ok();
                    response.root_probe = Some(probe);
                    response
                }
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::DehydrateRoot { sync_root_path } => {
                match host.dehydrate_root_path(&sync_root_path) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.dehydrate_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{
        actionable_callback_handler_outcome, begin_provider_shutdown_barrier,
        complete_callback_once, drain_provider_background_tasks, hydration_completion_range,
        hydration_transfer_ranges, paths_equal_for_platform, plan_remote_reconciliation,
        startup_error_after_disconnect, validate_hydration_request, CallbackHealthObservation,
        CloudCallbackKind, CloudHydrationExecuteResult, CloudHydrationTransferTelemetry,
        CloudMutationJournal, CloudMutationKind, CloudMutationRecord, CloudObjectIdentityV2,
        CloudPlaceholderEntry, CloudProviderError, CloudProviderHost, CloudProviderStatus,
        CloudRootProbeKind, CloudRootRegistration, CloudRootRegistrationKind, CloudRootStartError,
        CloudRootStartResult, CloudRuntimePaths, CloudStateStore, DehydrateRootSummary,
        ExpectedProviderVersion, HydrationCancellationRegistry, HydrationCancellationToken,
        HydrationTemporaryFile, HydrationWorkerGate, LocalRefreshDisposition,
        NativeConnectionBacking, OffThreadDisconnectAttempt, ProviderContentVersion, Result,
        RootHealthTelemetry, RootWriterLease, StartupRecoveryActivity,
    };
    use chrono::Utc;
    use hybridcipher_provider_core::{
        normalize_relative_path, FileIdentityV1, ProviderBridge, ProviderCoreError, ProviderEntry,
        ProviderEntryKind,
    };
    use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
    use std::collections::HashMap;
    use std::{
        ffi::c_void,
        ffi::OsStr,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom},
        mem::size_of,
        os::windows::ffi::OsStrExt,
        os::windows::fs::MetadataExt,
        panic::{catch_unwind, AssertUnwindSafe},
        path::{Component, Path, PathBuf},
        ptr::null,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };
    use tokio::sync::Mutex as AsyncMutex;
    use uuid::Uuid;
    use windows::core::{GUID, HRESULT, HSTRING, PCWSTR, PWSTR};
    use windows::ApplicationModel::Package;
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Storage::Provider::{
        StorageProviderHardlinkPolicy, StorageProviderHydrationPolicy,
        StorageProviderHydrationPolicyModifier, StorageProviderInSyncPolicy,
        StorageProviderPopulationPolicy, StorageProviderSyncRootInfo,
        StorageProviderSyncRootManager,
    };
    use windows::Storage::StorageFolder;
    use windows::Win32::Foundation::{
        CloseHandle, FreeLibrary, LocalFree, ERROR_ALREADY_EXISTS,
        ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT, HANDLE, HLOCAL, NTSTATUS, RPC_E_CHANGED_MODE,
        STATUS_CLOUD_FILE_INVALID_REQUEST, STATUS_CLOUD_FILE_REQUEST_ABORTED,
        STATUS_CLOUD_FILE_UNSUCCESSFUL, STATUS_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, SetFileSecurityW, TokenUser, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
    };
    use windows::Win32::Storage::CloudFilters::{
        CfCloseHandle, CfConnectSyncRoot, CfCreatePlaceholders, CfDehydratePlaceholder,
        CfDisconnectSyncRoot, CfExecute, CfGetPlaceholderInfo, CfGetWin32HandleFromProtectedHandle,
        CfOpenFileWithOplock, CfReferenceProtectedHandle, CfRegisterSyncRoot,
        CfReleaseProtectedHandle, CfSetInSyncState, CfSetPinState, CfUnregisterSyncRoot,
        CfUpdatePlaceholder, CfUpdateSyncProviderStatus, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
        CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
        CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_FETCH_DATA,
        CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_NONE,
        CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE, CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_DELETE, CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
        CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION, CF_CALLBACK_TYPE_VALIDATE_DATA,
        CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION, CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
        CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO, CF_CREATE_FLAG_NONE, CF_DEHYDRATE_FLAG_NONE,
        CF_FS_METADATA, CF_HARDLINK_POLICY_NONE, CF_HYDRATION_POLICY,
        CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED, CF_HYDRATION_POLICY_PROGRESSIVE,
        CF_INSYNC_POLICY_TRACK_ALL, CF_IN_SYNC_STATE_IN_SYNC, CF_OPEN_FILE_FLAGS,
        CF_OPEN_FILE_FLAG_DELETE_ACCESS, CF_OPEN_FILE_FLAG_EXCLUSIVE,
        CF_OPEN_FILE_FLAG_WRITE_ACCESS, CF_OPERATION_ACK_DATA_FLAG_NONE,
        CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE, CF_OPERATION_ACK_DELETE_FLAG_NONE, CF_OPERATION_INFO,
        CF_OPERATION_PARAMETERS, CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_0,
        CF_OPERATION_PARAMETERS_0_2, CF_OPERATION_PARAMETERS_0_4, CF_OPERATION_PARAMETERS_0_5,
        CF_OPERATION_PARAMETERS_0_7, CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
        CF_OPERATION_TYPE_ACK_DATA, CF_OPERATION_TYPE_ACK_DEHYDRATE, CF_OPERATION_TYPE_ACK_DELETE,
        CF_OPERATION_TYPE_TRANSFER_DATA, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS,
        CF_PIN_STATE_UNPINNED, CF_PLACEHOLDER_BASIC_INFO,
        CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION,
        CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC, CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE,
        CF_PLACEHOLDER_CREATE_INFO, CF_PLACEHOLDER_INFO_BASIC, CF_PLACEHOLDER_INFO_STANDARD,
        CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH,
        CF_PLACEHOLDER_STANDARD_INFO, CF_POPULATION_POLICY, CF_POPULATION_POLICY_FULL,
        CF_POPULATION_POLICY_MODIFIER_NONE, CF_PROVIDER_STATUS_IDLE,
        CF_PROVIDER_STATUS_POPULATE_CONTENT, CF_PROVIDER_STATUS_TERMINATED,
        CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
        CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT, CF_REGISTER_FLAG_UPDATE, CF_SET_IN_SYNC_FLAG_NONE,
        CF_SET_PIN_FLAG_NONE, CF_SYNC_POLICIES, CF_SYNC_REGISTRATION, CF_UPDATE_FLAG_DEHYDRATE,
        CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION, CF_UPDATE_FLAG_MARK_IN_SYNC,
        CF_UPDATE_FLAG_VERIFY_IN_SYNC,
    };
    use windows::Win32::Storage::FileSystem::{
        FileDispositionInfo, FileStandardInfo, GetFileInformationByHandleEx,
        SetFileInformationByHandle, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO,
        FILE_DISPOSITION_INFO, FILE_STANDARD_INFO,
    };
    use windows::Win32::System::LibraryLoader::LoadLibraryW;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
    use zeroize::Zeroizing;

    const HYBRIDCIPHER_PROVIDER_ID: GUID = GUID::from_u128(0x9c9eb75e_7e0b_47f4_8f33_546c1a3a38c4);
    const HYBRIDCIPHER_PACKAGE_NAME: &str = "HybridCipher.Desktop";
    const WINDOWS_TICKS_PER_SECOND: i64 = 10_000_000;
    const SECONDS_FROM_1601_TO_UNIX_EPOCH: i64 = 11_644_473_600;
    const HYDRATION_CALLBACK_TIMEOUT: Duration = Duration::from_secs(50);

    struct WindowsRuntimeApartment {
        uninitialize: bool,
    }

    impl WindowsRuntimeApartment {
        fn initialize() -> Result<Self> {
            match unsafe { RoInitialize(RO_INIT_MULTITHREADED) } {
                Ok(()) => Ok(Self { uninitialize: true }),
                Err(error) if error.code() == RPC_E_CHANGED_MODE => {
                    // Tauri's UI thread is already an STA. WinRT is initialized
                    // there, so these agile storage-provider APIs remain valid.
                    Ok(Self {
                        uninitialize: false,
                    })
                }
                Err(error) => Err(error.into()),
            }
        }
    }

    impl Drop for WindowsRuntimeApartment {
        fn drop(&mut self) {
            if self.uninitialize {
                unsafe { RoUninitialize() };
            }
        }
    }

    struct FetchDataCompletion {
        status: NTSTATUS,
        file_unavailable: bool,
        handler_error: Option<String>,
        execute_error: Option<String>,
        cancellation_observed: bool,
        transferred_bytes: u64,
        requested_offset: i64,
        requested_length: i64,
        execute_results: Vec<CloudHydrationExecuteResult>,
    }

    struct HydrationOutstandingRanges {
        ranges: Vec<(i64, i64)>,
    }

    #[derive(Default)]
    struct HydrationTransferStats {
        transferred_bytes: u64,
        cancellation_observed: bool,
        execute_results: Vec<CloudHydrationExecuteResult>,
    }

    impl HydrationOutstandingRanges {
        fn new(offset: i64, length: i64) -> Self {
            Self {
                ranges: offset
                    .checked_add(length)
                    .filter(|_| offset >= 0 && length > 0)
                    .map_or_else(Vec::new, |end| vec![(offset, end)]),
            }
        }

        fn complete(&mut self, offset: i64, length: i64) {
            let Some(end) = offset
                .checked_add(length)
                .filter(|_| offset >= 0 && length > 0)
            else {
                return;
            };
            let mut remaining = Vec::new();
            for (start, range_end) in self.ranges.drain(..) {
                if end <= start || offset >= range_end {
                    remaining.push((start, range_end));
                    continue;
                }
                if offset > start {
                    remaining.push((start, offset));
                }
                if end < range_end {
                    remaining.push((end, range_end));
                }
            }
            self.ranges = remaining;
        }

        fn ranges(&self) -> Vec<(i64, i64)> {
            self.ranges.clone()
        }
    }

    pub fn status() -> CloudProviderStatus {
        match cldapi_available() {
            Ok(true) => CloudProviderStatus::new(
                true,
                true,
                0,
                Some(
                    "CldApi.dll is available; sync-root registration, placeholder creation, hydration callbacks, and local mutation callbacks are available."
                        .to_string(),
                ),
            ),
            Ok(false) => CloudProviderStatus::scaffolded(false, "CldApi.dll is not available."),
            Err(err) => {
                CloudProviderStatus::scaffolded(false, format!("Failed to probe CldApi.dll: {err}"))
            }
        }
    }

    pub fn current_user_shell_sync_root_id(root_id: Uuid) -> Result<String> {
        Ok(format!("HybridCipher!{}!{}", current_user_sid()?, root_id))
    }

    fn current_user_sid() -> Result<String> {
        struct OwnedToken(HANDLE);
        impl Drop for OwnedToken {
            fn drop(&mut self) {
                if !self.0.is_invalid() {
                    let _ = unsafe { CloseHandle(self.0) };
                }
            }
        }

        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)? };
        let token = OwnedToken(token);
        let mut required = 0u32;
        let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
        if required < size_of::<TOKEN_USER>() as u32 {
            return Err(CloudProviderError::Callback(
                "Windows did not return a current-user token SID".into(),
            ));
        }
        let word_size = size_of::<usize>();
        let mut buffer = vec![0usize; (required as usize + word_size - 1) / word_size];
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )?
        };
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        let mut sid = PWSTR::null();
        unsafe { ConvertSidToStringSidW(token_user.User.Sid, &mut sid)? };
        let sid_string = unsafe { sid.to_string() }.map_err(|error| {
            CloudProviderError::Callback(format!("Windows returned an invalid user SID: {error}"))
        })?;
        let _ = unsafe { LocalFree(Some(HLOCAL(sid.0.cast()))) };
        Ok(sid_string)
    }

    pub fn restrict_hydration_temp_directory(path: &Path) -> Result<()> {
        ensure_existing_dir(path, "hydration temporary directory")?;
        let descriptor_text = format!("D:P(A;OICI;FA;;;{})(A;OICI;FA;;;SY)", current_user_sid()?);
        let descriptor_wide = to_wide(OsStr::new(&descriptor_text));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(descriptor_wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )?;
        }
        struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);
        impl Drop for OwnedSecurityDescriptor {
            fn drop(&mut self) {
                if !self.0 .0.is_null() {
                    let _ = unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
                }
            }
        }
        let descriptor = OwnedSecurityDescriptor(descriptor);
        let path_wide = to_wide(path.as_os_str());
        unsafe {
            SetFileSecurityW(
                PCWSTR(path_wide.as_ptr()),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
            .ok()?;
        }
        Ok(())
    }

    pub fn unregister_all_shell_roots() -> Result<usize> {
        let _apartment = WindowsRuntimeApartment::initialize()?;
        if !StorageProviderSyncRootManager::IsSupported()? {
            return Ok(0);
        }
        let prefix = format!("HybridCipher!{}!", current_user_sid()?);
        let roots = StorageProviderSyncRootManager::GetCurrentSyncRoots()?;
        let mut registrations = Vec::new();
        for index in 0..roots.Size()? {
            let root = roots.GetAt(index)?;
            let id = root.Id()?.to_string_lossy();
            let shell_integrated = id.starts_with(&prefix);
            let legacy_hybridcipher = root
                .ProviderId()
                .is_ok_and(|provider_id| provider_id == HYBRIDCIPHER_PROVIDER_ID);
            if shell_integrated || legacy_hybridcipher {
                let path = PathBuf::from(root.Path()?.Path()?.to_string_lossy());
                registrations.push((id, path, shell_integrated));
            }
        }
        for (id, path, shell_integrated) in &registrations {
            if path.exists() {
                let summary = dehydrate_root(path)?;
                if summary.failed_count > 0 {
                    return Err(CloudProviderError::Callback(format!(
                        "refusing to unregister Explorer sync root {id}: {} placeholder(s) could not be safely dehydrated",
                        summary.failed_count
                    )));
                }
                verify_root_dehydrated(path)?;
                clear_dehydrated_root(path)?;
            }
            if *shell_integrated {
                StorageProviderSyncRootManager::Unregister(&HSTRING::from(id))?;
            } else {
                unregister_root(path)?;
            }
            if path.exists() {
                fs::remove_dir(path)?;
            }
        }
        Ok(registrations.len())
    }

    pub fn register_root(registration: &CloudRootRegistration) -> Result<()> {
        match registration.registration_kind {
            CloudRootRegistrationKind::ShellIntegrated => register_shell_root(registration),
            CloudRootRegistrationKind::LegacyCfApi => register_cfapi_root(registration),
        }
    }

    fn production_package_identity() -> Result<Package> {
        let package = Package::Current().map_err(|error| {
            CloudProviderError::Callback(format!(
                "HybridCipher's Windows package identity is missing ({error}). Repair or reinstall HybridCipher before mounting this vault"
            ))
        })?;
        let package_name = package.Id()?.Name()?.to_string_lossy();
        if package_name != HYBRIDCIPHER_PACKAGE_NAME {
            return Err(CloudProviderError::Callback(format!(
                "HybridCipher's Windows package identity is '{package_name}', expected '{HYBRIDCIPHER_PACKAGE_NAME}'. Repair or reinstall HybridCipher"
            )));
        }
        Ok(package)
    }

    fn register_shell_root(registration: &CloudRootRegistration) -> Result<()> {
        let _apartment = WindowsRuntimeApartment::initialize()?;
        ensure_absolute_or_create_root(&registration.sync_root_path)?;
        ensure_existing_dir(&registration.encrypted_root, "encrypted root")?;
        let package = production_package_identity()?;
        if !StorageProviderSyncRootManager::IsSupported()? {
            return Err(CloudProviderError::Callback(
                "Windows Shell cloud-file registration is unavailable; HybridCipher requires Windows 10 build 19041 or newer"
                    .into(),
            ));
        }
        let expected_id = current_user_shell_sync_root_id(registration.root_id)?;
        let sync_root_id = registration.shell_sync_root_id.as_deref().ok_or_else(|| {
            CloudProviderError::Callback(
                "Shell-integrated registration is missing its stable sync-root ID".into(),
            )
        })?;
        if sync_root_id != expected_id {
            return Err(CloudProviderError::Callback(format!(
                "Shell sync-root ID does not match the current user and root UUID (expected {expected_id})"
            )));
        }

        let id = HSTRING::from(sync_root_id);
        if let Ok(existing) = StorageProviderSyncRootManager::GetSyncRootInformationForId(&id) {
            let existing_path = existing.Path()?.Path()?.to_string_lossy();
            if paths_equal_for_platform(Path::new(&existing_path), &registration.sync_root_path) {
                tracing::info!(
                    root_id = %registration.root_id,
                    shell_sync_root_id = sync_root_id,
                    "Reusing existing Windows Shell sync-root registration"
                );
                return Ok(());
            }
            return Err(CloudProviderError::Callback(format!(
                "Windows Shell sync-root ID {sync_root_id} is already registered at {existing_path}"
            )));
        }

        let path = HSTRING::from(registration.sync_root_path.to_string_lossy().as_ref());
        let folder = StorageFolder::GetFolderFromPathAsync(&path)?.get()?;
        let info = StorageProviderSyncRootInfo::new()?;
        info.SetId(&id)?;
        info.SetPath(&folder)?;
        info.SetDisplayNameResource(&HSTRING::from(&registration.display_name))?;
        let executable = std::env::current_exe()?;
        info.SetIconResource(&HSTRING::from(format!("{},0", executable.display())))?;
        info.SetProviderId(HYBRIDCIPHER_PROVIDER_ID)?;
        info.SetHydrationPolicy(StorageProviderHydrationPolicy::Progressive)?;
        info.SetHydrationPolicyModifier(
            StorageProviderHydrationPolicyModifier::StreamingAllowed
                | StorageProviderHydrationPolicyModifier::AutoDehydrationAllowed,
        )?;
        info.SetPopulationPolicy(StorageProviderPopulationPolicy::AlwaysFull)?;
        info.SetInSyncPolicy(
            StorageProviderInSyncPolicy::FileCreationTime
                | StorageProviderInSyncPolicy::FileReadOnlyAttribute
                | StorageProviderInSyncPolicy::FileHiddenAttribute
                | StorageProviderInSyncPolicy::FileSystemAttribute
                | StorageProviderInSyncPolicy::DirectoryCreationTime
                | StorageProviderInSyncPolicy::DirectoryReadOnlyAttribute
                | StorageProviderInSyncPolicy::DirectoryHiddenAttribute
                | StorageProviderInSyncPolicy::DirectorySystemAttribute
                | StorageProviderInSyncPolicy::FileLastWriteTime
                | StorageProviderInSyncPolicy::DirectoryLastWriteTime,
        )?;
        info.SetHardlinkPolicy(StorageProviderHardlinkPolicy::None)?;
        info.SetAllowPinning(true)?;
        info.SetShowSiblingsAsGroup(false)?;
        let package_version = package.Id()?.Version()?;
        info.SetVersion(&HSTRING::from(format!(
            "{}.{}.{}.{}",
            package_version.Major,
            package_version.Minor,
            package_version.Build,
            package_version.Revision
        )))?;
        info.SetContext(&CryptographicBuffer::CreateFromByteArray(
            registration.root_id.as_bytes(),
        )?)?;
        StorageProviderSyncRootManager::Register(&info)?;
        Ok(())
    }

    fn register_cfapi_root(registration: &CloudRootRegistration) -> Result<()> {
        ensure_absolute_or_create_root(&registration.sync_root_path)?;
        ensure_existing_dir(&registration.encrypted_root, "encrypted root")?;

        let sync_root_path = to_wide(registration.sync_root_path.as_os_str());
        let provider_name = to_wide(OsStr::new(&registration.display_name));
        let provider_version = to_wide(OsStr::new(env!("CARGO_PKG_VERSION")));
        let sync_root_identity = registration.root_id.as_bytes().to_vec();
        let file_identity = registration.root_id.as_bytes().to_vec();

        let sync_registration = CF_SYNC_REGISTRATION {
            StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: PCWSTR(provider_name.as_ptr()),
            ProviderVersion: PCWSTR(provider_version.as_ptr()),
            SyncRootIdentity: sync_root_identity.as_ptr().cast(),
            SyncRootIdentityLength: sync_root_identity.len() as u32,
            FileIdentity: file_identity.as_ptr().cast(),
            FileIdentityLength: file_identity.len() as u32,
            ProviderId: HYBRIDCIPHER_PROVIDER_ID,
        };

        let policies = CF_SYNC_POLICIES {
            StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_PROGRESSIVE,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED,
            },
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            InSync: CF_INSYNC_POLICY_TRACK_ALL,
            HardLink: CF_HARDLINK_POLICY_NONE,
            PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
        };

        let flags = CF_REGISTER_FLAG_UPDATE
            | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT
            | CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT;

        let result = unsafe {
            CfRegisterSyncRoot(
                PCWSTR(sync_root_path.as_ptr()),
                &sync_registration,
                &policies,
                flags,
            )
        };
        if let Err(err) = result {
            if windows_error_matches(&err, ERROR_ALREADY_EXISTS) {
                tracing::info!(
                    "Cloud Files sync root already exists at {}; reusing existing registration",
                    registration.sync_root_path.display()
                );
            } else {
                return Err(err.into());
            }
        }
        Ok(())
    }

    pub fn unregister_registration(registration: &CloudRootRegistration) -> Result<()> {
        match registration.registration_kind {
            CloudRootRegistrationKind::ShellIntegrated => {
                let _apartment = WindowsRuntimeApartment::initialize()?;
                let id = registration.shell_sync_root_id.as_deref().ok_or_else(|| {
                    CloudProviderError::Callback(
                        "Shell-integrated registration is missing its stable sync-root ID".into(),
                    )
                })?;
                match StorageProviderSyncRootManager::Unregister(&HSTRING::from(id)) {
                    Ok(()) => Ok(()),
                    Err(_error)
                        if StorageProviderSyncRootManager::GetSyncRootInformationForId(
                            &HSTRING::from(id),
                        )
                        .is_err() =>
                    {
                        tracing::info!(
                            shell_sync_root_id = id,
                            "Shell sync root is already unregistered"
                        );
                        Ok(())
                    }
                    Err(error) => Err(error.into()),
                }
            }
            CloudRootRegistrationKind::LegacyCfApi => unregister_root(&registration.sync_root_path),
        }
    }

    fn verify_registration(registration: &CloudRootRegistration) -> Result<()> {
        if registration.registration_kind == CloudRootRegistrationKind::LegacyCfApi {
            return Ok(());
        }
        let _apartment = WindowsRuntimeApartment::initialize()?;
        let _ = production_package_identity()?;
        let id = registration.shell_sync_root_id.as_deref().ok_or_else(|| {
            CloudProviderError::Callback(
                "Shell-integrated registration is missing its stable sync-root ID".into(),
            )
        })?;
        let info = StorageProviderSyncRootManager::GetSyncRootInformationForId(&HSTRING::from(id))
            .map_err(|error| {
                CloudProviderError::Callback(format!(
                    "Windows Shell sync-root registration {id} is missing ({error}). Repair the HybridCipher installation and remount the vault"
                ))
            })?;
        let registered_path = info.Path()?.Path()?.to_string_lossy();
        if !paths_equal_for_platform(Path::new(&registered_path), &registration.sync_root_path) {
            return Err(CloudProviderError::Callback(format!(
                "Windows Shell sync-root registration {id} points to {registered_path}, expected {}",
                registration.sync_root_path.display()
            )));
        }
        Ok(())
    }

    pub fn unregister_root(sync_root_path: &Path) -> Result<()> {
        ensure_absolute_path(sync_root_path, "sync root")?;
        let sync_root_path = to_wide(sync_root_path.as_os_str());
        let result = unsafe { CfUnregisterSyncRoot(PCWSTR(sync_root_path.as_ptr())) };
        if let Err(err) = result {
            if windows_error_matches(&err, ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT) {
                tracing::info!("Cloud Files path is already unregistered; continuing cleanup");
            } else {
                return Err(err.into());
            }
        }
        Ok(())
    }

    pub fn create_placeholders(
        sync_root_path: &Path,
        entries: &[CloudPlaceholderEntry],
    ) -> Result<u32> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        if entries.is_empty() {
            return Ok(0);
        }

        let ordered_entries = ordered_placeholder_entries(entries);
        let mut processed_total = 0u32;
        for entry in ordered_entries {
            processed_total = processed_total.saturating_add(create_single_placeholder(
                sync_root_path,
                entry,
                None,
            )?);
        }
        Ok(processed_total)
    }

    fn apply_reconciliation_placeholders(
        sync_root_path: &Path,
        entries: &[CloudPlaceholderEntry],
        current_state: &super::CloudRootPersistentState,
        placeholder_guard_ids: &HashMap<String, String>,
        guards: &HashMap<String, CloudFileOplock>,
    ) -> Result<u32> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        let ordered_entries = ordered_placeholder_entries(entries);
        let mut processed_total = 0u32;
        for entry in ordered_entries {
            let guard_object_id = placeholder_guard_ids
                .get(&entry.identity.object_id)
                .unwrap_or(&entry.identity.object_id);
            let guard = current_state
                .items
                .get(guard_object_id)
                .filter(|current| current.relative_path == entry.entry.relative_path)
                .and_then(|_| guards.get(guard_object_id));
            processed_total = processed_total.saturating_add(create_single_placeholder(
                sync_root_path,
                entry,
                guard,
            )?);
        }
        Ok(processed_total)
    }

    fn ordered_placeholder_entries(
        entries: &[CloudPlaceholderEntry],
    ) -> Vec<&CloudPlaceholderEntry> {
        let mut ordered = entries.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            placeholder_kind_rank(left.entry.kind)
                .cmp(&placeholder_kind_rank(right.entry.kind))
                .then_with(|| {
                    path_depth(&left.entry.relative_path)
                        .cmp(&path_depth(&right.entry.relative_path))
                })
                .then_with(|| left.entry.relative_path.cmp(&right.entry.relative_path))
        });
        ordered
    }

    fn placeholder_kind_rank(kind: ProviderEntryKind) -> u8 {
        match kind {
            ProviderEntryKind::Directory => 0,
            ProviderEntryKind::File => 1,
        }
    }

    fn path_depth(path: &str) -> usize {
        path.replace('\\', "/")
            .split('/')
            .filter(|component| !component.is_empty())
            .count()
    }

    fn create_single_placeholder(
        sync_root_path: &Path,
        entry: &CloudPlaceholderEntry,
        guard: Option<&CloudFileOplock>,
    ) -> Result<u32> {
        let (base_path, relative_name, full_path, display_path) =
            placeholder_location(sync_root_path, &entry.entry)?;
        let base_path_wide = to_wide(base_path.as_os_str());
        let placeholder = OwnedPlaceholder::new(entry, relative_name, full_path, display_path)?;

        if let Some(guard) = guard {
            update_existing_placeholder_with_handle(&placeholder, guard)?;
            return Ok(1);
        }

        for attempt in 0..2 {
            let mut processed = 0u32;
            let mut single = [placeholder.info];
            let result = unsafe {
                CfCreatePlaceholders(
                    PCWSTR(base_path_wide.as_ptr()),
                    &mut single,
                    CF_CREATE_FLAG_NONE,
                    Some(&mut processed),
                )
            };
            match result {
                Ok(()) if processed > 0 => {
                    if hresult_matches(single[0].Result, ERROR_ALREADY_EXISTS) {
                        if recover_existing_placeholder(&placeholder)? && attempt == 0 {
                            continue;
                        }
                        update_existing_placeholder(&placeholder)?;
                        return Ok(1);
                    }
                    return inspect_placeholder_results(
                        std::slice::from_ref(&placeholder),
                        &single,
                    );
                }
                Ok(()) => {
                    return Err(CloudProviderError::Callback(format!(
                        "Cloud Files did not confirm placeholder creation for {}",
                        placeholder.relative_path()
                    )));
                }
                Err(err) if windows_error_matches(&err, ERROR_ALREADY_EXISTS) => {
                    if recover_existing_placeholder(&placeholder)? && attempt == 0 {
                        continue;
                    }
                    update_existing_placeholder(&placeholder)?;
                    return Ok(1);
                }
                Err(err) => return Err(err.into()),
            }
        }

        Err(CloudProviderError::Callback(format!(
            "Cloud Files did not confirm placeholder creation for {}",
            placeholder.relative_path()
        )))
    }

    fn placeholder_location(
        sync_root_path: &Path,
        entry: &ProviderEntry,
    ) -> Result<(PathBuf, Vec<u16>, PathBuf, String)> {
        let relative_path = validate_relative_path(&entry.relative_path)?;
        let relative_path_buf = PathBuf::from(&relative_path);
        let relative_name = relative_path_buf
            .file_name()
            .ok_or_else(|| {
                CloudProviderError::InvalidPath(format!(
                    "placeholder relative path is missing a file name: {}",
                    entry.relative_path
                ))
            })
            .map(to_wide)?;
        let base_path = relative_path_buf
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| sync_root_path.join(parent))
            .unwrap_or_else(|| sync_root_path.to_path_buf());
        let full_path = sync_root_path.join(&relative_path_buf);
        Ok((base_path, relative_name, full_path, relative_path))
    }

    fn recover_existing_placeholder(placeholder: &OwnedPlaceholder) -> Result<bool> {
        let metadata = fs::symlink_metadata(&placeholder.full_path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            tracing::debug!(
                "Cloud Files placeholder already exists for {}; preserving existing entry",
                placeholder.relative_path()
            );
            return Ok(false);
        }

        if placeholder.kind == ProviderEntryKind::Directory
            && metadata.is_dir()
            && directory_is_empty(&placeholder.full_path)?
        {
            tracing::debug!(
                "Removing empty non-placeholder directory before Cloud Files placeholder recreation: {}",
                placeholder.full_path.display()
            );
            fs::remove_dir(&placeholder.full_path)?;
            return Ok(true);
        }

        Err(CloudProviderError::InvalidPath(format!(
            "Cloud Files path already exists but is not a provider placeholder: {}. Unmount and reset the Cloud Files root before retrying.",
            placeholder.full_path.display()
        )))
    }

    fn update_existing_placeholder(placeholder: &OwnedPlaceholder) -> Result<()> {
        let path = to_wide(placeholder.full_path.as_os_str());
        unsafe {
            let handle = CfOpenFileWithOplock(
                PCWSTR(path.as_ptr()),
                CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
            )?;
            let result = update_existing_placeholder_with_raw_handle(placeholder, handle);
            CfCloseHandle(handle);
            result?;
        }
        Ok(())
    }

    fn update_existing_placeholder_with_handle(
        placeholder: &OwnedPlaceholder,
        guard: &CloudFileOplock,
    ) -> Result<()> {
        unsafe { update_existing_placeholder_with_raw_handle(placeholder, guard.0)? };
        Ok(())
    }

    unsafe fn update_existing_placeholder_with_raw_handle(
        placeholder: &OwnedPlaceholder,
        handle: HANDLE,
    ) -> windows::core::Result<()> {
        let flags = placeholder_update_flags(placeholder.kind, placeholder.dirty);
        unsafe {
            CfUpdatePlaceholder(
                handle,
                Some(&placeholder.info.FsMetadata as *const _),
                Some(placeholder.identity.as_ptr().cast()),
                placeholder.identity.len() as u32,
                None,
                flags,
                None,
                None,
            )
        }
    }

    fn placeholder_update_flags(
        kind: ProviderEntryKind,
        dirty: bool,
    ) -> windows::Win32::Storage::CloudFilters::CF_UPDATE_FLAGS {
        let mut flags = CF_UPDATE_FLAG_MARK_IN_SYNC;
        match kind {
            ProviderEntryKind::Directory => {
                // The complete directory inventory is already materialized by reconciliation.
                // Upgrade older partial placeholders so nested file operations no longer trigger
                // an empty FETCH_PLACEHOLDERS loop.
                flags |= CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
            }
            ProviderEntryKind::File if !dirty => {
                flags |= CF_UPDATE_FLAG_DEHYDRATE | CF_UPDATE_FLAG_VERIFY_IN_SYNC;
            }
            ProviderEntryKind::File => {}
        }
        flags
    }

    fn directory_is_empty(path: &Path) -> Result<bool> {
        let mut entries = fs::read_dir(path)?;
        Ok(entries.next().transpose()?.is_none())
    }

    fn inspect_placeholder_results(
        requested: &[OwnedPlaceholder],
        results: &[CF_PLACEHOLDER_CREATE_INFO],
    ) -> Result<u32> {
        let mut confirmed_count = 0u32;
        for (placeholder, result) in requested.iter().zip(results.iter()) {
            if result.Result.is_ok() {
                confirmed_count = confirmed_count.saturating_add(1);
                continue;
            }

            return Err(CloudProviderError::Callback(format!(
                "failed to create Cloud Files placeholder for {}: {}",
                placeholder.relative_path(),
                windows::core::Error::from(result.Result)
            )));
        }
        Ok(confirmed_count)
    }

    pub fn dehydrate_root(sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        dehydrate_root_filtered(sync_root_path, &super::no_cloud_cleanup_path_filter)
    }

    pub fn dehydrate_root_filtered(
        sync_root_path: &Path,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<DehydrateRootSummary> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        let mut summary = DehydrateRootSummary {
            sync_root_path: sync_root_path.to_path_buf(),
            attempted_count: 0,
            dehydrated_count: 0,
            failed_count: 0,
            failures: Vec::new(),
            updated_at: chrono::Utc::now(),
        };
        dehydrate_tree(sync_root_path, &mut summary, cleanup_path_filter)?;
        summary.updated_at = chrono::Utc::now();
        Ok(summary)
    }

    #[allow(dead_code)]
    pub fn verify_root_dehydrated(sync_root_path: &Path) -> Result<()> {
        verify_root_dehydrated_filtered(sync_root_path, &super::no_cloud_cleanup_path_filter)
    }

    pub fn verify_root_dehydrated_filtered(
        sync_root_path: &Path,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        verify_dehydrated_tree(sync_root_path, cleanup_path_filter)
    }

    #[allow(dead_code)]
    pub fn clear_dehydrated_root(sync_root_path: &Path) -> Result<()> {
        clear_dehydrated_root_filtered(sync_root_path, &super::no_cloud_cleanup_path_filter)
    }

    pub fn clear_dehydrated_root_filtered(
        sync_root_path: &Path,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        verify_root_dehydrated_filtered(sync_root_path, cleanup_path_filter)?;
        clear_dehydrated_tree(sync_root_path, cleanup_path_filter)
    }

    pub fn active_probe(sync_root_path: &Path) -> Result<CloudRootProbeKind> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        let mut pending = vec![sync_root_path.to_path_buf()];
        let mut inspected = 0usize;
        while let Some(directory) = pending.pop() {
            for entry in fs::read_dir(directory)? {
                let entry = entry?;
                inspected = inspected.saturating_add(1);
                if inspected > 512 {
                    break;
                }
                let path = entry.path();
                let metadata = entry.metadata()?;
                if metadata.is_dir() {
                    if pending.len() < 64 {
                        pending.push(path);
                    }
                    continue;
                }
                if !metadata.is_file() {
                    continue;
                }
                let is_placeholder = metadata.file_attributes() & 0x0000_0400 != 0;
                if !is_placeholder {
                    continue;
                }
                // The provider is connected with BLOCK_SELF_IMPLICIT_HYDRATION. Reading
                // its own offline placeholder can therefore cancel the FETCH_DATA request
                // and surface ERROR_CLOUD_FILE_ACCESS_DENIED. Validate Cloud Files metadata
                // through an oplock instead; real client reads exercise hydration callbacks.
                let handle = CloudFileOplock::acquire_exclusive(&path)?;
                let _ = handle.is_in_sync()?;
                return Ok(CloudRootProbeKind::Namespace);
            }
            if inspected > 512 {
                break;
            }
        }

        Ok(CloudRootProbeKind::Namespace)
    }

    fn startup_error_with_recovery_failure(
        startup_error: CloudProviderError,
        recovery_error: Option<CloudProviderError>,
    ) -> CloudProviderError {
        match recovery_error {
            Some(recovery_error) => CloudProviderError::Callback(format!(
                "{startup_error}; failed to persist startup recovery state: {recovery_error}"
            )),
            None => startup_error,
        }
    }

    async fn cleanup_connected_startup_failure(
        connected: &mut ConnectedCloudRoot,
        context: &CallbackContext,
        startup_error: CloudProviderError,
    ) -> CloudRootStartError {
        match connected.disconnect().await {
            Ok(()) => {
                let _ = context.health.record_start_failure(
                    context.health_generation,
                    Utc::now(),
                    startup_error.to_string(),
                );
                startup_error_after_disconnect(startup_error, Ok(()))
            }
            Err(disconnect_error) => {
                let _ = context.health.record_startup_cleanup_failure(
                    context.health_generation,
                    Utc::now(),
                    startup_error.to_string(),
                    disconnect_error.to_string(),
                );
                startup_error_after_disconnect(startup_error, Err(disconnect_error))
            }
        }
    }

    pub async fn connect_root(
        registration: &CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
        entries: Vec<CloudPlaceholderEntry>,
        runtime_paths: CloudRuntimePaths,
        writer_lease: Arc<RootWriterLease>,
        health: RootHealthTelemetry,
        health_generation: u64,
    ) -> CloudRootStartResult<ConnectedCloudRoot> {
        ensure_existing_dir(&registration.sync_root_path, "sync root")?;
        ensure_existing_dir(&registration.encrypted_root, "encrypted root")?;
        verify_registration(registration)?;

        let sync_root_path_wide = to_wide(registration.sync_root_path.as_os_str());
        let context = Arc::new(CallbackContext::new(
            registration.clone(),
            bridge,
            entries,
            runtime_paths,
            writer_lease,
            health,
            health_generation,
            tokio::runtime::Handle::current(),
        ));
        let startup_gate = context.operation_lock.lock().await;
        let context_ptr = Arc::as_ptr(&context) as *const c_void;
        let callback_table = callback_registrations();
        let connection_key = unsafe {
            CfConnectSyncRoot(
                PCWSTR(sync_root_path_wide.as_ptr()),
                callback_table.as_ptr(),
                Some(context_ptr),
                CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH
                    | CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO
                    | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
            )
            .map_err(CloudProviderError::from)?
        };
        unsafe {
            let _ = CfUpdateSyncProviderStatus(connection_key, CF_PROVIDER_STATUS_IDLE);
        }
        let mut connected = ConnectedCloudRoot {
            root_id: registration.root_id,
            sync_root_path: registration.sync_root_path.clone(),
            connection_key: Some(connection_key),
            backing: NativeConnectionBacking::new(ConnectedCloudRootBacking {
                _callback_table: callback_table,
                context: context.clone(),
            }),
            _watchers: Vec::new(),
            background_tasks: Vec::new(),
            disconnect_attempt: OffThreadDisconnectAttempt::default(),
            drop_fallback_attempted: false,
        };
        let (watchers, background_tasks) = match start_background_sync(context.clone()) {
            Ok(background) => background,
            Err(err) => {
                context.startup_activity.begin_shutdown();
                drop(startup_gate);
                return Err(cleanup_connected_startup_failure(&mut connected, &context, err).await);
            }
        };
        connected._watchers = watchers;
        connected.background_tasks = background_tasks;
        // Recovery can require plaintext. The native provider must be connected first.
        if let Err(err) = context.replay_pending_locked(false).await {
            context.startup_activity.begin_shutdown();
            drop(startup_gate);
            return Err(cleanup_connected_startup_failure(&mut connected, &context, err).await);
        }
        if let Err(err) = context.reconcile_remote_inventory_locked().await {
            let recovery_error = context.mark_startup_recovery_failed(&err).err();
            context.startup_activity.begin_shutdown();
            drop(startup_gate);
            let startup_error = startup_error_with_recovery_failure(err, recovery_error);
            return Err(
                cleanup_connected_startup_failure(&mut connected, &context, startup_error).await,
            );
        }
        if let Err(err) = context.ingest_local_tree_locked().await {
            let recovery_error = context.mark_startup_recovery_failed(&err).err();
            context.startup_activity.begin_shutdown();
            drop(startup_gate);
            let startup_error = startup_error_with_recovery_failure(err, recovery_error);
            return Err(
                cleanup_connected_startup_failure(&mut connected, &context, startup_error).await,
            );
        }
        if let Err(err) = context.state_store.complete_startup_recovery() {
            context.startup_activity.begin_shutdown();
            drop(startup_gate);
            return Err(cleanup_connected_startup_failure(&mut connected, &context, err).await);
        }
        if let Err(err) = context.write_runtime_status(None) {
            context.startup_activity.begin_shutdown();
            drop(startup_gate);
            return Err(cleanup_connected_startup_failure(&mut connected, &context, err).await);
        }
        context.startup_activity.mark_running();
        drop(startup_gate);
        Ok(connected)
    }

    fn dehydrate_tree(
        path: &Path,
        summary: &mut DehydrateRootSummary,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if cleanup_path_filter(&path) {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                dehydrate_tree(&path, summary, cleanup_path_filter)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            summary.attempted_count = summary.attempted_count.saturating_add(1);
            match dehydrate_file(&path) {
                Ok(()) => {
                    summary.dehydrated_count = summary.dehydrated_count.saturating_add(1);
                }
                Err(err) => {
                    summary.failed_count = summary.failed_count.saturating_add(1);
                    summary.failures.push(format!("{}: {err}", path.display()));
                }
            }
        }
        Ok(())
    }

    fn dehydrate_file(path: &Path) -> Result<()> {
        let guard = CloudFileOplock::acquire_exclusive(path)?;
        unsafe {
            // Explicit eviction/unmount overrides an item's prior pin intent because
            // Windows rejects dehydration while a placeholder remains pinned.
            CfSetPinState(guard.0, CF_PIN_STATE_UNPINNED, CF_SET_PIN_FLAG_NONE, None)?;
            CfDehydratePlaceholder(guard.0, 0, -1, CF_DEHYDRATE_FLAG_NONE, None)?;
        }
        Ok(())
    }

    fn verify_dehydrated_tree(
        path: &Path,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child = entry.path();
            if cleanup_path_filter(&child) {
                continue;
            }
            let file_type = entry.file_type()?;
            let metadata = fs::symlink_metadata(&child)?;
            if file_type.is_symlink() {
                return Err(CloudProviderError::InvalidPath(format!(
                    "refusing to clear symlink or junction from Cloud Files mount: {}",
                    child.display()
                )));
            }
            if file_type.is_dir() {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    let canonical_child = fs::canonicalize(&child)?;
                    let lexical_child = fs::canonicalize(path)?.join(entry.file_name());
                    if !super::paths_equal_for_platform(&canonical_child, &lexical_child) {
                        return Err(CloudProviderError::InvalidPath(format!(
                            "refusing to traverse reparse directory outside its Cloud Files path: {}",
                            child.display()
                        )));
                    }
                }
                verify_dehydrated_tree(&child, cleanup_path_filter)?;
                continue;
            }
            if !file_type.is_file() {
                return Err(CloudProviderError::InvalidPath(format!(
                    "refusing to clear unsupported entry from Cloud Files mount: {}",
                    child.display()
                )));
            }
            verify_dehydrated_file(&child)?;
        }
        Ok(())
    }

    fn verify_dehydrated_file(path: &Path) -> Result<()> {
        let placeholder = CloudFileOplock::acquire_exclusive(path).map_err(|err| {
            CloudProviderError::Callback(format!(
                "ordinary file remains in Cloud Files mount after dehydration: {} ({err})",
                path.display()
            ))
        })?;
        verify_dehydrated_file_with_oplock(path, &placeholder)
    }

    /// Largest `AllocationSize` NTFS can report for a stream whose bytes live
    /// inside its MFT record. Resident attribute values are rounded up to an
    /// 8-byte boundary, so a placeholder that once held a small file keeps that
    /// rounded allocation after dehydration even though no file data remains.
    fn resident_allocation_bound(end_of_file: i64) -> i64 {
        end_of_file.saturating_add(7) & !7
    }

    fn verify_dehydrated_file_with_oplock(
        path: &Path,
        placeholder: &CloudFileOplock,
    ) -> Result<()> {
        // A successful placeholder query is also the test for "is this still an
        // ordinary file someone dropped into the mount".
        let residency = placeholder.data_residency().map_err(|err| {
            CloudProviderError::Callback(format!(
                "ordinary file remains in Cloud Files mount after dehydration: {} ({err})",
                path.display()
            ))
        })?;
        if !residency.in_sync {
            return Err(CloudProviderError::Callback(format!(
                "out-of-sync placeholder remains in Cloud Files mount after dehydration: {}",
                path.display()
            )));
        }
        // `OnDiskDataSize` is Cloud Files' own count of file bytes still on
        // disk, which is the authoritative dehydration test. `AllocationSize`
        // is not: NTFS keeps a small file's bytes resident in the MFT record,
        // and dehydration has no clusters to release there, so allocation stays
        // at the 8-byte-rounded file size forever.
        if residency.on_disk_data_size != 0 || residency.modified_data_size != 0 {
            return Err(CloudProviderError::Callback(format!(
                "resident file remains in Cloud Files mount after dehydration: {} ({} on-disk data bytes, {} modified data bytes)",
                path.display(),
                residency.on_disk_data_size,
                residency.modified_data_size,
            )));
        }
        // Cloud Files reports no file data left. Still refuse an allocation
        // larger than MFT residency can account for, so a placeholder that
        // under-reports its on-disk data cannot slip plaintext past cleanup.
        let allocation = placeholder.file_allocation()?;
        let resident_bound = resident_allocation_bound(allocation.end_of_file);
        if allocation.allocation_size > resident_bound {
            return Err(CloudProviderError::Callback(format!(
                "unexpected disk allocation remains in Cloud Files mount after dehydration: {} ({} allocated bytes exceed the {resident_bound}-byte resident bound for a {}-byte file)",
                path.display(),
                allocation.allocation_size,
                allocation.end_of_file,
            )));
        }
        Ok(())
    }

    fn clear_dehydrated_tree(
        path: &Path,
        cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let child = entry.path();
            let file_type = entry.file_type()?;
            let metadata = fs::symlink_metadata(&child)?;
            if file_type.is_symlink() {
                return Err(CloudProviderError::InvalidPath(format!(
                    "refusing to clear symlink or junction from Cloud Files mount: {}",
                    child.display()
                )));
            }
            if cleanup_path_filter(&child) {
                clear_excluded_cache_tree(&child)?;
                continue;
            }
            if file_type.is_dir() {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                    let canonical_child = fs::canonicalize(&child)?;
                    let lexical_child = fs::canonicalize(path)?.join(entry.file_name());
                    if !super::paths_equal_for_platform(&canonical_child, &lexical_child) {
                        return Err(CloudProviderError::InvalidPath(format!(
                            "refusing to traverse reparse directory outside its Cloud Files path: {}",
                            child.display()
                        )));
                    }
                }
                clear_dehydrated_tree(&child, cleanup_path_filter)?;
                fs::remove_dir(&child)?;
                continue;
            }
            if !file_type.is_file() {
                return Err(CloudProviderError::InvalidPath(format!(
                    "refusing to clear unsupported entry from Cloud Files mount: {}",
                    child.display()
                )));
            }
            let placeholder = CloudFileOplock::acquire_exclusive_for_delete(&child)?;
            verify_dehydrated_file_with_oplock(&child, &placeholder)?;
            placeholder.delete()?;
        }
        Ok(())
    }

    fn clear_excluded_cache_tree(path: &Path) -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() {
            return Err(CloudProviderError::InvalidPath(format!(
                "refusing to clear symlink or junction from Cloud Files mount: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
                let canonical_path = fs::canonicalize(path)?;
                let lexical_path = path
                    .parent()
                    .map(fs::canonicalize)
                    .transpose()?
                    .unwrap_or_else(|| PathBuf::from(""))
                    .join(path.file_name().ok_or_else(|| {
                        CloudProviderError::InvalidPath(format!(
                            "refusing to clear unnamed reparse directory: {}",
                            path.display()
                        ))
                    })?);
                if !super::paths_equal_for_platform(&canonical_path, &lexical_path) {
                    return Err(CloudProviderError::InvalidPath(format!(
                        "refusing to traverse reparse directory outside its Cloud Files path: {}",
                        path.display()
                    )));
                }
            }
            for entry in fs::read_dir(path)? {
                clear_excluded_cache_tree(&entry?.path())?;
            }
            fs::remove_dir(path)?;
            return Ok(());
        }
        if metadata.is_file() {
            fs::remove_file(path)?;
            return Ok(());
        }
        Err(CloudProviderError::InvalidPath(format!(
            "refusing to clear unsupported entry from Cloud Files mount: {}",
            path.display()
        )))
    }

    fn cldapi_available() -> windows::core::Result<bool> {
        let dll_name = OsStr::new("CldApi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            match LoadLibraryW(PCWSTR(dll_name.as_ptr())) {
                Ok(module) => {
                    let _ = FreeLibrary(module);
                    Ok(true)
                }
                Err(err) => {
                    if err.code().is_ok() {
                        Ok(false)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }

    pub struct ConnectedCloudRoot {
        root_id: uuid::Uuid,
        sync_root_path: std::path::PathBuf,
        connection_key: Option<windows::Win32::Storage::CloudFilters::CF_CONNECTION_KEY>,
        backing: NativeConnectionBacking<ConnectedCloudRootBacking>,
        _watchers: Vec<RecommendedWatcher>,
        background_tasks: Vec<tokio::task::JoinHandle<()>>,
        disconnect_attempt: OffThreadDisconnectAttempt,
        drop_fallback_attempted: bool,
    }

    #[derive(Clone)]
    pub struct CloudRootShutdownBarrier {
        context: Arc<CallbackContext>,
    }

    impl CloudRootShutdownBarrier {
        pub fn compatibility_status(&self) -> Option<super::VaultCompatibilityStatus> {
            self.context.bridge.compatibility_status()
        }

        pub async fn set_legacy_compatibility(
            &self,
            enabled: bool,
        ) -> Result<super::VaultCompatibilityStatus> {
            let _operation = self.context.operation_lock.lock().await;
            self.context.startup_activity.ensure_running()?;
            let status = self.context.bridge.set_legacy_compatibility(enabled)?;
            if enabled {
                let mut journal = self.context.read_journal()?;
                for record in &mut journal.records {
                    if record.error_code == Some(hybridcipher_provider_core::ProviderFileErrorCode::LegacyConsentRequired) || record
                        .last_error
                        .as_deref()
                        .is_some_and(|e| e.contains("legacy") || e.contains("older file"))
                    {
                        record.state = super::PendingOperationState::Ready;
                    }
                }
                self.context.write_journal(&journal)?;
            }
            Ok(status)
        }

        pub async fn resolve_pending(
            &self,
            id: Uuid,
            action: super::PendingOperationResolution,
        ) -> Result<()> {
            let _operation = self.context.operation_lock.lock().await;
            self.context.startup_activity.ensure_running()?;
            self.context.resolve_pending_locked(id, action).await
        }

        pub async fn begin(&self) -> Result<()> {
            begin_provider_shutdown_barrier(
                &self.context.startup_activity,
                &self.context.operation_lock,
            )
            .await;
            Ok(())
        }

        pub fn resume(&self) {
            self.context.startup_activity.mark_running();
        }
    }

    struct ConnectedCloudRootBacking {
        // Keep the registration array alive for the full native connection lifetime.
        _callback_table: Vec<CF_CALLBACK_REGISTRATION>,
        context: Arc<CallbackContext>,
    }

    impl ConnectedCloudRoot {
        pub fn root_id(&self) -> uuid::Uuid {
            self.root_id
        }

        pub fn sync_root_path(&self) -> &Path {
            &self.sync_root_path
        }

        pub fn shutdown_barrier(&self) -> CloudRootShutdownBarrier {
            CloudRootShutdownBarrier {
                context: self.backing.as_ref().context.clone(),
            }
        }

        pub async fn disconnect(&mut self) -> Result<()> {
            let Some(connection_key) = self.connection_key else {
                return Ok(());
            };
            // Drain work that already passed ensure_running before disconnecting.
            // Merely setting begin_shutdown leaves close/writeback callbacks alive
            // after native disconnect, still holding the exclusive writer lease.
            let context = &self.backing.as_ref().context;
            tokio::time::timeout(
                Duration::from_secs(30),
                begin_provider_shutdown_barrier(&context.startup_activity, &context.operation_lock),
            )
            .await
            .map_err(|_| {
                CloudProviderError::Callback(
                    "active provider work did not drain before disconnect; connection retained"
                        .into(),
                )
            })?;
            self._watchers.clear();
            drain_provider_background_tasks(&mut self.background_tasks, Duration::from_secs(2))
                .await?;
            let disconnect_result = self
                .disconnect_attempt
                .run(move || unsafe {
                    let _ =
                        CfUpdateSyncProviderStatus(connection_key, CF_PROVIDER_STATUS_TERMINATED);
                    CfDisconnectSyncRoot(connection_key).map_err(|error| error.to_string())
                })
                .await;
            if let Err(error) = disconnect_result {
                return Err(CloudProviderError::Callback(format!(
                    "Cloud Files native disconnect failed: {error}"
                )));
            }
            self.connection_key = None;
            self.backing.release_after_confirmed_disconnect();
            Ok(())
        }

        pub fn disconnect_best_effort_on_drop(&mut self) -> Result<()> {
            self.drop_fallback_attempted = true;
            if self.connection_key.is_none() {
                return Ok(());
            }
            self.backing
                .as_ref()
                .context
                .startup_activity
                .begin_shutdown();
            self._watchers.clear();
            for task in &self.background_tasks {
                task.abort();
            }
            // Drop cannot synchronously wait for Cloud Files. The backing's
            // default-retain policy keeps callback pointers alive whether an
            // off-thread attempt is still running or no attempt was started.
            if self.disconnect_attempt.has_in_flight() {
                return Err(CloudProviderError::Callback(
                    "native disconnect remains in flight during drop".into(),
                ));
            }
            Err(CloudProviderError::Callback(
                "native disconnect was not attempted from nonblocking drop".into(),
            ))
        }
    }

    impl Drop for ConnectedCloudRoot {
        fn drop(&mut self) {
            if !self.drop_fallback_attempted {
                if let Err(error) = self.disconnect_best_effort_on_drop() {
                    tracing::error!(
                        root_id = %self.root_id,
                        "Cloud Files connection could not be proven disconnected; retaining native callback backing: {error}"
                    );
                }
            } else if self.connection_key.is_some() {
                tracing::error!(
                    root_id = %self.root_id,
                    "Cloud Files connection remains unconfirmed during drop; retaining native callback backing"
                );
            }
        }
    }

    include!("pending_native.rs");
    struct CallbackContext {
        registration: CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
        runtime_paths: CloudRuntimePaths,
        runtime: tokio::runtime::Handle,
        inventory_by_object_id: Mutex<HashMap<String, ProviderEntry>>,
        state_store: CloudStateStore,
        operation_lock: AsyncMutex<()>,
        writer_lease: Arc<RootWriterLease>,
        health: RootHealthTelemetry,
        health_generation: u64,
        hydration_cancellations: HydrationCancellationRegistry,
        hydration_worker: HydrationWorkerGate,
        startup_activity: StartupRecoveryActivity,
        suppressed_paths: Mutex<std::collections::HashSet<String>>,
    }

    struct IngestionStateGuard<'a> {
        store: &'a CloudStateStore,
    }

    impl<'a> IngestionStateGuard<'a> {
        fn begin(store: &'a CloudStateStore) -> Result<Self> {
            store.transaction(|state| {
                state.ingestion_in_progress = state.ingestion_in_progress.saturating_add(1);
                Ok(())
            })?;
            Ok(Self { store })
        }
    }

    impl Drop for IngestionStateGuard<'_> {
        fn drop(&mut self) {
            if let Err(err) = self.store.transaction(|state| {
                state.ingestion_in_progress = state.ingestion_in_progress.saturating_sub(1);
                Ok(())
            }) {
                tracing::error!("Failed to clear Cloud Files ingestion state: {err}");
            }
        }
    }

    struct ReconciliationStateGuard<'a> {
        store: &'a CloudStateStore,
        active: bool,
    }

    impl<'a> ReconciliationStateGuard<'a> {
        fn begin(store: &'a CloudStateStore) -> Result<Self> {
            store.transaction(|state| {
                state.reconciliation_in_progress = true;
                Ok(())
            })?;
            Ok(Self {
                store,
                active: true,
            })
        }

        fn finish(&mut self) -> Result<()> {
            self.store.transaction(|state| {
                state.reconciliation_in_progress = false;
                Ok(())
            })?;
            self.active = false;
            Ok(())
        }
    }

    impl Drop for ReconciliationStateGuard<'_> {
        fn drop(&mut self) {
            if self.active {
                if let Err(err) = self.store.transaction(|state| {
                    state.reconciliation_in_progress = false;
                    Ok(())
                }) {
                    tracing::error!("Failed to clear Cloud Files reconciliation state: {err}");
                }
            }
        }
    }

    impl CallbackContext {
        fn new(
            registration: CloudRootRegistration,
            bridge: Arc<dyn ProviderBridge>,
            entries: Vec<CloudPlaceholderEntry>,
            runtime_paths: CloudRuntimePaths,
            writer_lease: Arc<RootWriterLease>,
            health: RootHealthTelemetry,
            health_generation: u64,
            runtime: tokio::runtime::Handle,
        ) -> Self {
            let inventory_by_object_id = entries
                .into_iter()
                .map(|placeholder| (placeholder.identity.object_id, placeholder.entry))
                .collect();
            let state_store =
                CloudStateStore::new(runtime_paths.state_path.clone(), registration.root_id);
            Self {
                registration,
                bridge,
                runtime_paths,
                runtime,
                inventory_by_object_id: Mutex::new(inventory_by_object_id),
                state_store,
                operation_lock: AsyncMutex::new(()),
                writer_lease,
                health,
                health_generation,
                hydration_cancellations: HydrationCancellationRegistry::default(),
                hydration_worker: HydrationWorkerGate::default(),
                startup_activity: StartupRecoveryActivity::default(),
                suppressed_paths: Mutex::new(std::collections::HashSet::new()),
            }
        }

        fn begin_health_observation(
            &self,
            kind: CloudCallbackKind,
            deadline_after: Duration,
        ) -> Result<CallbackHealthObservation> {
            let started_at = Utc::now();
            let deadline_at = started_at
                + chrono::Duration::from_std(deadline_after).unwrap_or(chrono::Duration::MAX);
            self.health
                .begin_callback(self.health_generation, kind, started_at, deadline_at)
        }

        fn entry_for_identity(&self, identity: &CloudObjectIdentityV2) -> Result<ProviderEntry> {
            let inventory = self.inventory_by_object_id.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory.get(&identity.object_id).cloned().ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "no provider inventory entry for {}",
                    identity.object_id
                ))
            })
        }

        fn upsert_committed_entry(&self, entry: ProviderEntry) -> Result<CloudObjectIdentityV2> {
            let identity = self
                .state_store
                .transaction(|state| state.upsert_committed_inventory_entry(&entry))?;
            let mut inventory = self.inventory_by_object_id.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory.insert(identity.object_id.clone(), entry);
            Ok(identity)
        }

        fn remove_identity(&self, identity: &CloudObjectIdentityV2) -> Result<()> {
            let mut inventory = self.inventory_by_object_id.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory.remove(&identity.object_id);
            self.state_store.transaction(|state| {
                state.items.remove(&identity.object_id);
                Ok(())
            })?;
            Ok(())
        }

        fn remove_cache_for_identity(&self, identity: &CloudObjectIdentityV2) {
            let prefix = format!(
                "{}-",
                identity.object_id.replace(
                    |c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_',
                    "_"
                )
            );
            if let Ok(entries) = fs::read_dir(&self.runtime_paths.cache_dir) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().starts_with(&prefix) {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }

        unsafe fn resolve_callback_identity(
            &self,
            info: &CF_CALLBACK_INFO,
        ) -> Result<CloudObjectIdentityV2> {
            let bytes = identity_bytes_from_callback(info)?;
            if let Ok(identity) = CloudObjectIdentityV2::from_bytes(bytes) {
                if identity.root_id != self.registration.root_id {
                    return Err(CloudProviderError::Callback(
                        "callback identity belongs to another root".into(),
                    ));
                }
                return Ok(identity);
            }

            let legacy = FileIdentityV1::from_bytes(bytes)?;
            let state = self.state_store.load()?;
            let directory_id = if legacy.kind == ProviderEntryKind::Directory {
                state.directory_ids.get(&legacy.relative_path).copied()
            } else {
                None
            };
            CloudObjectIdentityV2::from_legacy(&legacy, directory_id)
        }

        fn expected_version_for(
            &self,
            identity: &CloudObjectIdentityV2,
        ) -> Result<ExpectedProviderVersion> {
            let state = self.state_store.load()?;
            Ok(state
                .items
                .get(&identity.object_id)
                .and_then(|item| item.content_version.clone())
                .map(ExpectedProviderVersion::Exact)
                .unwrap_or(ExpectedProviderVersion::Unchecked))
        }

        fn record_conflict(
            &self,
            identity: &CloudObjectIdentityV2,
            relative_path: &str,
            local_path: Option<PathBuf>,
            expected: Option<ProviderContentVersion>,
            actual: Option<ProviderContentVersion>,
        ) -> Result<()> {
            self.state_store.transaction(|state| {
                state.conflicts.push(super::CloudConflictRecord {
                    id: Uuid::new_v4(),
                    object_id: identity.object_id.clone(),
                    relative_path: relative_path.to_string(),
                    expected_version: expected,
                    actual_version: actual,
                    local_plaintext_path: local_path,
                    created_at: Utc::now(),
                });
                if let Some(item) = state.items.get_mut(&identity.object_id) {
                    item.dirty = true;
                }
                Ok(())
            })
        }

        fn read_journal(&self) -> Result<CloudMutationJournal> {
            super::recover_mutation_journal_for_writer(
                &self.runtime_paths.journal_path,
                self.registration.root_id,
            )
        }

        fn write_journal(&self, journal: &CloudMutationJournal) -> Result<()> {
            super::write_mutation_journal(&self.runtime_paths.journal_path, journal)?;
            self.write_runtime_status(None)
        }

        fn write_runtime_status(&self, last_error: Option<String>) -> Result<()> {
            let journal = self.read_journal()?;
            let mut status = CloudProviderHost::status_from_journal(
                self.registration.root_id,
                &journal,
                last_error,
            );
            let state = self.state_store.load()?;
            CloudProviderHost::apply_persistent_safety(&mut status, &state);
            super::write_json_file_pretty(&self.runtime_paths.status_path, &status)
        }

        fn mark_startup_recovery_failed(&self, error: &CloudProviderError) -> Result<()> {
            self.state_store.require_startup_recovery()?;
            self.write_runtime_status(Some(error.to_string()))
        }

        fn add_pending_mutation(&self, mut record: CloudMutationRecord) -> Result<Uuid> {
            let mut journal = self.read_journal()?;
            if record.kind == CloudMutationKind::Rename {
                let previous_len = journal.records.len();
                if let Some(id) =
                    super::coalesce_matching_pending_renames(&mut journal.records, &record)
                {
                    if journal.records.len() != previous_len {
                        journal.updated_at = Utc::now();
                        self.write_journal(&journal)?;
                        self.write_runtime_status(None)?;
                    }
                    return Ok(id);
                }
            }
            record.updated_at = Utc::now();
            journal.next_sequence = journal.next_sequence.saturating_add(1);
            record.sequence = journal.next_sequence;
            let id = record.id;
            journal.records.push(record);
            journal.updated_at = Utc::now();
            self.write_journal(&journal)?;
            Ok(id)
        }

        fn clear_pending_mutation(&self, id: Uuid) -> Result<()> {
            let mut journal = self.read_journal()?;
            journal.records.retain(|record| record.id != id);
            journal.updated_at = Utc::now();
            self.write_journal(&journal)
        }

        fn mark_pending_mutation_error(&self, id: Uuid, error: &str) -> Result<()> {
            let mut journal = self.read_journal()?;
            for record in &mut journal.records {
                if record.id == id {
                    record.attempts = record.attempts.saturating_add(1);
                    record.last_error = Some(error.to_string());
                    record.updated_at = Utc::now();
                }
            }
            journal.updated_at = Utc::now();
            self.write_journal(&journal)
        }

        async fn reconcile_remote_inventory(&self) -> Result<()> {
            self.startup_activity.ensure_wait_allowed()?;
            let _operation = self.operation_lock.lock().await;
            self.startup_activity.ensure_running()?;
            self.reconcile_remote_inventory_locked().await
        }

        async fn reconcile_remote_inventory_locked(&self) -> Result<()> {
            let mut reconciliation = ReconciliationStateGuard::begin(&self.state_store)?;
            let result = async {
                let entries = self
                    .bridge
                    .inventory(self.registration.root_id, &self.registration.encrypted_root)
                    .await?;
                let current_state = self.state_store.load()?;
                let current_inventory = self
                    .inventory_by_object_id
                    .lock()
                    .map_err(|_| {
                        CloudProviderError::Callback("provider inventory lock poisoned".into())
                    })?
                    .clone();
                let (local_dispositions, mut guards) =
                    self.acquire_reconciliation_guards(&current_state);
                let plan = plan_remote_reconciliation(
                    &self.registration,
                    &current_state,
                    &current_inventory,
                    &entries,
                    &local_dispositions,
                )?;

                apply_reconciliation_placeholders(
                    &self.registration.sync_root_path,
                    &plan.placeholders,
                    &current_state,
                    &plan.placeholder_guard_ids,
                    &guards,
                )?;
                let mut removed_items = plan.removed_items.clone();
                removed_items
                    .sort_by_key(|(_, relative_path)| std::cmp::Reverse(path_depth(relative_path)));
                for (object_id, relative_path) in removed_items {
                    self.remove_local_path_for_remote_delete(
                        &relative_path,
                        guards.remove(&object_id),
                    )?;
                }

                self.state_store
                    .replace_if_generation(current_state.generation, plan.proposed_state)?;
                {
                    let mut inventory = self.inventory_by_object_id.lock().map_err(|_| {
                        CloudProviderError::Callback("provider inventory lock poisoned".into())
                    })?;
                    inventory.clear();
                    for (object_id, entry) in plan.inventory_entries {
                        inventory.insert(object_id, entry);
                    }
                }
                Ok(())
            }
            .await;
            reconciliation.finish()?;
            self.write_runtime_status(result.as_ref().err().map(ToString::to_string))?;
            result
        }

        fn acquire_reconciliation_guards(
            &self,
            state: &super::CloudRootPersistentState,
        ) -> (
            HashMap<String, LocalRefreshDisposition>,
            HashMap<String, CloudFileOplock>,
        ) {
            let mut dispositions = HashMap::new();
            let mut guards = HashMap::new();
            for (object_id, item) in &state.items {
                if item.dirty {
                    dispositions.insert(object_id.clone(), LocalRefreshDisposition::Dirty);
                    continue;
                }
                let path = self
                    .registration
                    .sync_root_path
                    .join(item.relative_path.replace('/', "\\"));
                if !path.exists() {
                    dispositions.insert(object_id.clone(), LocalRefreshDisposition::Missing);
                    continue;
                }
                if item.identity.kind == ProviderEntryKind::Directory {
                    dispositions.insert(object_id.clone(), LocalRefreshDisposition::Safe);
                    continue;
                }
                match CloudFileOplock::acquire_exclusive_for_delete(&path) {
                    Ok(guard) => match guard.is_in_sync() {
                        Ok(true) => {
                            dispositions.insert(object_id.clone(), LocalRefreshDisposition::Safe);
                            guards.insert(object_id.clone(), guard);
                        }
                        Ok(false) => {
                            dispositions.insert(object_id.clone(), LocalRefreshDisposition::Dirty);
                        }
                        Err(err) => {
                            tracing::debug!(
                                "Deferring Cloud Files refresh for {} because sync state could not be read: {}",
                                item.relative_path,
                                err
                            );
                            dispositions.insert(object_id.clone(), LocalRefreshDisposition::Busy);
                        }
                    },
                    Err(err) => {
                        tracing::debug!(
                            "Deferring Cloud Files refresh for busy path {}: {}",
                            item.relative_path,
                            err
                        );
                        dispositions.insert(object_id.clone(), LocalRefreshDisposition::Busy);
                    }
                }
            }
            (dispositions, guards)
        }

        async fn ingest_local_tree(&self) -> Result<()> {
            self.startup_activity.ensure_wait_allowed()?;
            let _operation = self.operation_lock.lock().await;
            self.startup_activity.ensure_running()?;
            self.ingest_local_tree_locked().await
        }

        async fn ingest_local_tree_locked(&self) -> Result<()> {
            self.replay_pending_locked(false).await?;
            let paths = self.collect_local_mutation_paths()?;
            let mut recovery_errors = Vec::new();
            for path in paths {
                let relative_path =
                    relative_path_from_full_path(&self.registration.sync_root_path, &path)
                        .ok_or_else(|| {
                            CloudProviderError::InvalidPath(format!(
                                "local ingestion path escaped sync root: {}",
                                path.display()
                            ))
                        })?;
                if self.is_suppressed(&relative_path)? {
                    continue;
                }
                if self
                    .bridge
                    .is_path_excluded(&self.registration.encrypted_root, Path::new(&relative_path))
                {
                    continue;
                }

                if self.read_journal()?.records.iter().any(|r| {
                    r.kind == CloudMutationKind::Writeback && r.relative_path == relative_path
                }) {
                    continue;
                }
                if let Some(identity) = self.known_local_placeholder_identity(&path)? {
                    match self
                        .ingest_local_placeholder_rename(&path, &relative_path, identity)
                        .await
                    {
                        Ok(true) => continue,
                        Err(error) => return Err(error), // inability to retain durable work is a root failure
                        Ok(false) => (),
                    }
                }

                if let Some(existing) = self
                    .state_store
                    .load()?
                    .items
                    .values()
                    .find(|item| item.relative_path == relative_path)
                    .cloned()
                {
                    if existing.identity.kind == ProviderEntryKind::Directory {
                        convert_local_to_placeholder(&path, &existing.identity)?;
                        continue;
                    }

                    let expected_version =
                        super::existing_file_ingestion_expected_version(&existing)?;
                    let existing_entry = self.entry_for_identity(&existing.identity)?;
                    let ingestion_guard = IngestionStateGuard::begin(&self.state_store)?;
                    let ingestion: Result<ProviderEntry> = async {
                        wait_for_stable_file(&path).await?;
                        let snapshot_path = self
                            .runtime_paths
                            .cache_dir
                            .join(format!(".ingestion-{}.plain", Uuid::new_v4()));
                        snapshot_plain_file_to_path(&path, &snapshot_path)?;
                        let entry = self
                            .bridge
                            .writeback_file_checked(
                                self.registration.root_id,
                                &self.registration.encrypted_root,
                                &relative_path,
                                &snapshot_path,
                                Some(&existing_entry.identity),
                                &expected_version,
                            )
                            .await;
                        let _ = fs::remove_file(&snapshot_path);
                        let entry = entry?;
                        Ok(entry)
                    }
                    .await;
                    match ingestion {
                        Ok(entry) => {
                            self.remove_identity(&existing.identity)?;
                            let committed_entry = entry.clone();
                            let identity = self.upsert_committed_entry(entry)?;
                            if let Err(err) = apply_local_placeholder_commit(
                                &self.registration.sync_root_path,
                                &path,
                                &committed_entry,
                                &identity,
                                None,
                            ) {
                                self.record_conflict(
                                    &identity,
                                    &relative_path,
                                    Some(path.clone()),
                                    match &expected_version {
                                        ExpectedProviderVersion::Exact(version) => {
                                            Some(version.clone())
                                        }
                                        ExpectedProviderVersion::Unchecked
                                        | ExpectedProviderVersion::Absent => None,
                                    },
                                    None,
                                )?;
                                tracing::warn!(
                                    "Cloud Files same-path placeholder conversion failed for {}: {}",
                                    relative_path,
                                    err
                                );
                            }
                        }
                        Err(CloudProviderError::ProviderCore(
                            ProviderCoreError::ContentConflict {
                                expected, actual, ..
                            },
                        )) => {
                            self.record_conflict(
                                &existing.identity,
                                &relative_path,
                                Some(path.clone()),
                                expected,
                                actual,
                            )?;
                        }
                        Err(CloudProviderError::ProviderCore(error))
                            if error.is_path_excluded() =>
                        {
                            tracing::debug!(
                                "Skipping excluded Cloud Files ingestion path {}",
                                relative_path
                            );
                        }
                        Err(err) => {
                            tracing::warn!(
                                "Cloud Files same-path ingestion failed for {}: {}",
                                relative_path,
                                err
                            );
                            recovery_errors.push(format!("{relative_path}: {err}"));
                            self.retain_failed_write(
                                &path,
                                &relative_path,
                                Some(existing_entry.identity.clone()),
                                &expected_version,
                                err,
                            )?;
                        }
                    }
                    drop(ingestion_guard);
                    continue;
                }

                let ingestion_guard = IngestionStateGuard::begin(&self.state_store)?;
                let ingestion: Result<(ProviderEntry, Option<CloudFileOplock>)> = if path.is_dir() {
                    self.bridge
                        .create_directory(
                            self.registration.root_id,
                            &self.registration.encrypted_root,
                            &relative_path,
                        )
                        .await
                        .map(|entry| (entry, None))
                        .map_err(CloudProviderError::from)
                } else {
                    async {
                        wait_for_stable_file(&path).await?;
                        let snapshot_path = self
                            .runtime_paths
                            .cache_dir
                            .join(format!(".ingestion-{}.plain", Uuid::new_v4()));
                        snapshot_plain_file_to_path(&path, &snapshot_path)?;
                        let entry = self
                            .bridge
                            .writeback_file_checked(
                                self.registration.root_id,
                                &self.registration.encrypted_root,
                                &relative_path,
                                &snapshot_path,
                                None,
                                &ExpectedProviderVersion::Absent,
                            )
                            .await;
                        let _ = fs::remove_file(&snapshot_path);
                        let entry = entry?;
                        Ok((entry, None))
                    }
                    .await
                };

                match ingestion {
                    Ok((entry, oplock)) => {
                        let committed_entry = entry.clone();
                        let identity = self.upsert_committed_entry(entry)?;
                        let conversion = apply_local_placeholder_commit(
                            &self.registration.sync_root_path,
                            &path,
                            &committed_entry,
                            &identity,
                            oplock.as_ref(),
                        );
                        if let Err(err) = conversion {
                            self.record_conflict(
                                &identity,
                                &relative_path,
                                Some(path.clone()),
                                None,
                                None,
                            )?;
                            tracing::warn!(
                                "Cloud Files local placeholder conversion failed for {}: {}",
                                relative_path,
                                err
                            );
                        }
                    }
                    Err(CloudProviderError::ProviderCore(ProviderCoreError::ContentConflict {
                        expected,
                        actual,
                        ..
                    })) => {
                        let identity = CloudObjectIdentityV2::new(
                            self.registration.root_id,
                            if path.is_dir() {
                                ProviderEntryKind::Directory
                            } else {
                                ProviderEntryKind::File
                            },
                            Uuid::new_v4().to_string(),
                        );
                        self.record_conflict(
                            &identity,
                            &relative_path,
                            Some(path.clone()),
                            expected,
                            actual,
                        )?;
                    }
                    Err(CloudProviderError::ProviderCore(error)) if error.is_path_excluded() => {
                        tracing::debug!(
                            "Skipping excluded Cloud Files ingestion path {}",
                            relative_path
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Cloud Files local ingestion failed for {}: {}",
                            relative_path,
                            err
                        );
                        recovery_errors.push(format!("{relative_path}: {err}"));
                        if path.is_file() {
                            self.retain_failed_write(
                                &path,
                                &relative_path,
                                None,
                                &ExpectedProviderVersion::Absent,
                                err,
                            )?;
                        } else {
                            return Err(err);
                        }
                    }
                }
                drop(ingestion_guard);
            }
            if recovery_errors.is_empty() {
                self.write_runtime_status(None)
            } else {
                let message = format!(
                    "Cloud Files ingestion recovery failed for {} item(s): {}",
                    recovery_errors.len(),
                    recovery_errors.join("; ")
                );
                self.write_runtime_status(Some(message))
            }
        }

        fn collect_local_mutation_paths(&self) -> Result<Vec<PathBuf>> {
            let state = self.state_store.load()?;
            let sync_root = &self.registration.sync_root_path;
            super::collect_ingestion_candidates(sync_root, &|path, metadata| {
                if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0 {
                    return false;
                }
                let Some(relative_path) = relative_path_from_full_path(sync_root, path) else {
                    return true;
                };
                let guard = match CloudFileOplock::acquire_exclusive(path) {
                    Ok(guard) => guard,
                    Err(err) => {
                        tracing::debug!(
                            "Deferring Cloud Files ingestion scan for {} because placeholder metadata could not be read: {}",
                            path.display(),
                            err
                        );
                        return true;
                    }
                };
                let moved_known_placeholder = guard
                    .identity()
                    .ok()
                    .filter(|identity| identity.root_id == self.registration.root_id)
                    .and_then(|identity| state.items.get(&identity.object_id))
                    .is_some_and(|item| item.relative_path != relative_path);
                if moved_known_placeholder {
                    return false;
                }
                if metadata.is_dir() {
                    return true;
                }
                match guard.is_in_sync() {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(err) => {
                        tracing::debug!(
                            "Deferring Cloud Files ingestion scan for {} because placeholder sync state could not be read: {}",
                            path.display(),
                            err
                        );
                        true
                    }
                }
            })
        }

        fn known_local_placeholder_identity(
            &self,
            path: &Path,
        ) -> Result<Option<CloudObjectIdentityV2>> {
            let metadata = fs::symlink_metadata(path)?;
            if !(metadata.is_file() || metadata.is_dir())
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0
            {
                return Ok(None);
            }
            let guard = match CloudFileOplock::acquire_exclusive(path) {
                Ok(guard) => guard,
                Err(err) => {
                    tracing::debug!(
                        "Could not inspect local placeholder identity for {}: {}",
                        path.display(),
                        err
                    );
                    return Ok(None);
                }
            };
            match guard.identity() {
                Ok(identity) if identity.root_id == self.registration.root_id => Ok(Some(identity)),
                Ok(_) => Ok(None),
                Err(err) => {
                    tracing::debug!(
                        "Could not decode local placeholder identity for {}: {}",
                        path.display(),
                        err
                    );
                    Ok(None)
                }
            }
        }

        async fn ingest_local_placeholder_rename(
            &self,
            path: &Path,
            target_relative_path: &str,
            identity: CloudObjectIdentityV2,
        ) -> Result<bool> {
            let Some(current_item) = self
                .state_store
                .load()?
                .items
                .get(&identity.object_id)
                .cloned()
            else {
                return Ok(false);
            };
            if current_item.relative_path == target_relative_path {
                return Ok(false);
            }

            let existing_entry = self.entry_for_identity(&identity)?;
            let expected_version = self.expected_version_for(&identity)?;
            let mut record = CloudMutationRecord::new(
                CloudMutationKind::Rename,
                self.registration.root_id,
                current_item.relative_path.clone(),
                Some(existing_entry.identity.clone()),
            );
            record.target_relative_path = Some(target_relative_path.to_string());
            if identity.kind == ProviderEntryKind::File {
                record.target_plaintext_path = Some(path.to_owned());
            }
            record.expected_version = match expected_version {
                ExpectedProviderVersion::Exact(version) => Some(version),
                _ => None,
            };
            let mutation_id = self.add_pending_mutation(record)?;
            let record = self
                .read_journal()?
                .records
                .into_iter()
                .find(|r| r.id == mutation_id)
                .ok_or_else(|| CloudProviderError::Callback("Pending rename disappeared".into()))?;
            if super::pending::ready(&record) {
                let result = self.execute_pending_rename(&record, false).await;
                self.finish_pending_attempt(mutation_id, result)?;
            }
            Ok(true)
        }
        fn remove_local_path_for_remote_delete(
            &self,
            relative_path: &str,
            guard: Option<CloudFileOplock>,
        ) -> Result<()> {
            let path = self.registration.sync_root_path.join(relative_path);
            if !path.exists() {
                return Ok(());
            }
            self.suppress(relative_path)?;
            let result = if let Some(guard) = guard {
                guard.delete()
            } else if path.is_dir() {
                fs::remove_dir(&path).map_err(CloudProviderError::from)
            } else {
                fs::remove_file(&path).map_err(CloudProviderError::from)
            };
            self.unsuppress(relative_path)?;
            result?;
            if path.exists() {
                return Err(CloudProviderError::Callback(format!(
                    "Cloud Files path remained after guarded remote deletion: {}",
                    path.display()
                )));
            }
            Ok(())
        }

        fn suppress(&self, relative_path: &str) -> Result<()> {
            self.suppressed_paths
                .lock()
                .map_err(|_| CloudProviderError::Callback("suppression lock poisoned".into()))?
                .insert(normalize_relative_path(relative_path));
            Ok(())
        }

        fn unsuppress(&self, relative_path: &str) -> Result<()> {
            self.suppressed_paths
                .lock()
                .map_err(|_| CloudProviderError::Callback("suppression lock poisoned".into()))?
                .remove(&normalize_relative_path(relative_path));
            Ok(())
        }

        fn is_suppressed(&self, relative_path: &str) -> Result<bool> {
            Ok(self
                .suppressed_paths
                .lock()
                .map_err(|_| CloudProviderError::Callback("suppression lock poisoned".into()))?
                .contains(&normalize_relative_path(relative_path)))
        }
    }

    fn start_background_sync(
        context: Arc<CallbackContext>,
    ) -> Result<(Vec<RecommendedWatcher>, Vec<tokio::task::JoinHandle<()>>)> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<bool>();
        let mut local_watcher = RecommendedWatcher::new(
            {
                let sender = sender.clone();
                move |event: notify::Result<notify::Event>| {
                    if event.is_ok() {
                        let _ = sender.send(true);
                    }
                }
            },
            NotifyConfig::default(),
        )
        .map_err(|err| CloudProviderError::Callback(err.to_string()))?;
        local_watcher
            .watch(
                &context.registration.sync_root_path,
                RecursiveMode::Recursive,
            )
            .map_err(|err| CloudProviderError::Callback(err.to_string()))?;

        let mut remote_watcher = RecommendedWatcher::new(
            {
                let sender = sender.clone();
                move |event: notify::Result<notify::Event>| {
                    if event.is_ok() {
                        let _ = sender.send(false);
                    }
                }
            },
            NotifyConfig::default(),
        )
        .map_err(|err| CloudProviderError::Callback(err.to_string()))?;
        remote_watcher
            .watch(
                &context.registration.encrypted_root,
                RecursiveMode::Recursive,
            )
            .map_err(|err| CloudProviderError::Callback(err.to_string()))?;

        let event_context = context.clone();
        let event_task = tokio::spawn(async move {
            while let Some(mut local) = receiver.recv().await {
                tokio::time::sleep(Duration::from_millis(750)).await;
                while let Ok(next_local) = receiver.try_recv() {
                    local |= next_local;
                }
                let result = if local {
                    event_context.ingest_local_tree().await
                } else {
                    event_context.reconcile_remote_inventory().await
                };
                if let Err(err) = result {
                    tracing::warn!("Cloud Files background synchronization failed: {}", err);
                }
            }
        });

        let periodic_context = context;
        let periodic_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(err) = periodic_context.reconcile_remote_inventory().await {
                    tracing::warn!("Cloud Files periodic reconciliation failed: {}", err);
                }
                if let Err(err) = periodic_context.ingest_local_tree().await {
                    tracing::warn!("Cloud Files periodic local ingestion failed: {}", err);
                }
            }
        });
        Ok((
            vec![local_watcher, remote_watcher],
            vec![event_task, periodic_task],
        ))
    }

    fn apply_local_placeholder_commit(
        sync_root_path: &Path,
        path: &Path,
        entry: &ProviderEntry,
        identity: &CloudObjectIdentityV2,
        oplock: Option<&CloudFileOplock>,
    ) -> Result<()> {
        let is_reparse_point =
            fs::symlink_metadata(path)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
        if !is_reparse_point {
            return match oplock {
                Some(oplock) => oplock.convert_to_placeholder(identity),
                None => convert_local_to_placeholder(path, identity),
            };
        }

        let (_base, relative_name, full_path, display_path) =
            placeholder_location(sync_root_path, entry)?;
        let placeholder = OwnedPlaceholder::new(
            &CloudPlaceholderEntry {
                entry: entry.clone(),
                identity: identity.clone(),
                dirty: true,
            },
            relative_name,
            full_path,
            display_path,
        )?;
        match oplock {
            Some(oplock) => update_existing_placeholder_with_handle(&placeholder, oplock),
            None => update_existing_placeholder(&placeholder),
        }
    }

    async fn wait_for_stable_file(path: &Path) -> Result<()> {
        let started = std::time::Instant::now();
        let mut previous = None;
        while started.elapsed() < Duration::from_secs(30) {
            let metadata = fs::metadata(path)?;
            let current = (metadata.len(), metadata.modified().ok());
            if previous.as_ref() == Some(&current) {
                return Ok(());
            }
            previous = Some(current);
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(CloudProviderError::Callback(format!(
            "local file did not stabilize before ingestion: {}",
            path.display()
        )))
    }

    fn snapshot_plain_file_to_path(source: &Path, destination: &Path) -> Result<()> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        let result = (|| -> Result<()> {
            let before = plain_file_fingerprint(source)?;
            let mut input = File::open(source)?;
            let mut output = File::create(destination)?;
            std::io::copy(&mut input, &mut output)?;
            output.sync_all()?;
            let after = plain_file_fingerprint(source)?;
            if before != after {
                return Err(CloudProviderError::Callback(format!(
                    "local file changed while snapshotting for ingestion: {}",
                    source.display()
                )));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(destination);
        }
        result
    }

    fn plain_file_fingerprint(path: &Path) -> Result<(u64, Option<std::time::SystemTime>)> {
        let metadata = fs::metadata(path)?;
        Ok((metadata.len(), metadata.modified().ok()))
    }

    struct CloudFileOplock(HANDLE);

    struct PlaceholderDataResidency {
        on_disk_data_size: i64,
        modified_data_size: i64,
        in_sync: bool,
    }

    struct FileAllocation {
        allocation_size: i64,
        end_of_file: i64,
    }

    struct ProtectedHandleReference(HANDLE);

    impl Drop for ProtectedHandleReference {
        fn drop(&mut self) {
            unsafe { CfReleaseProtectedHandle(self.0) };
        }
    }

    // Cloud Files oplock handles are kernel handles and can be closed from a
    // different worker thread than the one that acquired them.
    unsafe impl Send for CloudFileOplock {}

    impl CloudFileOplock {
        fn acquire_exclusive(path: &Path) -> Result<Self> {
            Self::open(path, Self::exclusive_write_flags())
        }

        fn acquire_exclusive_for_delete(path: &Path) -> Result<Self> {
            Self::open(path, Self::exclusive_delete_flags())
        }

        fn exclusive_write_flags() -> CF_OPEN_FILE_FLAGS {
            // Local ingestion only snapshots and converts through this handle.
            // Asking for delete access can be denied for ordinary newly-created files.
            CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS
        }

        fn exclusive_delete_flags() -> CF_OPEN_FILE_FLAGS {
            Self::exclusive_write_flags() | CF_OPEN_FILE_FLAG_DELETE_ACCESS
        }

        fn open(path: &Path, flags: CF_OPEN_FILE_FLAGS) -> Result<Self> {
            let path_wide = to_wide(path.as_os_str());
            let handle = unsafe { CfOpenFileWithOplock(PCWSTR(path_wide.as_ptr()), flags)? };
            Ok(Self(handle))
        }

        fn delete(self) -> Result<()> {
            unsafe {
                if !CfReferenceProtectedHandle(self.0) {
                    return Err(CloudProviderError::Callback(
                        "failed to reference protected Cloud Files handle for deletion".into(),
                    ));
                }
                let _reference = ProtectedHandleReference(self.0);
                let win32_handle = CfGetWin32HandleFromProtectedHandle(self.0);
                let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
                SetFileInformationByHandle(
                    win32_handle,
                    FileDispositionInfo,
                    (&disposition as *const FILE_DISPOSITION_INFO).cast(),
                    size_of::<FILE_DISPOSITION_INFO>() as u32,
                )?;
            }
            Ok(())
        }

        fn convert_to_placeholder(&self, identity: &CloudObjectIdentityV2) -> Result<()> {
            use windows::Win32::Storage::CloudFilters::{
                CfConvertToPlaceholder, CF_CONVERT_FLAG_MARK_IN_SYNC,
            };
            let identity = identity.to_bytes()?;
            unsafe {
                CfConvertToPlaceholder(
                    self.0,
                    Some(identity.as_ptr().cast()),
                    identity.len() as u32,
                    CF_CONVERT_FLAG_MARK_IN_SYNC,
                    None,
                    None,
                )?;
            }
            Ok(())
        }

        fn is_in_sync(&self) -> Result<bool> {
            let byte_len = size_of::<CF_PLACEHOLDER_BASIC_INFO>()
                + CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize;
            let mut buffer = vec![0u64; byte_len.div_ceil(size_of::<u64>())];
            unsafe {
                CfGetPlaceholderInfo(
                    self.0,
                    CF_PLACEHOLDER_INFO_BASIC,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * size_of::<u64>()) as u32,
                    None,
                )?;
                let info = &*(buffer.as_ptr().cast::<CF_PLACEHOLDER_BASIC_INFO>());
                Ok(info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC)
            }
        }

        fn identity(&self) -> Result<CloudObjectIdentityV2> {
            let byte_len = size_of::<CF_PLACEHOLDER_BASIC_INFO>()
                + CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize;
            let mut buffer = vec![0u64; byte_len.div_ceil(size_of::<u64>())];
            unsafe {
                CfGetPlaceholderInfo(
                    self.0,
                    CF_PLACEHOLDER_INFO_BASIC,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * size_of::<u64>()) as u32,
                    None,
                )?;
                let info = &*(buffer.as_ptr().cast::<CF_PLACEHOLDER_BASIC_INFO>());
                let identity_length = info.FileIdentityLength as usize;
                let identity_offset = std::mem::offset_of!(CF_PLACEHOLDER_BASIC_INFO, FileIdentity);
                let buffer_length = buffer.len() * size_of::<u64>();
                let max_identity_length = buffer_length.saturating_sub(identity_offset);
                if identity_length == 0 || identity_length > max_identity_length {
                    return Err(CloudProviderError::Callback(format!(
                        "placeholder identity length {} exceeds buffer capacity {}",
                        identity_length, max_identity_length
                    )));
                }
                let identity_bytes =
                    std::slice::from_raw_parts(info.FileIdentity.as_ptr(), identity_length);
                CloudObjectIdentityV2::from_bytes(identity_bytes)
            }
        }

        /// Cloud Files' own account of how much file data a placeholder still
        /// keeps on disk. `CfGetPlaceholderInfo` fails for anything that is not
        /// a placeholder, so a successful call also proves the entry is one.
        fn data_residency(&self) -> Result<PlaceholderDataResidency> {
            let byte_len = size_of::<CF_PLACEHOLDER_STANDARD_INFO>()
                + CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize;
            let mut buffer = vec![0u64; byte_len.div_ceil(size_of::<u64>())];
            unsafe {
                CfGetPlaceholderInfo(
                    self.0,
                    CF_PLACEHOLDER_INFO_STANDARD,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * size_of::<u64>()) as u32,
                    None,
                )?;
                let info = &*(buffer.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>());
                Ok(PlaceholderDataResidency {
                    on_disk_data_size: info.OnDiskDataSize,
                    modified_data_size: info.ModifiedDataSize,
                    in_sync: info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
                })
            }
        }

        fn file_allocation(&self) -> Result<FileAllocation> {
            unsafe {
                if !CfReferenceProtectedHandle(self.0) {
                    return Err(CloudProviderError::Callback(
                        "failed to reference protected Cloud Files handle for allocation check"
                            .into(),
                    ));
                }
                let _reference = ProtectedHandleReference(self.0);
                let win32_handle = CfGetWin32HandleFromProtectedHandle(self.0);
                let mut info = FILE_STANDARD_INFO::default();
                GetFileInformationByHandleEx(
                    win32_handle,
                    FileStandardInfo,
                    (&mut info as *mut FILE_STANDARD_INFO).cast(),
                    size_of::<FILE_STANDARD_INFO>() as u32,
                )?;
                Ok(FileAllocation {
                    allocation_size: info.AllocationSize,
                    end_of_file: info.EndOfFile,
                })
            }
        }

        fn mark_in_sync(&self) -> Result<()> {
            unsafe {
                CfSetInSyncState(
                    self.0,
                    CF_IN_SYNC_STATE_IN_SYNC,
                    CF_SET_IN_SYNC_FLAG_NONE,
                    None,
                )?;
            }
            Ok(())
        }
    }

    impl Drop for CloudFileOplock {
        fn drop(&mut self) {
            unsafe { CfCloseHandle(self.0) };
        }
    }

    fn convert_local_to_placeholder(path: &Path, identity: &CloudObjectIdentityV2) -> Result<()> {
        CloudFileOplock::acquire_exclusive(path)?.convert_to_placeholder(identity)
    }

    fn callback_registrations() -> Vec<CF_CALLBACK_REGISTRATION> {
        vec![
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_VALIDATE_DATA,
                Callback: Some(validate_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
                Callback: Some(cancel_fetch_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
                Callback: Some(fetch_placeholders_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
                Callback: Some(cancel_fetch_placeholders_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION,
                Callback: Some(open_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
                Callback: Some(close_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,
                Callback: Some(dehydrate_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
                Callback: Some(dehydrate_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
                Callback: Some(delete_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION,
                Callback: Some(delete_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ]
    }

    unsafe extern "system" fn fetch_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // Null callback information and missing callback context cannot be
        // attributed to a root. Process aborts can likewise preclude finalization.
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let started_at = Instant::now();
        let deadline = Instant::now() + HYDRATION_CALLBACK_TIMEOUT;
        let context = unsafe { callback_context(info) };
        let observation = context.as_ref().and_then(|context| {
            context
                .begin_health_observation(CloudCallbackKind::FetchData, HYDRATION_CALLBACK_TIMEOUT)
                .ok()
        });
        let completion = if let Some(context) = context.as_ref() {
            unsafe { context.handle_fetch_data(info, callback_parameters, deadline) }
        } else {
            let (requested_offset, requested_length) = if callback_parameters.is_null() {
                (0, 0)
            } else {
                let params = unsafe { (*callback_parameters).Anonymous.FetchData };
                (params.RequiredFileOffset, params.RequiredLength)
            };
            let (completion_offset, completion_length) =
                hydration_completion_range(info.FileSize, requested_offset, requested_length);
            let mut execute_results = Vec::new();
            let execute_error = unsafe {
                execute_transfer_data_recorded(
                    info,
                    STATUS_CLOUD_FILE_UNSUCCESSFUL,
                    &[],
                    completion_offset,
                    completion_length,
                    &mut execute_results,
                )
                .err()
                .map(|error| error.to_string())
            };
            FetchDataCompletion {
                status: STATUS_CLOUD_FILE_UNSUCCESSFUL,
                file_unavailable: false,
                handler_error: Some("callback context is unavailable".to_string()),
                execute_error,
                cancellation_observed: false,
                transferred_bytes: 0,
                requested_offset,
                requested_length,
                execute_results,
            }
        };
        if let Some(err) = &completion.handler_error {
            tracing::warn!("Cloud Files hydration callback failed: {err}");
        }
        if let Some(err) = &completion.execute_error {
            tracing::warn!("Cloud Files hydration completion failed: {err}");
        }
        if completion.cancellation_observed {
            tracing::debug!(
                transferred_bytes = completion.transferred_bytes,
                "Cloud Files hydration cancellation was observed"
            );
        }
        let finished_at = Utc::now();
        if let Some(context) = context.as_ref() {
            let telemetry = CloudHydrationTransferTelemetry {
                requested_offset: completion.requested_offset,
                requested_length: completion.requested_length,
                transferred_bytes: completion.transferred_bytes,
                elapsed_millis: u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX),
                cancellation_observed: completion.cancellation_observed,
                completed_at: finished_at,
                execute_results: completion.execute_results.clone(),
            };
            if let Err(error) = context
                .health
                .record_hydration_transfer(context.health_generation, telemetry)
            {
                tracing::warn!("Could not persist Cloud Files hydration telemetry: {error}");
            }
        }
        if let Some(observation) = observation {
            if completion.file_unavailable && completion.execute_error.is_none() {
                // Windows received a complete file-specific failure. Restarting the
                // root cannot grant consent, repair ciphertext or restore a missing file.
                observation.finish_observed_at(finished_at);
            } else if completion.cancellation_observed
                && completion.handler_error.is_none()
                && completion.execute_error.is_none()
            {
                observation.finish_observed_at(finished_at);
            } else {
                observation.finish_at(
                    actionable_callback_handler_outcome(
                        completion.handler_error.clone(),
                        completion.status.0,
                    ),
                    Some(
                        completion
                            .execute_error
                            .as_ref()
                            .map_or(Ok(()), |error| Err(error.clone())),
                    ),
                    finished_at,
                );
            }
        }
        let _ = unsafe { CfUpdateSyncProviderStatus(info.ConnectionKey, CF_PROVIDER_STATUS_IDLE) };
    }

    unsafe extern "system" fn validate_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let context = unsafe { callback_context(info) };
        let observation = context.as_ref().and_then(|context| {
            context
                .begin_health_observation(CloudCallbackKind::ValidateData, Duration::from_secs(60))
                .ok()
        });
        let result = if callback_parameters.is_null() {
            Err(CloudProviderError::Callback(
                "validate-data callback parameters are unavailable".into(),
            ))
        } else {
            let params = unsafe { (*callback_parameters).Anonymous.ValidateData };
            Ok((
                STATUS_SUCCESS,
                params.RequiredFileOffset,
                params.RequiredLength,
            ))
        };
        let mut execute_error = None;
        let mut selected_status = STATUS_CLOUD_FILE_INVALID_REQUEST.0;
        let handler_error = complete_callback_once(
            result,
            (STATUS_CLOUD_FILE_INVALID_REQUEST, 0, 0),
            |(status, offset, length)| {
                selected_status = status.0;
                execute_error = unsafe { execute_ack_data(info, status, offset, length).err() };
            },
        );
        if let Some(err) = &handler_error {
            tracing::warn!("Cloud Files validate-data callback failed: {err}");
        }
        if let Some(err) = &execute_error {
            tracing::warn!("Cloud Files validate-data completion failed: {err}");
        }
        if let Some(observation) = observation {
            observation.finish_at(
                actionable_callback_handler_outcome(
                    handler_error.as_ref().map(ToString::to_string),
                    selected_status,
                ),
                Some(
                    execute_error
                        .as_ref()
                        .map_or(Ok(()), |error| Err(error.to_string())),
                ),
                Utc::now(),
            );
        }
    }

    unsafe extern "system" fn fetch_placeholders_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let context = unsafe { callback_context(info) };
        let observation = context.as_ref().and_then(|context| {
            context
                .begin_health_observation(
                    CloudCallbackKind::FetchPlaceholders,
                    Duration::from_secs(60),
                )
                .ok()
        });
        // The provider reconciles the complete remote namespace before serving the mount, so
        // there are no missing children to transfer. Mark this legacy directory placeholder as
        // fully populated while completing the request; otherwise Windows will ask again on each
        // nested path lookup and can leave Explorer's create/rename operation unresolved.
        let execute_error = unsafe { execute_transfer_placeholders(info, STATUS_SUCCESS, 0) }.err();
        if let Some(err) = &execute_error {
            tracing::warn!("Cloud Files placeholder completion failed: {err}");
        }
        if let Some(observation) = observation {
            observation.finish_at(
                actionable_callback_handler_outcome(None, STATUS_SUCCESS.0),
                Some(
                    execute_error
                        .as_ref()
                        .map_or(Ok(()), |error| Err(error.to_string())),
                ),
                Utc::now(),
            );
        }
    }

    unsafe extern "system" fn close_completion_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        notification_guard(
            callback_info,
            CloudCallbackKind::Close,
            |context, info| unsafe { context.handle_close_completion(info) },
        );
    }

    unsafe extern "system" fn open_completion_callback(
        _callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // Completion notifications are advisory; the pre-operation callbacks
        // carry the mutations that need provider-side acknowledgement.
    }

    unsafe extern "system" fn dehydrate_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let context = unsafe { callback_context(info) };
        let observation = context.as_ref().and_then(|context| {
            context
                .begin_health_observation(CloudCallbackKind::Dehydrate, Duration::from_secs(60))
                .ok()
        });
        let execute_error = unsafe { execute_ack_dehydrate(info, STATUS_SUCCESS) }.err();
        if let Some(err) = &execute_error {
            tracing::warn!("Cloud Files dehydrate completion failed: {err}");
        }
        if let Some(observation) = observation {
            observation.finish_at(
                actionable_callback_handler_outcome(None, STATUS_SUCCESS.0),
                Some(
                    execute_error
                        .as_ref()
                        .map_or(Ok(()), |error| Err(error.to_string())),
                ),
                Utc::now(),
            );
        }
    }

    unsafe extern "system" fn dehydrate_completion_callback(
        _callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // The pre-dehydrate callback ACKs the operation synchronously.
    }

    unsafe extern "system" fn delete_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let context = unsafe { callback_context(info) };
        let observation = context.as_ref().and_then(|context| {
            context
                .begin_health_observation(CloudCallbackKind::Delete, Duration::from_secs(60))
                .ok()
        });
        let result = unsafe {
            context
                .as_ref()
                .ok_or_else(|| {
                    CloudProviderError::Callback("callback context is unavailable".into())
                })
                .and_then(|context| context.handle_delete(info))
        };
        let mut execute_error = None;
        let mut selected_status = STATUS_CLOUD_FILE_UNSUCCESSFUL.0;
        let handler_error =
            complete_callback_once(result, STATUS_CLOUD_FILE_UNSUCCESSFUL, |status| {
                selected_status = status.0;
                execute_error = unsafe { execute_ack_delete(info, status).err() }
            });
        if let Some(err) = &handler_error {
            tracing::warn!("Cloud Files delete callback failed: {err}");
        }
        if let Some(err) = &execute_error {
            tracing::warn!("Cloud Files delete completion failed: {err}");
        }
        if let Some(observation) = observation {
            observation.finish_at(
                actionable_callback_handler_outcome(
                    handler_error.as_ref().map(ToString::to_string),
                    selected_status,
                ),
                Some(
                    execute_error
                        .as_ref()
                        .map_or(Ok(()), |error| Err(error.to_string())),
                ),
                Utc::now(),
            );
        }
    }

    unsafe extern "system" fn delete_completion_callback(
        _callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        // The encrypted delete is committed before ACK_DELETE succeeds.
    }

    unsafe extern "system" fn cancel_fetch_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let Some(context) = (unsafe { callback_context(info) }) else {
            return;
        };
        let observation = context
            .begin_health_observation(CloudCallbackKind::CancelFetchData, Duration::from_secs(60))
            .ok();
        let handler = if callback_parameters.is_null() {
            Err("cancel-fetch-data callback parameters are unavailable".to_string())
        } else {
            let cancel = unsafe { (*callback_parameters).Anonymous.Cancel.Anonymous.FetchData };
            let cancelled = context.hydration_cancellations.cancel_intersecting(
                info.TransferKey,
                cancel.FileOffset,
                cancel.Length,
            );
            tracing::debug!(
                transfer_key = info.TransferKey,
                offset = cancel.FileOffset,
                length = cancel.Length,
                cancelled,
                "processed Cloud Files fetch-data cancellation"
            );
            Ok(())
        };
        if let Some(observation) = observation {
            observation.finish_at(handler, None, Utc::now());
        }
    }

    unsafe extern "system" fn cancel_fetch_placeholders_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        if callback_info.is_null() {
            return;
        }
        let info = unsafe { &*callback_info };
        let Some(context) = (unsafe { callback_context(info) }) else {
            return;
        };
        let observation = context
            .begin_health_observation(
                CloudCallbackKind::CancelFetchPlaceholders,
                Duration::from_secs(60),
            )
            .ok();
        // Placeholder enumeration completes synchronously and has no outstanding state to cancel.
        if let Some(observation) = observation {
            observation.finish_at(Ok(()), None, Utc::now());
        }
    }

    fn notification_guard(
        callback_info: *const CF_CALLBACK_INFO,
        kind: CloudCallbackKind,
        f: impl FnOnce(&CallbackContext, &CF_CALLBACK_INFO) -> Result<()>,
    ) {
        unsafe {
            if callback_info.is_null() {
                return;
            }
            let info = &*callback_info;
            let Some(context) = callback_context(info) else {
                return;
            };
            let observation = context
                .begin_health_observation(kind, Duration::from_secs(60))
                .ok();
            let result = f(&context, info);
            if let Err(err) = &result {
                tracing::warn!("Windows Cloud Files callback failed: {}", err);
            }
            if let Some(observation) = observation {
                observation.finish_at(result.map_err(|error| error.to_string()), None, Utc::now());
            }
        }
    }

    impl CallbackContext {
        unsafe fn handle_fetch_data(
            &self,
            info: &CF_CALLBACK_INFO,
            callback_parameters: *const CF_CALLBACK_PARAMETERS,
            deadline: Instant,
        ) -> FetchDataCompletion {
            let (requested_offset, requested_length) = if callback_parameters.is_null() {
                (0, 0)
            } else {
                let params = (*callback_parameters).Anonymous.FetchData;
                (params.RequiredFileOffset, params.RequiredLength)
            };
            let (completion_offset, completion_length) =
                hydration_completion_range(info.FileSize, requested_offset, requested_length);
            let mut outstanding =
                HydrationOutstandingRanges::new(completion_offset, completion_length);
            let mut stats = HydrationTransferStats::default();
            let result = if callback_parameters.is_null() {
                Err(CloudProviderError::Callback(
                    "fetch-data callback parameters are unavailable".into(),
                ))
            } else {
                self.hydrate_and_transfer(
                    info,
                    (*callback_parameters).Anonymous.FetchData,
                    deadline,
                    &mut outstanding,
                    &mut stats,
                )
            };

            match result {
                Ok(()) => FetchDataCompletion {
                    file_unavailable: false,
                    status: if stats.cancellation_observed && stats.transferred_bytes == 0 {
                        STATUS_CLOUD_FILE_REQUEST_ABORTED
                    } else {
                        STATUS_SUCCESS
                    },
                    handler_error: None,
                    execute_error: None,
                    cancellation_observed: stats.cancellation_observed,
                    transferred_bytes: stats.transferred_bytes,
                    requested_offset,
                    requested_length,
                    execute_results: stats.execute_results,
                },
                Err(error) => {
                    let status = hydration_error_status(&error);
                    let mut execute_error = None;
                    for (range_start, range_end) in outstanding.ranges() {
                        let range_length = range_end - range_start;
                        if range_length <= 0 {
                            continue;
                        }
                        if let Err(completion_error) = unsafe {
                            execute_transfer_data_recorded(
                                info,
                                status,
                                &[],
                                range_start,
                                range_length,
                                &mut stats.execute_results,
                            )
                        } {
                            execute_error.get_or_insert_with(|| completion_error.to_string());
                        } else {
                            outstanding.complete(range_start, range_length);
                        }
                    }
                    let cancelled_error = matches!(error, CloudProviderError::HydrationCancelled);
                    FetchDataCompletion {
                        status,
                        file_unavailable: matches!(&error, CloudProviderError::ProviderCore(error) if error.is_file_unavailable())
                            || matches!(&error, CloudProviderError::Io(error) if error.kind() == std::io::ErrorKind::NotFound),
                        handler_error: (!cancelled_error)
                            .then(|| hydration_error_telemetry(&error)),
                        execute_error,
                        cancellation_observed: stats.cancellation_observed || cancelled_error,
                        transferred_bytes: stats.transferred_bytes,
                        requested_offset,
                        requested_length,
                        execute_results: stats.execute_results,
                    }
                }
            }
        }

        unsafe fn hydrate_and_transfer(
            &self,
            info: &CF_CALLBACK_INFO,
            params: windows::Win32::Storage::CloudFilters::CF_CALLBACK_PARAMETERS_0_1,
            deadline: Instant,
            outstanding: &mut HydrationOutstandingRanges,
            stats: &mut HydrationTransferStats,
        ) -> Result<()> {
            self.startup_activity.ensure_wait_allowed()?;
            let cancellation = self.hydration_cancellations.register(
                info.TransferKey,
                params.RequiredFileOffset,
                params.RequiredLength,
            );
            let identity = self.resolve_callback_identity(info)?;
            if identity.kind != ProviderEntryKind::File {
                return Err(CloudProviderError::Callback(
                    "Cloud Files hydration target is not a file".into(),
                ));
            }
            let entry = self.entry_for_identity(&identity)?;
            let request = validate_hydration_request(
                entry.logical_size,
                params.RequiredFileOffset,
                params.RequiredLength,
            )?;
            let tokio_deadline = tokio::time::Instant::from_std(deadline);
            self.runtime.block_on(async {
                tokio::select! {
                    _ = cancellation.cancelled() => Err(CloudProviderError::HydrationCancelled),
                    ready = tokio::time::timeout_at(
                        tokio_deadline,
                        self.startup_activity.wait_until_running(),
                    ) => ready.map_err(|_| CloudProviderError::HydrationTimedOut)?,
                }
            })?;
            let _worker_permit = self.runtime.block_on(async {
                tokio::select! {
                    _ = cancellation.cancelled() => Err(CloudProviderError::HydrationCancelled),
                    permit = tokio::time::timeout_at(tokio_deadline, self.hydration_worker.begin()) => {
                        permit.map_err(|_| CloudProviderError::HydrationTimedOut)?
                    }
                }
            })?;
            self.startup_activity.ensure_running()?;
            ensure_hydration_active(&cancellation, deadline)?;
            unsafe {
                CfUpdateSyncProviderStatus(info.ConnectionKey, CF_PROVIDER_STATUS_POPULATE_CONTENT)?
            };

            let transfer_ranges = hydration_transfer_ranges(request)?;
            for (index, transfer) in transfer_ranges.iter().enumerate() {
                ensure_hydration_active(&cancellation, deadline)?;
                let decrypt = self.runtime.block_on(async {
                    tokio::select! {
                        _ = cancellation.cancelled() => Err(CloudProviderError::HydrationCancelled),
                        result = tokio::time::timeout_at(
                            tokio_deadline,
                            self.bridge.hydrate_file_range(&entry, transfer.offset, transfer.length),
                        ) => {
                            result
                                .map_err(|_| CloudProviderError::HydrationTimedOut)?
                                .map_err(CloudProviderError::from)
                        }
                    }
                });
                match decrypt {
                    Ok(bytes) => unsafe {
                        transfer_decrypted_range(
                            info,
                            transfer.offset as i64,
                            &bytes,
                            &cancellation,
                            outstanding,
                            stats,
                        )?;
                    },
                    Err(CloudProviderError::ProviderCore(error))
                        if index == 0 && error.is_range_unsupported() =>
                    {
                        return unsafe {
                            self.hydrate_full_file_fallback(
                                info,
                                &entry,
                                &cancellation,
                                deadline,
                                outstanding,
                                stats,
                            )
                        };
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }

        unsafe fn hydrate_full_file_fallback(
            &self,
            info: &CF_CALLBACK_INFO,
            entry: &ProviderEntry,
            cancellation: &HydrationCancellationToken,
            deadline: Instant,
            outstanding: &mut HydrationOutstandingRanges,
            stats: &mut HydrationTransferStats,
        ) -> Result<()> {
            fs::create_dir_all(&self.runtime_paths.cache_dir)?;
            restrict_hydration_temp_directory(&self.runtime_paths.cache_dir)?;
            let temporary_path = self
                .runtime_paths
                .cache_dir
                .join(format!(".hydrate-{}.plain.tmp", Uuid::new_v4()));
            let temporary =
                HydrationTemporaryFile::new(temporary_path.clone(), self.writer_lease.clone());
            let fallback = catch_unwind(AssertUnwindSafe(|| -> Result<()> {
                let tokio_deadline = tokio::time::Instant::from_std(deadline);
                self.runtime.block_on(async {
                    tokio::select! {
                        _ = cancellation.cancelled() => Err(CloudProviderError::HydrationCancelled),
                        result = tokio::time::timeout_at(
                            tokio_deadline,
                            self.bridge.hydrate_file_to_path(entry, &temporary_path),
                        ) => {
                            result
                                .map_err(|_| CloudProviderError::HydrationTimedOut)?
                                .map_err(CloudProviderError::from)
                        }
                    }
                })?;
                ensure_hydration_active(cancellation, deadline)?;
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(temporary.path())?
                    .sync_all()?;
                let actual_length = fs::metadata(temporary.path())?.len();
                if actual_length != entry.logical_size {
                    return Err(CloudProviderError::Callback(format!(
                        "temporary hydration length mismatch (expected {}, found {actual_length})",
                        entry.logical_size
                    )));
                }

                let full_length = usize::try_from(entry.logical_size).map_err(|_| {
                    CloudProviderError::Callback(
                        "legacy hydration file is too large for this process".into(),
                    )
                })?;
                let mut file = File::open(temporary.path())?;
                for transfer in hydration_transfer_ranges(super::HydrationRequest {
                    offset: 0,
                    length: full_length,
                })? {
                    ensure_hydration_active(cancellation, deadline)?;
                    let mut bytes = Zeroizing::new(vec![0u8; transfer.length]);
                    file.seek(SeekFrom::Start(transfer.offset))?;
                    file.read_exact(&mut bytes)?;
                    unsafe {
                        transfer_decrypted_range(
                            info,
                            transfer.offset as i64,
                            &bytes,
                            cancellation,
                            outstanding,
                            stats,
                        )?;
                    }
                }
                Ok(())
            }));
            let result = match fallback {
                Ok(result) => result,
                Err(_) => Err(CloudProviderError::Callback(
                    "legacy hydration fallback panicked; temporary plaintext was removed".into(),
                )),
            };
            drop(temporary);
            result
        }

        unsafe fn handle_close_completion(&self, info: &CF_CALLBACK_INFO) -> Result<()> {
            self.startup_activity.ensure_wait_allowed()?;
            let _operation = self.runtime.block_on(self.operation_lock.lock());
            self.startup_activity.ensure_running()?;
            let identity = self.resolve_callback_identity(info)?;
            if identity.kind != ProviderEntryKind::File {
                return Ok(());
            }
            let Some(full_path) = normalized_path_from_callback(info) else {
                return Ok(());
            };
            if !full_path.is_file() {
                return Ok(());
            }
            let placeholder = CloudFileOplock::acquire_exclusive(&full_path)?;
            if placeholder.is_in_sync()? {
                // Read-only opens also generate close notifications. TRACK_ALL
                // leaves unchanged content in sync, so it must not be written back.
                return Ok(());
            }
            drop(placeholder);
            let relative_path =
                relative_path_from_full_path(&self.registration.sync_root_path, &full_path)
                    .unwrap_or_else(|| {
                        self.entry_for_identity(&identity)
                            .map(|entry| entry.relative_path)
                            .unwrap_or_default()
                    });
            let existing_entry = self.entry_for_identity(&identity)?;
            if normalize_relative_path(&existing_entry.relative_path)
                != normalize_relative_path(&relative_path)
                && self.runtime.block_on(self.ingest_local_placeholder_rename(
                    &full_path,
                    &relative_path,
                    identity.clone(),
                ))?
            {
                // A close notification may race ahead of the filesystem watcher after a
                // local move. Treat the stable-object path change as the rename itself;
                // attempting ordinary writeback with the old path-bound V1 identity is
                // invalid and would strand a pending mutation.
                return Ok(());
            }
            let existing_identity = existing_entry.identity.clone();
            let expected_version = self.expected_version_for(&identity)?;
            self.state_store.transaction(|state| {
                if let Some(item) = state.items.get_mut(&identity.object_id) {
                    item.dirty = true;
                }
                Ok(())
            })?;
            let mut record = CloudMutationRecord::new(
                CloudMutationKind::Writeback,
                self.registration.root_id,
                relative_path.clone(),
                Some(existing_identity.clone()),
            );
            record.plaintext_path = Some(full_path.clone());
            record.expected_version = match &expected_version {
                ExpectedProviderVersion::Exact(version) => Some(version.clone()),
                ExpectedProviderVersion::Unchecked | ExpectedProviderVersion::Absent => None,
            };
            let mutation_id = self.add_pending_mutation(record)?;
            let writeback_result = self.runtime.block_on(async {
                self.bridge
                    .writeback_file_checked(
                        self.registration.root_id,
                        &self.registration.encrypted_root,
                        &relative_path,
                        &full_path,
                        Some(&existing_identity),
                        &expected_version,
                    )
                    .await
            });
            let writeback = match writeback_result {
                Ok(writeback) => writeback,
                Err(err @ ProviderCoreError::ContentConflict { .. }) => {
                    if let ProviderCoreError::ContentConflict {
                        expected, actual, ..
                    } = &err
                    {
                        self.record_conflict(
                            &identity,
                            &relative_path,
                            Some(full_path.clone()),
                            expected.clone(),
                            actual.clone(),
                        )?;
                    }
                    self.finish_pending_attempt(mutation_id, Err(err.into()))?;
                    return Ok(()); // durable file-specific work does not require a root restart
                }
                Err(err) => {
                    self.finish_pending_attempt(mutation_id, Err(err.into()))?;
                    return Ok(()); // durable file-specific work does not require a root restart
                }
            };
            self.remove_identity(&identity)?;
            self.remove_cache_for_identity(&identity);
            let _ = self.upsert_committed_entry(writeback)?;
            CloudFileOplock::acquire_exclusive(&full_path)?.mark_in_sync()?;
            self.clear_pending_mutation(mutation_id)?;
            Ok(())
        }

        unsafe fn handle_delete(&self, info: &CF_CALLBACK_INFO) -> Result<NTSTATUS> {
            self.startup_activity.ensure_wait_allowed()?;
            if let Some(full_path) = normalized_path_from_callback(info) {
                if let Some(relative_path) =
                    relative_path_from_full_path(&self.registration.sync_root_path, &full_path)
                {
                    if self.is_suppressed(&relative_path)? {
                        return Ok(STATUS_SUCCESS);
                    }
                }
            }
            let _operation = self.runtime.block_on(self.operation_lock.lock());
            self.startup_activity.ensure_running()?;
            let identity = self.resolve_callback_identity(info)?;
            let entry = self.entry_for_identity(&identity)?;
            let expected_version = self.expected_version_for(&identity)?;
            let mut record = CloudMutationRecord::new(
                CloudMutationKind::Delete,
                self.registration.root_id,
                entry.relative_path.clone(),
                Some(entry.identity.clone()),
            );
            record.expected_version = match &expected_version {
                ExpectedProviderVersion::Exact(version) => Some(version.clone()),
                ExpectedProviderVersion::Unchecked | ExpectedProviderVersion::Absent => None,
            };
            let mutation_id = self.add_pending_mutation(record)?;
            let status = match self.runtime.block_on(async {
                self.bridge
                    .delete_entry_checked(
                        self.registration.root_id,
                        &self.registration.encrypted_root,
                        &entry.identity,
                        &expected_version,
                    )
                    .await
            }) {
                Ok(()) => {
                    self.remove_identity(&identity)?;
                    self.remove_cache_for_identity(&identity);
                    self.clear_pending_mutation(mutation_id)?;
                    STATUS_SUCCESS
                }
                Err(err @ ProviderCoreError::ContentConflict { .. }) => {
                    if let ProviderCoreError::ContentConflict {
                        expected, actual, ..
                    } = &err
                    {
                        self.record_conflict(
                            &identity,
                            &entry.relative_path,
                            normalized_path_from_callback(info),
                            expected.clone(),
                            actual.clone(),
                        )?;
                    }
                    self.mark_pending_mutation_error(mutation_id, &err.to_string())?;
                    error_status(&err.to_string())
                }
                Err(err) => {
                    self.mark_pending_mutation_error(mutation_id, &err.to_string())?;
                    tracing::warn!(
                        "Cloud Files delete failed for {}: {}",
                        entry.relative_path,
                        err
                    );
                    error_status(&err.to_string())
                }
            };
            Ok(status)
        }
    }

    unsafe fn callback_context(info: &CF_CALLBACK_INFO) -> Option<Arc<CallbackContext>> {
        if info.CallbackContext.is_null() {
            return None;
        }
        let context = info.CallbackContext as *const CallbackContext;
        // ConnectedCloudRoot retains the original Arc until CfDisconnectSyncRoot
        // returns and field teardown begins. Give every dispatched callback its
        // own strong reference so shutdown can observe and drain callback work.
        unsafe {
            Arc::increment_strong_count(context);
            Some(Arc::from_raw(context))
        }
    }

    unsafe fn identity_bytes_from_callback(info: &CF_CALLBACK_INFO) -> Result<&[u8]> {
        if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
            return Err(CloudProviderError::Callback(
                "callback did not include a file identity".to_string(),
            ));
        }
        Ok(std::slice::from_raw_parts(
            info.FileIdentity.cast::<u8>(),
            info.FileIdentityLength as usize,
        ))
    }

    unsafe fn normalized_path_from_callback(info: &CF_CALLBACK_INFO) -> Option<std::path::PathBuf> {
        let path = pcwstr_to_path(info.NormalizedPath)?;
        let volume = pcwstr_to_path(info.VolumeDosName);
        Some(qualify_callback_path(path, volume.as_deref()))
    }

    fn qualify_callback_path(path: PathBuf, volume: Option<&Path>) -> PathBuf {
        let path_text = path.to_string_lossy();
        if path_text.starts_with('\\') && !path_text.starts_with(r"\\") {
            if let Some(volume) = volume {
                return PathBuf::from(format!("{}{}", volume.display(), path_text));
            }
        }
        path
    }

    unsafe fn pcwstr_to_path(value: PCWSTR) -> Option<std::path::PathBuf> {
        if value.is_null() {
            return None;
        }
        value
            .to_string()
            .ok()
            .map(strip_windows_nt_prefix)
            .map(std::path::PathBuf::from)
    }

    fn strip_windows_nt_prefix(value: String) -> String {
        value
            .strip_prefix(r"\??\")
            .or_else(|| value.strip_prefix(r"\\?\"))
            .unwrap_or(&value)
            .to_string()
    }

    fn relative_path_from_full_path(sync_root: &Path, full_path: &Path) -> Option<String> {
        full_path
            .strip_prefix(sync_root)
            .ok()
            .map(|path| normalize_relative_path(path.to_string_lossy()))
            .or_else(|| {
                let root = sync_root
                    .to_string_lossy()
                    .replace('/', "\\")
                    .to_lowercase();
                let full = full_path.to_string_lossy().replace('/', "\\");
                let full_lower = full.to_lowercase();
                full_lower.strip_prefix(&root).map(|_| {
                    normalize_relative_path(full[root.len()..].trim_start_matches('\\').to_string())
                })
            })
    }

    unsafe fn transfer_decrypted_range(
        info: &CF_CALLBACK_INFO,
        offset: i64,
        bytes: &[u8],
        cancellation: &HydrationCancellationToken,
        outstanding: &mut HydrationOutstandingRanges,
        stats: &mut HydrationTransferStats,
    ) -> Result<()> {
        let length = i64::try_from(bytes.len()).map_err(|_| {
            CloudProviderError::Callback("hydration transfer buffer is too large".into())
        })?;
        if length <= 0 {
            return Err(CloudProviderError::Callback(
                "hydration transfer buffer is empty".into(),
            ));
        }
        let end = offset.checked_add(length).ok_or_else(|| {
            CloudProviderError::Callback("hydration transfer range overflows".into())
        })?;
        let cancelled = cancellation.cancelled_ranges(offset, length);
        stats.cancellation_observed |= !cancelled.is_empty();

        // CFAPI requires transfer offsets and non-EOF lengths to be 4-KiB aligned.
        // A partial cancellation can bisect a page, so transfer that page when any
        // byte is still required and abort only pages covered completely by the
        // cancelled union.
        let alignment = super::HYDRATION_TRANSFER_ALIGNMENT_BYTES as i64;
        if offset % alignment != 0 {
            return Err(CloudProviderError::Callback(
                "hydration transfer offset is not 4-KiB aligned".into(),
            ));
        }
        let mut segments: Vec<(i64, i64, bool)> = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            let page_end = cursor.saturating_add(alignment).min(end);
            let page_cancelled = cancelled
                .iter()
                .any(|(start, range_end)| *start <= cursor && *range_end >= page_end);
            if let Some((_, segment_end, segment_cancelled)) = segments.last_mut() {
                if *segment_end == cursor && *segment_cancelled == page_cancelled {
                    *segment_end = page_end;
                } else {
                    segments.push((cursor, page_end, page_cancelled));
                }
            } else {
                segments.push((cursor, page_end, page_cancelled));
            }
            cursor = page_end;
        }

        for (segment_start, segment_end, segment_cancelled) in segments {
            let segment_length = segment_end - segment_start;
            if segment_cancelled {
                unsafe {
                    execute_transfer_data_recorded(
                        info,
                        STATUS_CLOUD_FILE_REQUEST_ABORTED,
                        &[],
                        segment_start,
                        segment_length,
                        &mut stats.execute_results,
                    )?
                };
            } else {
                let slice_start = usize::try_from(segment_start - offset).map_err(|_| {
                    CloudProviderError::Callback("hydration slice offset is invalid".into())
                })?;
                let slice_end = usize::try_from(segment_end - offset).map_err(|_| {
                    CloudProviderError::Callback("hydration slice end is invalid".into())
                })?;
                unsafe {
                    execute_transfer_data_recorded(
                        info,
                        STATUS_SUCCESS,
                        &bytes[slice_start..slice_end],
                        segment_start,
                        segment_length,
                        &mut stats.execute_results,
                    )?
                };
                stats.transferred_bytes = stats
                    .transferred_bytes
                    .saturating_add(segment_length as u64);
            }
            outstanding.complete(segment_start, segment_length);
        }
        Ok(())
    }

    unsafe fn execute_transfer_data(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        bytes: &[u8],
        offset: i64,
        length: i64,
    ) -> Result<()> {
        if length <= 0 {
            return Err(CloudProviderError::Callback(
                "Cloud Files transfer completion length must be nonzero".into(),
            ));
        }
        if status == STATUS_SUCCESS && bytes.len() != length as usize {
            return Err(CloudProviderError::Callback(
                "successful Cloud Files transfer length does not match its buffer".into(),
            ));
        }
        if status != STATUS_SUCCESS && !bytes.is_empty() {
            return Err(CloudProviderError::Callback(
                "failed Cloud Files transfer must not include plaintext bytes".into(),
            ));
        }
        let op_info = operation_info(info, CF_OPERATION_TYPE_TRANSFER_DATA);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_0>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferData: CF_OPERATION_PARAMETERS_0_0 {
                    Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                    CompletionStatus: status,
                    Buffer: if bytes.is_empty() {
                        null()
                    } else {
                        bytes.as_ptr().cast()
                    },
                    Offset: offset,
                    Length: length,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_transfer_data_recorded(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        bytes: &[u8],
        offset: i64,
        length: i64,
        results: &mut Vec<CloudHydrationExecuteResult>,
    ) -> Result<()> {
        let result = unsafe { execute_transfer_data(info, status, bytes, offset, length) };
        results.push(CloudHydrationExecuteResult {
            offset,
            length,
            completion_status: status.0,
            cf_execute_succeeded: result.is_ok(),
        });
        result
    }

    unsafe fn execute_ack_data(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        offset: i64,
        length: i64,
    ) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DATA);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_2>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckData: CF_OPERATION_PARAMETERS_0_2 {
                    Flags: CF_OPERATION_ACK_DATA_FLAG_NONE,
                    CompletionStatus: status,
                    Offset: offset,
                    Length: length,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_transfer_placeholders(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        total_count: i64,
    ) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_4>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferPlaceholders: CF_OPERATION_PARAMETERS_0_4 {
                    Flags: transfer_placeholders_flags(),
                    CompletionStatus: status,
                    PlaceholderTotalCount: total_count,
                    PlaceholderArray: std::ptr::null_mut(),
                    PlaceholderCount: 0,
                    EntriesProcessed: 0,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    fn transfer_placeholders_flags(
    ) -> windows::Win32::Storage::CloudFilters::CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS {
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION
    }

    unsafe fn execute_ack_dehydrate(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DEHYDRATE);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_5>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckDehydrate: CF_OPERATION_PARAMETERS_0_5 {
                    Flags: CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE,
                    CompletionStatus: status,
                    FileIdentity: info.FileIdentity,
                    FileIdentityLength: info.FileIdentityLength,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_ack_delete(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DELETE);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_7>(),
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckDelete: CF_OPERATION_PARAMETERS_0_7 {
                    Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
                    CompletionStatus: status,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    fn cf_operation_param_size<T>() -> u32 {
        (std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous) + size_of::<T>()) as u32
    }

    unsafe fn operation_info(
        info: &CF_CALLBACK_INFO,
        operation_type: windows::Win32::Storage::CloudFilters::CF_OPERATION_TYPE,
    ) -> CF_OPERATION_INFO {
        CF_OPERATION_INFO {
            StructSize: size_of::<CF_OPERATION_INFO>() as u32,
            Type: operation_type,
            ConnectionKey: info.ConnectionKey,
            TransferKey: info.TransferKey,
            CorrelationVector: info.CorrelationVector,
            SyncStatus: null(),
            RequestKey: info.RequestKey,
        }
    }

    fn ensure_hydration_active(
        cancellation: &HydrationCancellationToken,
        deadline: Instant,
    ) -> Result<()> {
        if cancellation.is_cancelled() {
            return Err(CloudProviderError::HydrationCancelled);
        }
        if Instant::now() >= deadline {
            return Err(CloudProviderError::HydrationTimedOut);
        }
        Ok(())
    }

    fn hydration_error_status(error: &CloudProviderError) -> NTSTATUS {
        match error {
            CloudProviderError::HydrationCancelled => STATUS_CLOUD_FILE_REQUEST_ABORTED,
            _ => STATUS_CLOUD_FILE_UNSUCCESSFUL,
        }
    }

    fn hydration_error_telemetry(error: &CloudProviderError) -> String {
        match error {
            CloudProviderError::UnsupportedPlatform => {
                "Cloud Files is unsupported on this platform".into()
            }
            CloudProviderError::NativeCallbacksNotImplemented => {
                "Cloud Files callbacks are unavailable".into()
            }
            CloudProviderError::InvalidCommand(_) => "invalid provider command".into(),
            CloudProviderError::InvalidPath(_) => "hydration path validation failed".into(),
            CloudProviderError::IdentityTooLarge { length, max, .. } => {
                format!("placeholder identity is too large ({length} bytes; maximum {max})")
            }
            CloudProviderError::Io(source) => format!(
                "hydration I/O failed (kind={:?}, os_code={:?})",
                source.kind(),
                source.raw_os_error()
            ),
            CloudProviderError::ProviderCore(source) => match source {
                ProviderCoreError::Io(source) => format!(
                    "provider I/O failed (kind={:?}, os_code={:?})",
                    source.kind(),
                    source.raw_os_error()
                ),
                ProviderCoreError::IdentitySerialization(_) => {
                    "provider identity serialization failed".into()
                }
                ProviderCoreError::InvalidIdentity(_) => "provider identity is invalid".into(),
                ProviderCoreError::MetadataParse { .. } => {
                    "encrypted metadata parsing failed".into()
                }
                ProviderCoreError::PathOutsideRoot { .. } => {
                    "provider path escaped the encrypted root".into()
                }
                ProviderCoreError::Crypto(_) if source.is_legacy_consent_required() => "legacy_compatibility_required: Open folder details and enable access to older files after reviewing the integrity limitation".into(),
                ProviderCoreError::Crypto(_) if source.is_integrity_failure() => "file_integrity_failed: The file failed authentication. Preserve its encrypted original and recover a verified copy".into(),
                ProviderCoreError::Crypto(_) => "file_unavailable: Authenticated file decryption failed; inspect this file's recovery status".into(),
                ProviderCoreError::MutationUnsupported(_) => {
                    "provider operation is unsupported".into()
                }
                ProviderCoreError::ContentConflict { .. } => {
                    "provider content version conflict".into()
                }
            },
            CloudProviderError::Callback(_) => "Cloud Files callback invariant failed".into(),
            CloudProviderError::StartupRecoveryUnavailable => {
                "provider startup or shutdown interrupted hydration".into()
            }
            CloudProviderError::HydrationCancelled => {
                "hydration was cancelled by the caller".into()
            }
            CloudProviderError::HydrationTimedOut => "hydration callback timed out".into(),
            CloudProviderError::Serialization(_) => "provider state serialization failed".into(),
            CloudProviderError::Uuid(_) => "provider root identity is invalid".into(),
            CloudProviderError::Windows(source) => format!(
                "Windows Cloud Files operation failed (HRESULT=0x{:08X})",
                source.code().0 as u32
            ),
        }
    }

    fn error_status(_message: &str) -> NTSTATUS {
        STATUS_CLOUD_FILE_UNSUCCESSFUL
    }

    struct OwnedPlaceholder {
        relative_name: Vec<u16>,
        full_path: PathBuf,
        display_path: String,
        kind: ProviderEntryKind,
        dirty: bool,
        identity: Vec<u8>,
        info: CF_PLACEHOLDER_CREATE_INFO,
    }

    impl OwnedPlaceholder {
        fn new(
            entry: &CloudPlaceholderEntry,
            relative_name: Vec<u16>,
            full_path: PathBuf,
            display_path: String,
        ) -> Result<Self> {
            let identity = entry.identity.to_bytes()?;
            if identity.len() > CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize {
                return Err(CloudProviderError::IdentityTooLarge {
                    path: entry.entry.relative_path.clone(),
                    length: identity.len(),
                    max: CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH,
                });
            }

            let attributes = match entry.entry.kind {
                ProviderEntryKind::Directory => FILE_ATTRIBUTE_DIRECTORY.0,
                ProviderEntryKind::File => FILE_ATTRIBUTE_ARCHIVE.0,
            };
            let modified_time = filetime_from_datetime(entry.entry.modified_at);
            let file_size = i64::try_from(entry.entry.logical_size).map_err(|_| {
                CloudProviderError::InvalidPath(format!(
                    "logical size for {} does not fit Windows Cloud Files metadata",
                    entry.entry.relative_path
                ))
            })?;

            let mut placeholder = Self {
                relative_name,
                full_path,
                display_path,
                kind: entry.entry.kind,
                dirty: entry.dirty,
                identity,
                info: CF_PLACEHOLDER_CREATE_INFO::default(),
            };
            placeholder.info = CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: PCWSTR(placeholder.relative_name.as_ptr()),
                FsMetadata: CF_FS_METADATA {
                    BasicInfo: FILE_BASIC_INFO {
                        CreationTime: modified_time,
                        LastAccessTime: modified_time,
                        LastWriteTime: modified_time,
                        ChangeTime: modified_time,
                        FileAttributes: attributes,
                    },
                    FileSize: file_size,
                },
                FileIdentity: placeholder.identity.as_ptr().cast(),
                FileIdentityLength: placeholder.identity.len() as u32,
                Flags: placeholder_create_flags(entry.entry.kind),
                Result: Default::default(),
                CreateUsn: 0,
            };
            Ok(placeholder)
        }

        fn relative_path(&self) -> String {
            self.display_path.clone()
        }
    }

    fn placeholder_create_flags(
        kind: ProviderEntryKind,
    ) -> windows::Win32::Storage::CloudFilters::CF_PLACEHOLDER_CREATE_FLAGS {
        let mut flags =
            CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC | CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE;
        if kind == ProviderEntryKind::Directory {
            // Reconciliation creates every known child up front, so tell Windows this directory
            // is complete. Leaving it partial causes nested creates and renames to wait on
            // FETCH_PLACEHOLDERS even though the children are already on disk.
            flags |= CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION;
        }
        flags
    }

    fn windows_error_matches(err: &windows::core::Error, code: WIN32_ERROR) -> bool {
        hresult_matches(err.code(), code)
    }

    fn hresult_matches(actual: HRESULT, code: WIN32_ERROR) -> bool {
        actual == HRESULT::from_win32(code.0)
    }

    fn ensure_absolute_or_create_root(path: &Path) -> Result<()> {
        ensure_absolute_path(path, "sync root")?;
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn ensure_existing_dir(path: &Path, label: &str) -> Result<()> {
        ensure_absolute_path(path, label)?;
        if !path.is_dir() {
            return Err(CloudProviderError::InvalidPath(format!(
                "{label} must be an existing directory: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn ensure_absolute_path(path: &Path, label: &str) -> Result<()> {
        if !path.is_absolute() {
            return Err(CloudProviderError::InvalidPath(format!(
                "{label} must be an absolute path: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn validate_relative_path(path: &str) -> Result<String> {
        if path.trim().is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "placeholder relative path is empty".to_string(),
            ));
        }
        let normalized = path.replace('/', "\\");
        let candidate = Path::new(&normalized);
        if candidate.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::ParentDir
            )
        }) {
            return Err(CloudProviderError::InvalidPath(format!(
                "placeholder path must stay under the sync root: {path}"
            )));
        }
        Ok(normalized)
    }

    fn filetime_from_datetime(datetime: chrono::DateTime<chrono::Utc>) -> i64 {
        (datetime.timestamp() + SECONDS_FROM_1601_TO_UNIX_EPOCH) * WINDOWS_TICKS_PER_SECOND
            + i64::from(datetime.timestamp_subsec_nanos() / 100)
    }

    fn to_wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn resident_allocation_bound_rounds_up_to_eight_bytes() {
            assert_eq!(resident_allocation_bound(0), 0);
            assert_eq!(resident_allocation_bound(1), 8);
            assert_eq!(resident_allocation_bound(8), 8);
            assert_eq!(resident_allocation_bound(9), 16);
            assert_eq!(resident_allocation_bound(57), 64);
            assert_eq!(resident_allocation_bound(700), 704);
        }

        #[test]
        fn resident_allocation_bound_separates_mft_leftovers_from_cluster_backed_data() {
            // Regression: a 57-byte file that dehydrated to zero on-disk data
            // still reports 64 allocated bytes, because NTFS kept the stream
            // resident in its MFT record and dehydration has no clusters to
            // release. The previous `AllocationSize != 0` gate blocked unmount
            // on that file forever.
            assert!(64 <= resident_allocation_bound(57));
            // A placeholder that is genuinely still hydrated holds whole
            // clusters, which residency cannot account for.
            assert!(4096 > resident_allocation_bound(398));
            assert!(4096 > resident_allocation_bound(3181));
        }

        #[test]
        fn small_files_report_allocation_the_resident_bound_can_explain() {
            use std::os::windows::io::AsRawHandle;

            let temp = tempfile::tempdir().unwrap();
            for size in [0usize, 1, 8, 57, 100, 500, 688, 700] {
                let path = temp.path().join(format!("resident-{size}.bin"));
                std::fs::write(&path, vec![0u8; size]).unwrap();
                let file = std::fs::File::open(&path).unwrap();
                let mut info = FILE_STANDARD_INFO::default();
                unsafe {
                    GetFileInformationByHandleEx(
                        HANDLE(file.as_raw_handle()),
                        FileStandardInfo,
                        (&mut info as *mut FILE_STANDARD_INFO).cast(),
                        size_of::<FILE_STANDARD_INFO>() as u32,
                    )
                    .unwrap();
                }
                // Either the volume kept the stream resident, in which case the
                // bound covers it, or it handed out whole sectors. Anything else
                // means the bound formula no longer models this filesystem.
                assert!(
                    info.AllocationSize <= resident_allocation_bound(info.EndOfFile)
                        || info.AllocationSize % 512 == 0,
                    "{size}-byte file reported {} allocated bytes for a {}-byte stream, which neither MFT residency nor sector allocation explains",
                    info.AllocationSize,
                    info.EndOfFile,
                );
            }
        }

        #[test]
        fn reconciliation_guard_clears_durable_marker_when_dropped() {
            let temp = tempfile::tempdir().unwrap();
            let root_id = Uuid::new_v4();
            let store = CloudStateStore::new(temp.path().join("state.json"), root_id);

            {
                let _guard = ReconciliationStateGuard::begin(&store).unwrap();
                assert!(store.load().unwrap().reconciliation_in_progress);
            }

            assert!(!store.load().unwrap().reconciliation_in_progress);
        }

        #[test]
        fn callback_path_adds_dos_volume_to_root_relative_path() {
            assert_eq!(
                qualify_callback_path(
                    PathBuf::from(r"\Users\Admin\file.txt"),
                    Some(Path::new("C:")),
                ),
                PathBuf::from(r"C:\Users\Admin\file.txt")
            );
        }

        #[test]
        fn callback_path_preserves_fully_qualified_path() {
            assert_eq!(
                qualify_callback_path(
                    PathBuf::from(r"C:\Users\Admin\file.txt"),
                    Some(Path::new("C:")),
                ),
                PathBuf::from(r"C:\Users\Admin\file.txt")
            );
        }

        #[test]
        fn cf_operation_param_size_uses_selected_union_member() {
            let full_size = size_of::<CF_OPERATION_PARAMETERS>() as u32;
            let delete_size = cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_7>();

            assert_eq!(
                delete_size as usize,
                std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
                    + size_of::<CF_OPERATION_PARAMETERS_0_7>()
            );
            assert!(delete_size < full_size);
            assert_eq!(
                cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_5>() as usize,
                std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
                    + size_of::<CF_OPERATION_PARAMETERS_0_5>()
            );
            assert_eq!(
                cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_0>() as usize,
                std::mem::offset_of!(CF_OPERATION_PARAMETERS, Anonymous)
                    + size_of::<CF_OPERATION_PARAMETERS_0_0>()
            );
            assert!(cf_operation_param_size::<CF_OPERATION_PARAMETERS_0_0>() < full_size);
        }

        #[test]
        fn callback_table_supports_population_fallback_and_post_scan_renames() {
            use windows::Win32::Storage::CloudFilters::{
                CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
                CF_CALLBACK_TYPE_NOTIFY_RENAME, CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION,
            };

            let registrations = callback_registrations();
            assert!(registrations
                .iter()
                .any(|entry| entry.Type == CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS
                    && entry.Callback.is_some()));
            assert!(registrations.iter().any(|entry| entry.Type
                == CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS
                && entry.Callback.is_some()));
            assert!(!registrations
                .iter()
                .any(|entry| entry.Type == CF_CALLBACK_TYPE_NOTIFY_RENAME
                    && entry.Callback.is_some()));
            assert!(!registrations.iter().any(|entry| entry.Type
                == CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION
                && entry.Callback.is_some()));
        }

        #[test]
        fn directory_placeholders_disable_on_demand_population() {
            let directory_create = placeholder_create_flags(ProviderEntryKind::Directory);
            let file_create = placeholder_create_flags(ProviderEntryKind::File);
            assert_ne!(
                directory_create.0 & CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION.0,
                0
            );
            assert_eq!(
                file_create.0 & CF_PLACEHOLDER_CREATE_FLAG_DISABLE_ON_DEMAND_POPULATION.0,
                0
            );

            let directory_update = placeholder_update_flags(ProviderEntryKind::Directory, false);
            let file_update = placeholder_update_flags(ProviderEntryKind::File, false);
            assert_ne!(
                directory_update.0 & CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION.0,
                0
            );
            assert_eq!(
                file_update.0 & CF_UPDATE_FLAG_DISABLE_ON_DEMAND_POPULATION.0,
                0
            );
            assert_ne!(
                transfer_placeholders_flags().0
                    & CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION.0,
                0
            );
        }

        #[test]
        fn ingestion_oplock_does_not_request_delete_access() {
            let flags = CloudFileOplock::exclusive_write_flags();
            assert_ne!(flags.0 & CF_OPEN_FILE_FLAG_EXCLUSIVE.0, 0);
            assert_ne!(flags.0 & CF_OPEN_FILE_FLAG_WRITE_ACCESS.0, 0);
            assert_eq!(flags.0 & CF_OPEN_FILE_FLAG_DELETE_ACCESS.0, 0);
        }

        #[test]
        fn plain_file_ingestion_snapshot_copies_ordinary_file() {
            let temp = tempfile::tempdir().unwrap();
            let source = temp.path().join("new-local-file.txt");
            let destination = temp.path().join("cache").join("snapshot.plain");
            fs::write(&source, b"ordinary file bytes").unwrap();

            snapshot_plain_file_to_path(&source, &destination).unwrap();

            assert_eq!(fs::read(&destination).unwrap(), b"ordinary file bytes");
        }

        #[test]
        fn delete_oplock_requests_delete_access_explicitly() {
            let flags = CloudFileOplock::exclusive_delete_flags();
            assert_ne!(flags.0 & CF_OPEN_FILE_FLAG_EXCLUSIVE.0, 0);
            assert_ne!(flags.0 & CF_OPEN_FILE_FLAG_WRITE_ACCESS.0, 0);
            assert_ne!(flags.0 & CF_OPEN_FILE_FLAG_DELETE_ACCESS.0, 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{
        CloudPlaceholderEntry, CloudProviderError, CloudProviderStatus, CloudRootProbeKind,
        CloudRootRegistration, CloudRootStartResult, CloudRuntimePaths, DehydrateRootSummary,
        Result, RootHealthTelemetry, RootWriterLease,
    };
    use hybridcipher_provider_core::ProviderBridge;
    use std::path::Path;
    use std::sync::Arc;
    use uuid::Uuid;

    pub struct ConnectedCloudRoot;

    #[derive(Clone)]
    pub struct CloudRootShutdownBarrier;

    impl CloudRootShutdownBarrier {
        pub fn compatibility_status(&self) -> Option<super::VaultCompatibilityStatus> {
            None
        }
        pub async fn set_legacy_compatibility(
            &self,
            _enabled: bool,
        ) -> Result<super::VaultCompatibilityStatus> {
            Err(CloudProviderError::UnsupportedPlatform)
        }
        pub async fn resolve_pending(
            &self,
            _id: Uuid,
            _action: super::PendingOperationResolution,
        ) -> Result<()> {
            Err(CloudProviderError::UnsupportedPlatform)
        }
        pub async fn begin(&self) -> Result<()> {
            Err(CloudProviderError::UnsupportedPlatform)
        }

        pub fn resume(&self) {}
    }

    impl ConnectedCloudRoot {
        pub fn root_id(&self) -> Uuid {
            Uuid::nil()
        }

        pub fn sync_root_path(&self) -> &Path {
            Path::new("")
        }

        pub fn shutdown_barrier(&self) -> CloudRootShutdownBarrier {
            CloudRootShutdownBarrier
        }

        pub async fn disconnect(&mut self) -> Result<()> {
            Err(CloudProviderError::UnsupportedPlatform)
        }

        pub fn disconnect_best_effort_on_drop(&mut self) -> Result<()> {
            Err(CloudProviderError::UnsupportedPlatform)
        }
    }

    pub fn status() -> CloudProviderStatus {
        CloudProviderStatus::scaffolded(false, "Cloud Files API is only available on Windows.")
    }

    pub fn register_root(_registration: &CloudRootRegistration) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn current_user_shell_sync_root_id(_root_id: Uuid) -> Result<String> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn restrict_hydration_temp_directory(_path: &Path) -> Result<()> {
        Ok(())
    }

    pub fn unregister_all_shell_roots() -> Result<usize> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn unregister_registration(_registration: &CloudRootRegistration) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn unregister_root(_sync_root_path: &Path) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn create_placeholders(
        _sync_root_path: &Path,
        _entries: &[CloudPlaceholderEntry],
    ) -> Result<u32> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn dehydrate_root(_sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn dehydrate_root_filtered(
        _sync_root_path: &Path,
        _cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<DehydrateRootSummary> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    #[allow(dead_code)]
    pub fn verify_root_dehydrated(_sync_root_path: &Path) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn verify_root_dehydrated_filtered(
        _sync_root_path: &Path,
        _cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    #[allow(dead_code)]
    pub fn clear_dehydrated_root(_sync_root_path: &Path) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn clear_dehydrated_root_filtered(
        _sync_root_path: &Path,
        _cleanup_path_filter: &super::CloudCleanupPathFilter,
    ) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn active_probe(_sync_root_path: &Path) -> Result<CloudRootProbeKind> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub async fn connect_root(
        _registration: &CloudRootRegistration,
        _bridge: Arc<dyn ProviderBridge>,
        _entries: Vec<CloudPlaceholderEntry>,
        _runtime_paths: CloudRuntimePaths,
        _writer_lease: Arc<RootWriterLease>,
        _health: RootHealthTelemetry,
        _health_generation: u64,
    ) -> CloudRootStartResult<ConnectedCloudRoot> {
        Err(CloudProviderError::UnsupportedPlatform.into())
    }
}
