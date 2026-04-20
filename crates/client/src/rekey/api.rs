use chrono::{DateTime, Utc};
use hybridcipher_coverage::CoverageTransparencyMetadata;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// Request payload for initiating a rekey operation
#[derive(Debug, Clone, Serialize)]
pub struct RekeyInitiateRequest {
    pub reason: EpochChangeReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_updates: Option<Value>,
    #[serde(default)]
    pub welcome_messages: Vec<EncryptedWelcomeMessage>,
    pub emergency: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_epoch_id: Option<u64>,
}

/// Encrypted welcome message payload sent to the server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedWelcomeMessage {
    pub recipient_user_id: Uuid,
    pub device_id: String,
    #[serde(alias = "encrypted_content")]
    pub encrypted_epoch_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Server response payload for rekey initiation
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyResponsePayload {
    pub rekey_id: Uuid,
    pub group_id: Uuid,
    pub new_epoch_id: String,
    pub status: RekeyStatus,
    pub initiated_at: DateTime<Utc>,
    pub estimated_completion: DateTime<Utc>,
    pub migration_progress: ApiMigrationProgress,
    #[serde(default)]
    pub descriptor_commitment: Option<String>,
}

/// Server response payload for rekey status queries
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyStatusPayload {
    pub rekey_id: Uuid,
    pub group_id: Uuid,
    pub status: RekeyStatus,
    #[serde(default)]
    pub new_epoch_id: Option<String>,
    pub progress: ApiMigrationProgress,
    pub started_at: DateTime<Utc>,
    pub last_updated: DateTime<Utc>,
    pub errors: Vec<ApiRekeyError>,
    pub can_cutover: bool,
    #[serde(default)]
    pub policy: Option<PolicyEvaluationSnapshot>,
    #[serde(default)]
    pub descriptor_commitment: Option<String>,
    #[serde(default)]
    pub coverage_transparency: Option<CoverageTransparencyMetadata>,
}

/// Migration progress snapshot returned by the API
#[derive(Debug, Clone, Deserialize)]
pub struct ApiMigrationProgress {
    pub total_files: u64,
    pub migrated_files: u64,
    pub total_members: u32,
    pub confirmed_members: u32,
    #[serde(default)]
    pub reporting_members: u32,
    pub estimated_time_remaining_minutes: Option<u32>,
}

/// Rekey error entry returned by the API
#[derive(Debug, Clone, Deserialize)]
pub struct ApiRekeyError {
    pub error_type: String,
    pub message: String,
    pub timestamp: DateTime<Utc>,
    pub member_id: Option<Uuid>,
}

/// Payload for reporting member/device progress during migration
#[derive(Debug, Clone, Serialize)]
pub struct RekeyProgressUpdateRequest {
    pub operation_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<RekeyProgressState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u8>,
}

/// Request payload for automatic migration heartbeats
#[derive(Debug, Clone, Serialize)]
pub struct RekeyHeartbeatRequestPayload {
    pub operation_id: Uuid,
    pub device_id: String,
    pub epoch_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor_commitment: Option<String>,
    pub coverage_bytes: u64,
    pub protected_bytes: u64,
    pub coverage_items: u64,
    pub protected_items: u64,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default)]
    pub root_kpis: Vec<RootCoverageKpiPayload>,
}

/// Request payload for cutover execution
#[derive(Debug, Clone, Serialize)]
pub struct CutoverRequest {
    pub rekey_id: Uuid,
    pub force: bool,
    pub immediate_cleanup: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,
}

/// Request payload for cancelling an active rekey operation.
#[derive(Debug, Clone, Serialize)]
pub struct RekeyFallbackRequestPayload {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Per-root coverage KPI payload included with heartbeats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCoverageKpiPayload {
    pub root_id: Uuid,
    pub coverage_ratio: f64,
    pub tracked_files: u64,
    pub orphaned_files: u64,
    pub unmanaged_files: u64,
    pub tracked_bytes: u64,
    pub orphaned_bytes: u64,
    pub unmanaged_bytes: u64,
}

/// Descriptor summary exposed via admin/audit endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyDescriptorSummary {
    pub operation_id: Uuid,
    pub commitment: String,
}

/// Response returned when listing descriptors for a group.
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyDescriptorList {
    pub group_id: Uuid,
    pub descriptors: Vec<RekeyDescriptorSummary>,
}

/// Response payload returned after cutover completes
#[derive(Debug, Clone, Deserialize)]
pub struct CutoverResponsePayload {
    pub cutover_id: Uuid,
    pub group_id: Uuid,
    pub new_epoch_id: Uuid,
    pub old_epoch_id: Uuid,
    pub completed_at: DateTime<Utc>,
    pub cleanup_status: String,
    #[serde(default)]
    pub coverage_transparency: Option<CoverageTransparencyMetadata>,
}

/// Response payload returned when a rekey operation is cancelled.
#[derive(Debug, Clone, Deserialize)]
pub struct RekeyFallbackResponsePayload {
    pub rekey_id: Uuid,
    pub group_id: Uuid,
    pub status: RekeyStatus,
    pub cancelled_at: DateTime<Utc>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub new_epoch_id: Option<Uuid>,
    #[serde(default)]
    pub new_epoch_number: Option<u64>,
    #[serde(default)]
    pub previous_epoch_id: Option<Uuid>,
    #[serde(default)]
    pub previous_epoch_number: Option<u64>,
}

/// Reasons for initiating a rekey operation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EpochChangeReason {
    MemberAdded,
    MemberRemoved,
    MemberDeviceAdded,
    MemberDeviceRemoved,
    KeyRotation,
    SecurityIncident,
    ScheduledRotation,
    AdminAction,
}

/// Overall status of the rekey operation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RekeyStatus {
    Initiated,
    InProgress,
    AwaitingCutover,
    Completing,
    Completed,
    Failed,
    Cancelled,
}

/// Member/device progress state reported during migration
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RekeyProgressState {
    Pending,
    Migrating,
    Confirmed,
    Failed,
}

/// Snapshot of the activation policy evaluation returned by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEvaluationSnapshot {
    pub decision: ActivationDecision,
    pub activation_time: DateTime<Utc>,
    pub grace_deadline: DateTime<Utc>,
    pub retention_deadline: DateTime<Utc>,
    #[serde(default)]
    pub coverage_percent_bytes: Option<f64>,
    #[serde(default)]
    pub coverage_percent_items: Option<f64>,
    #[serde(default)]
    pub lowest_root_coverage: Option<f64>,
    pub quorum_devices: usize,
    pub required_devices_met: usize,
    #[serde(default)]
    pub stale_devices: usize,
}

/// Activation decision outcome returned by the policy engine.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ActivationDecision {
    Pending,
    Ready,
    GraceReady,
    BlockedSafety,
}
