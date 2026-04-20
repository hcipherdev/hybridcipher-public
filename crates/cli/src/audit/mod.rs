use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Audit entry for PIN-related operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinAuditEntry {
    pub action: PinAuditAction,
    pub user_id: String,
    pub device_id: String,
    pub fingerprint: Option<String>,
    pub method: Option<String>,
    pub notes: Option<String>,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub signature: Option<String>,
    pub signer_public_key: Option<String>,
    pub checkpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_sequence: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PinAuditAction {
    Add,
    Remove,
    Verify,
    Import,
    Export,
}
mod file_log;
pub use file_log::append_jsonl;
