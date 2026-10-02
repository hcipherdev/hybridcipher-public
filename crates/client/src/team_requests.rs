//! Account-protected Team administration requests awaiting server acceptance.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TeamAdminRequest {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub kind: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub invitation_code: Option<String>,
    #[serde(default)]
    pub group_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub target_id: Option<Uuid>,
}

impl Drop for TeamAdminRequest {
    fn drop(&mut self) {
        if let Some(code) = &mut self.invitation_code {
            code.zeroize();
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingTeamRequest {
    pub request: TeamAdminRequest,
    pub created_at: i64,
    /// `pending`, `initializing`, `accepted`, or `rejected`. Initialization is
    /// durable and retryable; accepted groups have their real encryption keys.
    pub status: String,
    #[serde(default)]
    pub result_id: Option<Uuid>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[cfg(test)]
#[path = "../test/team_requests/test_team_requests.rs"]
mod tests;
