use serde::{Deserialize, Serialize};

/// Provenance for epoch keys, used to prevent encryption with unverified material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochKeySource {
    /// Key was authenticated via a Welcome message.
    Welcome,
    /// Key was authenticated via a roster/group update.
    GroupUpdate,
    /// Key was generated locally before Welcome distribution.
    LocalInit,
    /// Placeholder or zeroed key material.
    Placeholder,
    /// Unknown origin (legacy or missing metadata).
    Unknown,
}

impl Default for EpochKeySource {
    fn default() -> Self {
        EpochKeySource::Unknown
    }
}

impl EpochKeySource {
    pub fn is_verified(self) -> bool {
        matches!(self, EpochKeySource::Welcome | EpochKeySource::GroupUpdate)
    }
}
