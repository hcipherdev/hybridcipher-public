use serde::{Deserialize, Serialize};

/// Provenance for epoch keys, used to prevent encryption with unverified material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpochKeySource {
    /// Key was authenticated via a Welcome message.
    Welcome,
    /// Key was authenticated via a roster/group update.
    GroupUpdate,
    /// Key authenticated by decrypting a saved-code recovery artifact.
    Recovery,
    /// Key was generated locally before Welcome distribution.
    LocalInit,
    /// Key belongs to an accountless vault held only on this device. It never
    /// satisfies account readiness; adoption replaces it with a Welcome key.
    LocalVault,
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
        matches!(
            self,
            EpochKeySource::Welcome | EpochKeySource::GroupUpdate | EpochKeySource::Recovery
        )
    }

    /// Usable for an accountless vault's own files; never for account readiness.
    pub fn is_locally_usable(self) -> bool {
        self.is_verified() || self == EpochKeySource::LocalVault
    }
}
