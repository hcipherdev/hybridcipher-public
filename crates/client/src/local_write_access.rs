//! Account-scoped authorization for local mutations, including long-lived mounts.

use crate::{entitlement, ClientError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const STORAGE_KEY: &str = "local_write_access";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalWriteAccess {
    pub issuer: String,
    pub user_id: String,
    pub entitlement: Option<String>,
    pub revoked: bool,
}

impl LocalWriteAccess {
    pub fn check_group(
        &self,
        organization_id: Option<&str>,
        role: Option<&str>,
        keys: &[entitlement::TrustedKey],
        now: i64,
    ) -> Result<(), ClientError> {
        if role.is_some_and(|role| !matches!(role, "admin" | "owner" | "member")) {
            return Err(ClientError::InvalidState(
                "This group is read-only for this account".into(),
            ));
        }
        let Some(organization_id) = organization_id else {
            return Ok(());
        };
        if self.revoked {
            return Err(ClientError::InvalidState(
                "Team license has been revoked; existing files remain readable".into(),
            ));
        }
        let token = self.entitlement.as_deref().ok_or_else(|| {
            ClientError::InvalidState(
                "A valid Team entitlement is required to write to this group".into(),
            )
        })?;
        let claims =
            entitlement::verify(token, keys, &self.issuer, &self.user_id, now).map_err(|err| {
                ClientError::InvalidState(format!("Team entitlement expired or invalid: {err}"))
            })?;
        if claims.organization_id != organization_id {
            return Err(ClientError::InvalidState(
                "Team entitlement belongs to another organization".into(),
            ));
        }
        Ok(())
    }
}

/// Group metadata is stored in the same protected account storage by both clients.
#[derive(Default, Deserialize)]
pub(crate) struct GroupCache {
    #[serde(default)]
    pub by_id: std::collections::HashMap<String, CachedGroup>,
}

#[derive(Deserialize)]
pub(crate) struct CachedGroup {
    pub organization_id: Option<String>,
    #[serde(default)]
    pub organization_known: bool,
    pub role: Option<String>,
}

pub(crate) fn check_cached_group(
    access: &LocalWriteAccess,
    cache: &GroupCache,
    group_id: Uuid,
    keys: &[entitlement::TrustedKey],
    now: i64,
) -> Result<(), ClientError> {
    let group = cache.by_id.get(&group_id.to_string());
    match group {
        Some(group) if group.organization_known => access.check_group(
            group.organization_id.as_deref(),
            group.role.as_deref(),
            keys,
            now,
        ),
        // Existing pre-Team accounts contain Personal groups only. Once an
        // account has Team data, unknown groups require an authenticated refresh.
        _ if access.entitlement.is_none() && !access.revoked => Ok(()),
        _ => Err(ClientError::InvalidState(
            "Group workspace is unknown; sign in and refresh the group list before writing".into(),
        )),
    }
}

#[cfg(test)]
#[path = "../tests/licensing/test_local_write_access.rs"]
mod tests;
