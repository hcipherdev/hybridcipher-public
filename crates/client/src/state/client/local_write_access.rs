use super::*;
use crate::local_write_access::{self, GroupCache, LocalWriteAccess};

impl<S: Storage, N: Network> Client<S, N> {
    pub async fn cache_team_directory(&self, value: &serde_json::Value) -> Result<(), ClientError> {
        self.storage
            .store_config("team_directory", &value.to_string())
            .await?;
        Ok(())
    }

    pub async fn cached_team_directory(&self) -> Result<Option<serde_json::Value>, ClientError> {
        self.storage
            .load_config_fresh("team_directory")
            .await?
            .map(|raw| {
                serde_json::from_str(&raw).map_err(|err| ClientError::InvalidState(err.to_string()))
            })
            .transpose()
    }

    /// Call before exposing local mutation commands or a mount. The identity is
    /// fixed in memory; updates from another process must match this account.
    pub async fn configure_local_write_access(
        &self,
        access: LocalWriteAccess,
    ) -> Result<(), ClientError> {
        let identity = (access.issuer.clone(), access.user_id.clone());
        let json = serde_json::to_string(&access)
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        self.storage
            .store_config(local_write_access::STORAGE_KEY, &json)
            .await?;
        *self
            .local_write_identity
            .write()
            .map_err(|_| ClientError::InvalidState("Local access lock unavailable".into()))? =
            Some(identity);
        Ok(())
    }

    /// Record a verified online observation, including revocation or restoration.
    pub async fn record_online_write_access(
        &self,
        access: LocalWriteAccess,
    ) -> Result<(), ClientError> {
        self.configure_local_write_access(access.clone()).await?;
        self.storage
            .store_config(
                "local_server_write_access",
                &serde_json::to_string(&access)
                    .map_err(|error| ClientError::InvalidState(error.to_string()))?,
            )
            .await?;
        *self.local_access_refresh.lock().await = None;
        Ok(())
    }

    pub async fn require_local_write_for_group(&self, group_id: Uuid) -> Result<(), ClientError> {
        let identity = self
            .local_write_identity
            .read()
            .map_err(|_| ClientError::InvalidState("Local access lock unavailable".into()))?
            .clone();
        let Some((issuer, user_id)) = identity else {
            return Ok(());
        };
        self.refresh_local_write_access().await;
        let raw = self
            .storage
            .load_config_fresh(local_write_access::STORAGE_KEY)
            .await?
            .ok_or_else(|| {
                ClientError::InvalidState("Local account access is unavailable".into())
            })?;
        let mut access: LocalWriteAccess = serde_json::from_str(&raw)
            .map_err(|_| ClientError::InvalidState("Local account access is invalid".into()))?;
        if access.issuer != issuer || access.user_id != user_id {
            return Err(ClientError::InvalidState(
                "Local access belongs to another account".into(),
            ));
        }
        if let Some(raw) = self
            .storage
            .load_config_fresh("local_server_write_access")
            .await?
        {
            let authoritative: LocalWriteAccess = serde_json::from_str(&raw)
                .map_err(|_| ClientError::InvalidState("Server access cache is invalid".into()))?;
            if authoritative.issuer == issuer && authoritative.user_id == user_id {
                access = authoritative;
            }
        }
        let cache = self
            .storage
            .load_config_fresh("group_metadata_cache")
            .await?
            .map(|raw| serde_json::from_str::<GroupCache>(&raw))
            .transpose()
            .map_err(|_| ClientError::InvalidState("Group access cache is invalid".into()))?
            .unwrap_or_default();
        let keys =
            crate::entitlement::trusted_keys_from_build().map_err(ClientError::InvalidState)?;
        local_write_access::check_cached_group(
            &access,
            &cache,
            group_id,
            &keys,
            Utc::now().timestamp(),
        )
    }

    pub async fn require_local_write(&self) -> Result<(), ClientError> {
        self.ensure_state_loaded().await?;
        if let Some(group_id) = self.active_group_id_opt().await {
            self.require_local_write_for_group(group_id).await?;
        }
        Ok(())
    }

    /// Quietly refresh long-lived mounts. An expired authentication session never
    /// authorizes a request; network failures leave the signed offline grant intact.
    async fn refresh_local_write_access(&self) {
        let mut last = self.local_access_refresh.lock().await;
        if last.is_some_and(|time| time.elapsed() < std::time::Duration::from_secs(30)) {
            return;
        }
        *last = Some(std::time::Instant::now());
        drop(last);
        let _ = self.refresh_local_write_access_online().await;
    }

    async fn refresh_local_write_access_online(&self) -> Result<(), ClientError> {
        let Some(raw) = self
            .storage
            .load_config_fresh(local_write_access::STORAGE_KEY)
            .await?
        else {
            return Ok(());
        };
        let mut access: LocalWriteAccess =
            serde_json::from_str(&raw).map_err(|err| ClientError::InvalidState(err.to_string()))?;
        if access.entitlement.is_none() && !access.revoked {
            return Ok(());
        }
        let session = self.load_session_info().await?;
        if session.expires_at.is_none_or(|expiry| expiry <= Utc::now())
            || session.user_id.map(|id| id.to_string()).as_deref() != Some(access.user_id.as_str())
        {
            return Ok(());
        }
        let Some(server) = session.server_url else {
            return Ok(());
        };
        let server = server.trim_end_matches('/').trim_end_matches("/api/v1");
        if server != access.issuer {
            return Ok(());
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        let response = http
            .get(format!("{server}/api/v1/organizations/me"))
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        if !response.status().is_success() {
            return Ok(());
        }
        let org: Option<serde_json::Value> = response
            .json()
            .await
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        let active = org
            .as_ref()
            .is_some_and(|org| org["license_status"] == "active");
        if active {
            let keys =
                crate::entitlement::trusted_keys_from_build().map_err(ClientError::InvalidState)?;
            let claims = access.entitlement.as_deref().and_then(|token| {
                crate::entitlement::verify(
                    token,
                    &keys,
                    server,
                    &access.user_id,
                    Utc::now().timestamp(),
                )
                .ok()
            });
            let org = org.as_ref().unwrap();
            let fresh = claims.is_some_and(|claims| {
                Some(claims.organization_id.as_str()) == org["id"].as_str()
                    && Some(claims.entitlement_version) == org["entitlement_version"].as_i64()
                    && Some(claims.max_members as u64) == org["seat_limit"].as_u64()
                    && claims.exp - Utc::now().timestamp() > 7 * 24 * 60 * 60
            });
            if !fresh {
                let response = http
                    .get(format!("{server}/api/v1/organizations/me/entitlement"))
                    .bearer_auth(&session.token)
                    .send()
                    .await
                    .map_err(|err| ClientError::InvalidState(err.to_string()))?;
                if !response.status().is_success() {
                    return Ok(());
                }
                let value: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|err| ClientError::InvalidState(err.to_string()))?;
                let token = value["token"]
                    .as_str()
                    .ok_or_else(|| ClientError::InvalidState("Missing entitlement".into()))?;
                let claims = crate::entitlement::verify(
                    token,
                    &keys,
                    server,
                    &access.user_id,
                    Utc::now().timestamp(),
                )
                .map_err(ClientError::InvalidState)?;
                if Some(claims.organization_id.as_str()) != org["id"].as_str()
                    || Some(claims.entitlement_version) != org["entitlement_version"].as_i64()
                    || Some(claims.max_members as u64) != org["seat_limit"].as_u64()
                {
                    return Err(ClientError::InvalidState(
                        "Entitlement does not match organization".into(),
                    ));
                }
                access.entitlement = Some(token.to_string());
            }
            access.revoked = false;
        } else {
            access.revoked = true;
        }
        // Keep server observations separate from a saved session so opening an
        // older session cannot erase a revocation learned by another process.
        self.storage
            .store_config(
                "local_server_write_access",
                &serde_json::to_string(&access)
                    .map_err(|err| ClientError::InvalidState(err.to_string()))?,
            )
            .await?;
        let response = http
            .get(format!("{server}/api/v1/groups"))
            .bearer_auth(&session.token)
            .send()
            .await
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        if !response.status().is_success() {
            return Ok(());
        }
        let value: serde_json::Value = response
            .json()
            .await
            .map_err(|err| ClientError::InvalidState(err.to_string()))?;
        let Some(groups) = value["groups"].as_array() else {
            return Ok(());
        };
        let mut cache: serde_json::Value = self
            .storage
            .load_config_fresh("group_metadata_cache")
            .await?
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_else(|| serde_json::json!({"by_id":{}}));
        let Some(by_id) = cache["by_id"].as_object_mut() else {
            return Ok(());
        };
        for entry in by_id.values_mut() {
            entry["role"] = serde_json::json!("removed");
        }
        for group in groups {
            if let Some(id) = group["id"].as_str() {
                let entry = by_id
                    .entry(id.to_string())
                    .or_insert_with(|| serde_json::json!({}));
                entry["organization_id"] = group["organization_id"].clone();
                entry["organization_known"] = serde_json::json!(true);
                entry["role"] = group["role"].clone();
                entry["name"] = group["name"].clone();
            }
        }
        self.storage
            .store_config("group_metadata_cache", &cache.to_string())
            .await?;
        Ok(())
    }
}
