use super::*;

/// A group key version this device confirmed to the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReceiptReport {
    pub group_id: Uuid,
    pub version: u64,
}

/// Outcome of one key receipt pass over all of this device's groups.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyReceiptReports {
    pub reported: Vec<KeyReceiptReport>,
    /// Groups whose key version could not be confirmed this time; the caller retries sooner.
    pub failed_groups: usize,
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Tell the server which key version this device holds for each of its groups, so
    /// admins can see which devices picked up a rotation. A missing current key is
    /// fetched first, which is how a device catches up after a rotation.
    pub async fn report_key_receipts(&self) -> Result<KeyReceiptReports, ClientError> {
        self.ensure_state_loaded().await?;
        let auth_token = self.get_auth_token().await?;
        let mut reports = KeyReceiptReports::default();
        for group in self.fetch_group_list(&auth_token).await? {
            match self.report_key_receipt_for_group(group.id, &auth_token).await {
                Ok(Some(version)) => reports.reported.push(KeyReceiptReport {
                    group_id: group.id,
                    version,
                }),
                Ok(None) => {}
                Err(err) => {
                    reports.failed_groups += 1;
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("Could not confirm the key version for group {}: {}", group.name, err),
                        Some(&group.id.to_string()),
                    );
                }
            }
        }
        Ok(reports)
    }

    async fn report_key_receipt_for_group(
        &self,
        group_id: Uuid,
        auth_token: &str,
    ) -> Result<Option<u64>, ClientError> {
        let Some(response) = self
            .fetch_server_welcome_messages_once(group_id, auth_token)
            .await?
        else {
            return Ok(None);
        };
        if !self.holds_verified_epoch(group_id, response.epoch_id).await {
            self.sync_welcome_messages_for_group(group_id).await?;
            if !self.holds_verified_epoch(group_id, response.epoch_id).await {
                return Ok(None);
            }
        }

        let server_url = self.active_server_base_url().await;
        let response_status = reqwest::Client::new()
            .post(format!("{}/api/v1/groups/{}/key-receipt", server_url, group_id))
            .bearer_auth(auth_token)
            .json(&serde_json::json!({ "epoch_id": response.epoch_uuid }))
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkConnection,
                    format!("Failed to confirm the group key version: {:?}", e),
                    "key_receipt_request".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "request_failed".to_string(),
            })?
            .status();
        if !response_status.is_success() {
            return Err(ClientError::NetworkError {
                context: ErrorContext::new(
                    ErrorCode::NetworkProtocol,
                    format!("Server rejected the key version receipt ({})", response_status),
                    "key_receipt_response".to_string(),
                ),
                retry_count: 0,
                last_attempt: std::time::SystemTime::now(),
                connection_state: "error_response".to_string(),
            });
        }
        Ok(Some(response.epoch_id))
    }

    async fn holds_verified_epoch(&self, group_id: Uuid, epoch_id: u64) -> bool {
        let state = self.state.read().await;
        Self::get_epoch_state(&state, group_id, epoch_id)
            .is_some_and(|epoch| epoch.key_source.is_verified())
    }

    /// Whether this device holds a usable key for the group's key `version`, so the app can
    /// tell a newer key it has not picked up yet without asking the server for Welcomes.
    pub async fn holds_group_key(&self, group_id: Uuid, version: u64) -> bool {
        let state = self.state.read().await;
        Self::get_epoch_state(&state, group_id, version)
            .is_some_and(|epoch| epoch.key_source.is_locally_usable())
    }
}

#[cfg(test)]
#[path = "../../../tests/rekey/test_holds_group_key.rs"]
mod holds_group_key_tests;
