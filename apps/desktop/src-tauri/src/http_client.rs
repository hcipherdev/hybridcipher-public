/// HTTP client for HybridCipher server API communication
// Handles authentication, retries, and error handling
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// HTTP client for server API calls
pub struct HttpClient {
    client: reqwest::Client,
    base_url: String,
    access_token: Option<String>,
}

impl HttpClient {
    /// Create a new HTTP client
    pub fn new(base_url: &str) -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

        Ok(Self {
            client,
            base_url: base_url.to_string(),
            access_token: None,
        })
    }

    /// Set access token for authenticated requests
    pub fn set_access_token(&mut self, token: String) {
        self.access_token = Some(token);
    }

    /// Clear access token
    pub fn clear_access_token(&mut self) {
        self.access_token = None;
    }

    /// Build full URL from path
    fn build_url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Make authenticated POST request
    pub async fn post<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &T,
    ) -> Result<R, String> {
        let url = self.build_url(path);

        let mut request = self.client.post(&url).json(body);

        // Add authorization header if token is available
        if let Some(token) = &self.access_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("HTTP POST failed: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("HTTP {} - {}", status, error_text));
        }

        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    }

    /// Make authenticated GET request
    pub async fn get<R: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<R, String> {
        let url = self.build_url(path);

        let mut request = self.client.get(&url);

        // Add authorization header if token is available
        if let Some(token) = &self.access_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("HTTP GET failed: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("HTTP {} - {}", status, error_text));
        }

        response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))
    }

    /// Make authenticated DELETE request
    pub async fn delete(&self, path: &str) -> Result<(), String> {
        let url = self.build_url(path);

        let mut request = self.client.delete(&url);

        // Add authorization header if token is available
        if let Some(token) = &self.access_token {
            request = request.header("Authorization", format!("Bearer {}", token));
        }

        let response = request
            .send()
            .await
            .map_err(|e| format!("HTTP DELETE failed: {}", e))?;

        let status = response.status();

        if !status.is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("HTTP {} - {}", status, error_text));
        }

        Ok(())
    }
}

// Server API request/response types (matching crates/server/src/handlers/groups.rs)

use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    pub settings: Option<GroupSettings>,
    pub initial_members: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GroupSettings {
    pub auto_rekey_enabled: bool,
    pub rekey_interval_days: Option<u32>,
    pub max_members: Option<u32>,
    pub require_admin_approval: bool,
    pub allow_member_invite: bool,
    pub file_retention_days: Option<u32>,
}

impl Default for GroupSettings {
    fn default() -> Self {
        Self {
            auto_rekey_enabled: false,
            rekey_interval_days: Some(90),
            max_members: Some(100),
            require_admin_approval: true,
            allow_member_invite: false,
            file_retention_days: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum GroupRole {
    Admin,
    Member,
    Viewer,
    #[serde(other)]
    Observer,
}

#[derive(Debug, Deserialize)]
pub struct GroupInfo {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub creator_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub current_epoch: Option<String>,
    pub member_count: u32,
    pub settings: GroupSettings,
    pub user_role: GroupRole,
    pub last_activity: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct GroupListResponse {
    pub groups: Vec<GroupInfo>,
    pub total_count: u32,
    pub has_more: bool,
    pub next_cursor: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_client_creation() {
        let client = HttpClient::new("https://api.example.com");
        assert!(client.is_ok());
    }

    #[test]
    fn test_token_management() {
        let mut client = HttpClient::new("https://api.example.com").unwrap();
        assert!(client.access_token.is_none());

        client.set_access_token("test_token".to_string());
        assert_eq!(client.access_token, Some("test_token".to_string()));

        client.clear_access_token();
        assert!(client.access_token.is_none());
    }
}
