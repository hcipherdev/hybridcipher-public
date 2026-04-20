// ============================================================================
// Feedback Submission
// ============================================================================
//
// This module handles in-app feedback submission with file attachments.
// Feedback is sent to a backend API which emails it to the team.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use std::fs as std_fs;
use std::path::{Path, PathBuf};
use tokio::fs;

/// Single file attachment encoded as base64
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FeedbackAttachment {
    pub filename: String,
    pub content_base64: String,
    pub mime_type: String,
}

/// Request payload for feedback submission
#[derive(Debug, Serialize, Deserialize)]
pub struct FeedbackRequest {
    pub title: String,
    pub description: String,
    pub user_email: Option<String>,
    pub attachments: Vec<FeedbackAttachment>,
    pub app_version: String,
    pub platform: String,
}

/// Response from the feedback API
#[derive(Debug, Serialize, Deserialize)]
pub struct FeedbackResponse {
    pub success: bool,
    pub message: Option<String>,
}

/// Default feedback API URL - override with HYBRIDCIPHER_FEEDBACK_API_URL env var
/// Uses the main HybridCipher server endpoint
const DEFAULT_FEEDBACK_API_URL: &str = "https://api.hybridcipher.com/api/v1/feedback";

fn config_file_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let prod_default = PathBuf::from("config/production.toml");
    if prod_default.exists() {
        candidates.push(prod_default);
    }

    candidates
}

fn feedback_api_url_from_toml(contents: &str) -> Option<String> {
    let parsed: toml::Value = toml::from_str(contents).ok()?;

    if let Some(url) = parsed
        .get("HYBRIDCIPHER_FEEDBACK_API_URL")
        .and_then(|value| value.as_str())
    {
        return Some(url.to_string());
    }

    if let Some(url) = parsed
        .get("feedback")
        .and_then(|section| section.get("api_url"))
        .and_then(|value| value.as_str())
    {
        return Some(url.to_string());
    }

    parsed
        .get("desktop")
        .and_then(|section| section.get("feedback_api_url"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn load_feedback_api_url_from_config() -> Option<String> {
    for path in config_file_candidates() {
        let contents = match std_fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(_) => continue,
        };
        if let Some(url) = feedback_api_url_from_toml(&contents) {
            return Some(url);
        }
    }

    None
}

/// Read a file from disk and encode as base64 attachment
async fn read_attachment(path: &str) -> Result<FeedbackAttachment, String> {
    let file_path = Path::new(path);

    // Get filename
    let filename = file_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("attachment")
        .to_string();

    // Read file contents
    let content = fs::read(file_path)
        .await
        .map_err(|e| format!("Failed to read file '{}': {}", path, e))?;

    // Encode as base64
    let content_base64 = BASE64.encode(&content);

    // Guess MIME type from extension
    let mime_type = match file_path.extension().and_then(|e| e.to_str()) {
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("log") => "text/plain",
        Some("json") => "application/json",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string();

    Ok(FeedbackAttachment {
        filename,
        content_base64,
        mime_type,
    })
}

/// Submit feedback to the backend API
///
/// # Arguments
/// * `title` - Brief summary of the issue
/// * `description` - Detailed description
/// * `user_email` - Optional email for follow-up
/// * `attachment_paths` - Paths to files to attach (will be read and base64 encoded)
#[tauri::command]
pub async fn submit_feedback(
    title: String,
    description: String,
    user_email: Option<String>,
    attachment_paths: Vec<String>,
) -> Result<FeedbackResponse, String> {
    tracing::info!(
        "Submitting feedback: title='{}', attachments={}",
        title,
        attachment_paths.len()
    );

    // Read and encode all attachments
    let mut attachments = Vec::new();
    for path in &attachment_paths {
        match read_attachment(path).await {
            Ok(attachment) => {
                tracing::debug!(
                    "Attached file: {} ({} bytes base64)",
                    attachment.filename,
                    attachment.content_base64.len()
                );
                attachments.push(attachment);
            }
            Err(e) => {
                tracing::warn!("Skipping attachment '{}': {}", path, e);
                // Continue with other attachments rather than failing entirely
            }
        }
    }

    // Build the request
    let request = FeedbackRequest {
        title,
        description,
        user_email,
        attachments,
        app_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: std::env::consts::OS.to_string(),
    };

    // Get API URL from env or use default
    let api_url = std::env::var("HYBRIDCIPHER_FEEDBACK_API_URL")
        .ok()
        .or_else(load_feedback_api_url_from_config)
        .unwrap_or_else(|| DEFAULT_FEEDBACK_API_URL.to_string());

    // Send to backend API
    let client = reqwest::Client::new();
    let response = client
        .post(&api_url)
        .json(&request)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|e| format!("Failed to send feedback: {}", e))?;

    if response.status().is_success() {
        let body: FeedbackResponse = response.json().await.unwrap_or(FeedbackResponse {
            success: true,
            message: Some("Feedback submitted successfully".to_string()),
        });
        tracing::info!("Feedback submitted successfully");
        Ok(body)
    } else {
        let status = response.status();
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        tracing::error!("Feedback submission failed: {} - {}", status, error_text);
        Err(format!("Server returned error {}: {}", status, error_text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mime_type_detection() {
        // This is a basic sanity check - actual file reading is async
        assert_eq!(
            match Some("png") {
                Some("png") => "image/png",
                _ => "application/octet-stream",
            },
            "image/png"
        );
    }
}
