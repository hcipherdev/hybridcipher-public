//! Opportunistic rewrapping for background migration
//!
//! This module provides opportunistic file rewrapping functionality
//! that triggers during normal file access to accelerate migration.

use anyhow::Result;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Opportunistic rewrapping request
#[derive(Debug, Clone)]
pub struct RewrapRequest {
    pub file_id: String,
    pub from_epoch: String,
    pub to_epoch: String,
    pub priority: u8,
    pub triggered_by: TriggerSource,
    pub requested_at: SystemTime,
}

/// Source that triggered the rewrapping request
#[derive(Debug, Clone)]
pub enum TriggerSource {
    FileRead,
    FileWrite,
    DirectoryListing,
    Scheduled,
    Manual,
}

/// Opportunistic rewrapper for background migration
pub struct OpportunisticRewrapper<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
> {
    /// HybridCipher client for rewrapping operations
    client: Arc<hybridcipher_client::Client<S, N>>,

    /// Request queue for rewrapping
    request_queue: Arc<tokio::sync::Mutex<VecDeque<RewrapRequest>>>,

    /// Active rewrapping tasks
    active_tasks: Arc<tokio::sync::Mutex<std::collections::HashSet<String>>>,

    /// Completion notification channel
    completion_sender: mpsc::UnboundedSender<RewrapResult>,

    /// Maximum concurrent rewrapping operations
    max_concurrent: usize,

    /// Rate limiting configuration
    rate_limit_per_second: u32,
}

/// Result of a rewrapping operation
#[derive(Debug, Clone)]
pub struct RewrapResult {
    pub file_id: String,
    pub success: bool,
    pub error: Option<String>,
    pub duration: std::time::Duration,
    pub bytes_processed: u64,
}

impl<S: hybridcipher_client::storage::Storage, N: hybridcipher_client::network::Network>
    OpportunisticRewrapper<S, N>
{
    /// Create a new opportunistic rewrapper
    ///
    /// # Arguments
    ///
    /// * `client` - HybridCipher client for rewrapping operations
    /// * `max_concurrent` - Maximum concurrent rewrapping operations
    /// * `rate_limit_per_second` - Rate limit for rewrapping operations
    ///
    /// # Returns
    ///
    /// Returns a new opportunistic rewrapper instance
    pub async fn new(
        client: Arc<hybridcipher_client::Client<S, N>>,
        max_concurrent: usize,
        rate_limit_per_second: u32,
    ) -> Result<(Self, mpsc::UnboundedReceiver<RewrapResult>)> {
        let (completion_sender, completion_receiver) = mpsc::unbounded_channel();

        let rewrapper = Self {
            client,
            request_queue: Arc::new(tokio::sync::Mutex::new(VecDeque::new())),
            active_tasks: Arc::new(tokio::sync::Mutex::new(std::collections::HashSet::new())),
            completion_sender,
            max_concurrent,
            rate_limit_per_second,
        };

        // Start background processor
        rewrapper.start_background_processor().await;

        Ok((rewrapper, completion_receiver))
    }

    /// Schedule a file for opportunistic rewrapping
    ///
    /// # Arguments
    ///
    /// * `file_id` - Unique identifier of the file
    /// * `from_epoch` - Source epoch ID
    /// * `to_epoch` - Target epoch ID
    /// * `priority` - Rewrapping priority (1-10, higher is more urgent)
    /// * `trigger_source` - What triggered this rewrapping request
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if successfully scheduled
    pub async fn schedule_rewrap(
        &self,
        file_id: String,
        from_epoch: String,
        to_epoch: String,
        priority: u8,
        trigger_source: TriggerSource,
    ) -> Result<()> {
        debug!(
            "Scheduling rewrap for file {} from {} to {} (priority: {})",
            file_id, from_epoch, to_epoch, priority
        );

        // Check if already active or queued
        {
            let active_tasks = self.active_tasks.lock().await;
            if active_tasks.contains(&file_id) {
                debug!("File {} already being rewrapped", file_id);
                return Ok(());
            }
        }

        {
            let queue = self.request_queue.lock().await;
            if queue.iter().any(|req| req.file_id == file_id) {
                debug!("File {} already queued for rewrapping", file_id);
                return Ok(());
            }
        }

        let request = RewrapRequest {
            file_id,
            from_epoch,
            to_epoch,
            priority: priority.clamp(1, 10),
            triggered_by: trigger_source,
            requested_at: SystemTime::now(),
        };

        // Insert into queue maintaining priority order
        {
            let mut queue = self.request_queue.lock().await;

            // Find insertion point to maintain priority order
            let insert_pos = queue
                .iter()
                .position(|req| req.priority < request.priority)
                .unwrap_or(queue.len());

            queue.insert(insert_pos, request);
        }

        info!("Rewrap scheduled successfully");
        Ok(())
    }

    /// Start background processor for rewrapping queue
    async fn start_background_processor(&self) {
        let client = self.client.clone();
        let request_queue = self.request_queue.clone();
        let active_tasks = self.active_tasks.clone();
        let completion_sender = self.completion_sender.clone();
        let max_concurrent = self.max_concurrent;
        let rate_limit = self.rate_limit_per_second;

        tokio::spawn(async move {
            let mut rate_limiter =
                tokio::time::interval(std::time::Duration::from_millis(1000 / rate_limit as u64));

            loop {
                rate_limiter.tick().await;

                // Check if we can start more tasks
                let current_active = {
                    let active = active_tasks.lock().await;
                    active.len()
                };

                if current_active >= max_concurrent {
                    continue;
                }

                // Get next request from queue
                let request = {
                    let mut queue = request_queue.lock().await;
                    queue.pop_front()
                };

                if let Some(req) = request {
                    // Mark as active
                    {
                        let mut active = active_tasks.lock().await;
                        active.insert(req.file_id.clone());
                    }

                    // Start rewrapping task
                    let client_clone = client.clone();
                    let active_tasks_clone = active_tasks.clone();
                    let completion_sender_clone = completion_sender.clone();

                    tokio::spawn(async move {
                        let result = Self::perform_rewrap(client_clone, &req).await;

                        // Remove from active tasks
                        {
                            let mut active = active_tasks_clone.lock().await;
                            active.remove(&req.file_id);
                        }

                        // Send completion notification
                        let _ = completion_sender_clone.send(result);
                    });
                }
            }
        });
    }

    /// Perform the actual rewrapping operation
    async fn perform_rewrap(
        client: Arc<hybridcipher_client::Client<S, N>>,
        request: &RewrapRequest,
    ) -> RewrapResult {
        let start_time = SystemTime::now();

        debug!(
            "Starting rewrap for file {} from {} to {}",
            request.file_id, request.from_epoch, request.to_epoch
        );

        match client
            .rewrap_file_header_only(&request.file_id, &request.from_epoch, &request.to_epoch)
            .await
        {
            Ok(bytes_processed) => {
                let duration = SystemTime::now()
                    .duration_since(start_time)
                    .unwrap_or_default();

                info!(
                    "Successfully rewrapped file {} ({} bytes in {:?})",
                    request.file_id, bytes_processed, duration
                );

                RewrapResult {
                    file_id: request.file_id.clone(),
                    success: true,
                    error: None,
                    duration,
                    bytes_processed,
                }
            }
            Err(e) => {
                let duration = SystemTime::now()
                    .duration_since(start_time)
                    .unwrap_or_default();

                warn!("Failed to rewrap file {}: {}", request.file_id, e);

                RewrapResult {
                    file_id: request.file_id.clone(),
                    success: false,
                    error: Some(e.to_string()),
                    duration,
                    bytes_processed: 0,
                }
            }
        }
    }

    /// Get current queue statistics
    ///
    /// # Returns
    ///
    /// Returns queue statistics for monitoring
    pub async fn get_queue_stats(&self) -> QueueStats {
        let queue = self.request_queue.lock().await;
        let active_tasks = self.active_tasks.lock().await;

        let mut priority_counts = [0u32; 10]; // Index 0 = priority 1, etc.
        for request in queue.iter() {
            if request.priority >= 1 && request.priority <= 10 {
                priority_counts[(request.priority - 1) as usize] += 1;
            }
        }

        QueueStats {
            queued_requests: queue.len(),
            active_requests: active_tasks.len(),
            priority_counts,
            max_concurrent: self.max_concurrent,
            rate_limit_per_second: self.rate_limit_per_second,
        }
    }

    /// Clear all queued requests (keep active ones running)
    ///
    /// # Returns
    ///
    /// Returns number of requests cleared
    pub async fn clear_queue(&self) -> usize {
        let mut queue = self.request_queue.lock().await;
        let cleared_count = queue.len();
        queue.clear();

        info!("Cleared {} requests from rewrap queue", cleared_count);
        cleared_count
    }

    /// Pause all rewrapping operations
    pub async fn pause(&self) {
        // Implementation would pause the background processor
        warn!("Rewrapping paused (not fully implemented)");
    }

    /// Resume rewrapping operations  
    pub async fn resume(&self) {
        // Implementation would resume the background processor
        info!("Rewrapping resumed (not fully implemented)");
    }
}

/// Queue statistics for monitoring
#[derive(Debug, Clone)]
pub struct QueueStats {
    pub queued_requests: usize,
    pub active_requests: usize,
    pub priority_counts: [u32; 10], // Count per priority level (1-10)
    pub max_concurrent: usize,
    pub rate_limit_per_second: u32,
}

impl QueueStats {
    /// Get total requests (queued + active)
    pub fn total_requests(&self) -> usize {
        self.queued_requests + self.active_requests
    }

    /// Get highest priority in queue
    pub fn highest_priority(&self) -> Option<u8> {
        for (i, &count) in self.priority_counts.iter().enumerate().rev() {
            if count > 0 {
                return Some((i + 1) as u8);
            }
        }
        None
    }

    /// Get average priority in queue
    pub fn average_priority(&self) -> Option<f64> {
        let total_weighted: u32 = self
            .priority_counts
            .iter()
            .enumerate()
            .map(|(i, &count)| (i as u32 + 1) * count)
            .sum();

        let total_count: u32 = self.priority_counts.iter().sum();

        if total_count > 0 {
            Some(total_weighted as f64 / total_count as f64)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rewrap_request_creation() {
        let request = RewrapRequest {
            file_id: "test_file".to_string(),
            from_epoch: "epoch1".to_string(),
            to_epoch: "epoch2".to_string(),
            priority: 5,
            triggered_by: TriggerSource::FileRead,
            requested_at: SystemTime::now(),
        };

        assert_eq!(request.file_id, "test_file");
        assert_eq!(request.priority, 5);
        matches!(request.triggered_by, TriggerSource::FileRead);
    }

    #[test]
    fn test_queue_stats() {
        let stats = QueueStats {
            queued_requests: 10,
            active_requests: 5,
            priority_counts: [1, 2, 3, 2, 1, 1, 0, 0, 0, 0],
            max_concurrent: 8,
            rate_limit_per_second: 10,
        };

        assert_eq!(stats.total_requests(), 15);
        assert_eq!(stats.highest_priority(), Some(6));

        let avg_priority = stats.average_priority().unwrap();
        assert!(avg_priority > 2.0 && avg_priority < 4.0);
    }
}
