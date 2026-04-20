use serde::{Deserialize, Serialize};
/// Error Recovery and Circuit Breaker System
///
/// Implements sophisticated error recovery strategies, circuit breakers,
/// and retry mechanisms for production-grade fault tolerance.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time::sleep;

use crate::errors::{ClientError, ErrorCode, RecoveryAction};

/// Retry policy configuration for different error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts
    pub max_attempts: u32,

    /// Base delay between retries
    pub base_delay: Duration,

    /// Maximum delay between retries
    pub max_delay: Duration,

    /// Exponential backoff multiplier
    pub backoff_multiplier: f64,

    /// Jitter factor to prevent thundering herd
    pub jitter_factor: f64,

    /// Whether to use exponential backoff
    pub exponential_backoff: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            jitter_factor: 0.1,
            exponential_backoff: true,
        }
    }
}

impl RetryPolicy {
    /// Calculate delay for a specific retry attempt
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        let mut delay = if self.exponential_backoff {
            Duration::from_millis(
                (self.base_delay.as_millis() as f64 * self.backoff_multiplier.powi(attempt as i32))
                    as u64,
            )
        } else {
            self.base_delay
        };

        // Apply maximum delay limit
        if delay > self.max_delay {
            delay = self.max_delay;
        }

        // Add jitter to prevent thundering herd
        if self.jitter_factor > 0.0 {
            let jitter =
                (delay.as_millis() as f64 * self.jitter_factor * rand::random::<f64>()) as u64;
            delay = Duration::from_millis(delay.as_millis() as u64 + jitter);
        }

        delay
    }

    /// Create a policy for network operations
    pub fn for_network() -> Self {
        Self {
            max_attempts: 5,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(60),
            backoff_multiplier: 2.0,
            jitter_factor: 0.2,
            exponential_backoff: true,
        }
    }

    /// Create a policy for storage operations
    pub fn for_storage() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            backoff_multiplier: 1.5,
            jitter_factor: 0.1,
            exponential_backoff: true,
        }
    }

    /// Create a policy for cryptographic operations
    pub fn for_crypto() -> Self {
        Self {
            max_attempts: 2,
            base_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(5),
            backoff_multiplier: 2.0,
            jitter_factor: 0.0, // No jitter for crypto operations
            exponential_backoff: false,
        }
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    /// Circuit is closed, allowing all requests
    Closed,
    /// Circuit is open, rejecting all requests
    Open,
    /// Circuit is half-open, allowing limited requests to test recovery
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open the circuit
    pub failure_threshold: u32,

    /// Success threshold to close the circuit from half-open
    pub success_threshold: u32,

    /// Time to wait before trying half-open state
    pub timeout: Duration,

    /// Rolling window for failure counting
    pub rolling_window: Duration,

    /// Maximum number of concurrent requests in half-open state
    pub half_open_max_calls: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout: Duration::from_secs(60),
            rolling_window: Duration::from_secs(120),
            half_open_max_calls: 3,
        }
    }
}

/// Circuit breaker implementation
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: CircuitBreakerState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
    half_open_calls: u32,
    failure_times: Vec<Instant>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with configuration
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure_time: None,
            half_open_calls: 0,
            failure_times: Vec::new(),
        }
    }

    /// Check if a call should be allowed through the circuit breaker
    pub fn allow_request(&mut self) -> bool {
        self.update_state();

        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => false,
            CircuitBreakerState::HalfOpen => {
                if self.half_open_calls < self.config.half_open_max_calls {
                    self.half_open_calls += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful operation
    pub fn record_success(&mut self) {
        match self.state {
            CircuitBreakerState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.config.success_threshold {
                    self.state = CircuitBreakerState::Closed;
                    self.reset_counts();
                }
            }
            CircuitBreakerState::Closed => {
                // Reset failure count on success
                if self.failure_count > 0 {
                    self.failure_count = 0;
                    self.failure_times.clear();
                }
            }
            CircuitBreakerState::Open => {
                // Should not happen, but handle gracefully
            }
        }
    }

    /// Record a failed operation
    pub fn record_failure(&mut self) {
        let now = Instant::now();
        self.last_failure_time = Some(now);

        // Add to rolling window
        self.failure_times.push(now);
        self.clean_old_failures(now);

        self.failure_count = self.failure_times.len() as u32;

        match self.state {
            CircuitBreakerState::Closed => {
                if self.failure_count >= self.config.failure_threshold {
                    self.state = CircuitBreakerState::Open;
                    self.half_open_calls = 0;
                }
            }
            CircuitBreakerState::HalfOpen => {
                self.state = CircuitBreakerState::Open;
                self.success_count = 0;
                self.half_open_calls = 0;
            }
            CircuitBreakerState::Open => {
                // Already open, nothing to do
            }
        }
    }

    /// Update circuit breaker state based on time
    fn update_state(&mut self) {
        if self.state == CircuitBreakerState::Open {
            if let Some(last_failure) = self.last_failure_time {
                if last_failure.elapsed() >= self.config.timeout {
                    self.state = CircuitBreakerState::HalfOpen;
                    self.success_count = 0;
                    self.half_open_calls = 0;
                }
            }
        }

        // Clean old failures from rolling window
        let now = Instant::now();
        self.clean_old_failures(now);
        self.failure_count = self.failure_times.len() as u32;
    }

    /// Remove failures outside the rolling window
    fn clean_old_failures(&mut self, now: Instant) {
        self.failure_times
            .retain(|&failure_time| now.duration_since(failure_time) <= self.config.rolling_window);
    }

    /// Reset counters and state
    fn reset_counts(&mut self) {
        self.failure_count = 0;
        self.success_count = 0;
        self.half_open_calls = 0;
        self.failure_times.clear();
    }

    /// Get current state
    pub fn state(&self) -> CircuitBreakerState {
        self.state
    }

    /// Get current metrics
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        CircuitBreakerMetrics {
            state: self.state,
            failure_count: self.failure_count,
            success_count: self.success_count,
            half_open_calls: self.half_open_calls,
        }
    }
}

/// Circuit breaker metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerMetrics {
    pub state: CircuitBreakerState,
    pub failure_count: u32,
    pub success_count: u32,
    pub half_open_calls: u32,
}

/// Central error recovery manager
pub struct ErrorRecoveryManager {
    retry_policies: HashMap<ErrorCode, RetryPolicy>,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreaker>>>,
    recovery_metrics: Arc<Mutex<RecoveryMetrics>>,
}

/// Recovery operation metrics
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    pub total_retries: u64,
    pub successful_retries: u64,
    pub failed_retries: u64,
    pub circuit_breaker_trips: u64,
    pub recovery_time_ms: Vec<u64>,
}

impl ErrorRecoveryManager {
    /// Create a new error recovery manager with default policies
    pub fn new() -> Self {
        let mut retry_policies = HashMap::new();

        // Configure retry policies for different error codes
        retry_policies.insert(ErrorCode::NetworkConnection, RetryPolicy::for_network());
        retry_policies.insert(ErrorCode::NetworkTimeout, RetryPolicy::for_network());
        retry_policies.insert(ErrorCode::StorageRead, RetryPolicy::for_storage());
        retry_policies.insert(ErrorCode::StorageWrite, RetryPolicy::for_storage());
        retry_policies.insert(ErrorCode::CryptoEncryption, RetryPolicy::for_crypto());
        retry_policies.insert(ErrorCode::CryptoDecryption, RetryPolicy::for_crypto());

        Self {
            retry_policies,
            circuit_breakers: Arc::new(Mutex::new(HashMap::new())),
            recovery_metrics: Arc::new(Mutex::new(RecoveryMetrics::default())),
        }
    }

    /// Get or create circuit breaker for a service
    fn get_circuit_breaker(&self, service_name: &str) -> Arc<Mutex<CircuitBreaker>> {
        let mut breakers = self.circuit_breakers.lock().unwrap();

        if !breakers.contains_key(service_name) {
            let config = match service_name {
                "network" => CircuitBreakerConfig {
                    failure_threshold: 10,
                    timeout: Duration::from_secs(30),
                    ..Default::default()
                },
                "storage" => CircuitBreakerConfig {
                    failure_threshold: 5,
                    timeout: Duration::from_secs(10),
                    ..Default::default()
                },
                _ => CircuitBreakerConfig::default(),
            };

            breakers.insert(service_name.to_string(), CircuitBreaker::new(config));
        }

        Arc::new(Mutex::new(breakers.get(service_name).unwrap().clone()))
    }

    /// Handle error with appropriate recovery strategy
    pub async fn handle_error(&self, error: &ClientError) -> Result<RecoveryAction, ClientError> {
        if let Some(context) = error.context() {
            let service_name = self.extract_service_name(&context.operation);
            let circuit_breaker = self.get_circuit_breaker(&service_name);

            // Record failure in circuit breaker
            {
                let mut breaker = circuit_breaker.lock().unwrap();
                breaker.record_failure();

                if breaker.state() == CircuitBreakerState::Open {
                    let mut metrics = self.recovery_metrics.lock().unwrap();
                    metrics.circuit_breaker_trips += 1;

                    return Ok(RecoveryAction::Abort {
                        safe_cleanup: true,
                        user_notification: format!(
                            "Service {} is temporarily unavailable. Please try again later.",
                            service_name
                        ),
                    });
                }
            }

            Ok(context.recovery_action.clone())
        } else {
            // Legacy error handling
            Ok(RecoveryAction::Abort {
                safe_cleanup: true,
                user_notification: "Operation failed. Please try again.".to_string(),
            })
        }
    }

    /// Check if operation should be retried
    pub fn should_retry(&self, error: &ClientError) -> bool {
        if let Some(context) = error.context() {
            let policy = self.retry_policies.get(&context.code);
            policy.is_some() && context.code.is_retryable()
        } else {
            error.is_retryable()
        }
    }

    /// Execute operation with retry and circuit breaker protection
    pub async fn execute_with_retry<T, F, Fut>(
        &self,
        operation_name: &str,
        operation: F,
    ) -> Result<T, ClientError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        let service_name = self.extract_service_name(operation_name);
        let circuit_breaker = self.get_circuit_breaker(&service_name);

        // Check circuit breaker
        {
            let mut breaker = circuit_breaker.lock().unwrap();
            if !breaker.allow_request() {
                return Err(ClientError::network_error(
                    ErrorCode::NetworkConnection,
                    "Service temporarily unavailable (circuit breaker open)".to_string(),
                    operation_name.to_string(),
                    0,
                    "circuit_breaker_open".to_string(),
                ));
            }
        }

        let start_time = Instant::now();
        let mut attempt = 0;

        loop {
            let result = operation().await;

            match result {
                Ok(value) => {
                    // Record success
                    {
                        let mut breaker = circuit_breaker.lock().unwrap();
                        breaker.record_success();
                    }

                    // Update metrics
                    {
                        let mut metrics = self.recovery_metrics.lock().unwrap();
                        if attempt > 0 {
                            metrics.successful_retries += 1;
                            metrics
                                .recovery_time_ms
                                .push(start_time.elapsed().as_millis() as u64);
                        }
                    }

                    return Ok(value);
                }
                Err(error) => {
                    attempt += 1;

                    // Check if we should retry
                    if !self.should_retry(&error) {
                        {
                            let mut breaker = circuit_breaker.lock().unwrap();
                            breaker.record_failure();
                        }
                        return Err(error);
                    }

                    // Get retry policy
                    let default_policy = RetryPolicy::default();
                    let policy = if let Some(context) = error.context() {
                        self.retry_policies
                            .get(&context.code)
                            .unwrap_or(&default_policy)
                    } else {
                        &default_policy
                    };

                    // Check if we've exceeded retry attempts
                    if attempt >= policy.max_attempts {
                        {
                            let mut breaker = circuit_breaker.lock().unwrap();
                            breaker.record_failure();
                        }

                        {
                            let mut metrics = self.recovery_metrics.lock().unwrap();
                            metrics.failed_retries += 1;
                        }

                        return Err(error);
                    }

                    // Calculate delay and wait
                    let delay = policy.calculate_delay(attempt - 1);
                    sleep(delay).await;

                    {
                        let mut metrics = self.recovery_metrics.lock().unwrap();
                        metrics.total_retries += 1;
                    }
                }
            }
        }
    }

    /// Extract service name from operation for circuit breaker identification
    fn extract_service_name(&self, operation: &str) -> String {
        if operation.contains("network") || operation.contains("connect") {
            "network".to_string()
        } else if operation.contains("storage")
            || operation.contains("store")
            || operation.contains("read")
        {
            "storage".to_string()
        } else if operation.contains("crypto")
            || operation.contains("encrypt")
            || operation.contains("decrypt")
        {
            "crypto".to_string()
        } else {
            "default".to_string()
        }
    }

    /// Get current recovery metrics
    pub fn get_metrics(&self) -> RecoveryMetrics {
        self.recovery_metrics.lock().unwrap().clone()
    }

    /// Get circuit breaker metrics for all services
    pub fn get_circuit_breaker_metrics(&self) -> HashMap<String, CircuitBreakerMetrics> {
        let breakers = self.circuit_breakers.lock().unwrap();
        breakers
            .iter()
            .map(|(name, breaker)| (name.clone(), breaker.metrics()))
            .collect()
    }

    /// Reset all metrics and circuit breakers
    pub fn reset(&self) {
        {
            let mut metrics = self.recovery_metrics.lock().unwrap();
            *metrics = RecoveryMetrics::default();
        }

        {
            let mut breakers = self.circuit_breakers.lock().unwrap();
            breakers.clear();
        }
    }
}

impl Default for ErrorRecoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Global error recovery manager instance
static RECOVERY_MANAGER: std::sync::OnceLock<ErrorRecoveryManager> = std::sync::OnceLock::new();

/// Get the global error recovery manager
pub fn get_recovery_manager() -> &'static ErrorRecoveryManager {
    RECOVERY_MANAGER.get_or_init(ErrorRecoveryManager::new)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_retry_policy_calculation() {
        let policy = RetryPolicy::default();

        let delay1 = policy.calculate_delay(0);
        let delay2 = policy.calculate_delay(1);
        let delay3 = policy.calculate_delay(2);

        assert!(delay2 > delay1);
        assert!(delay3 > delay2);
        assert!(delay3 <= policy.max_delay);
    }

    #[tokio::test]
    async fn test_circuit_breaker_states() {
        let mut breaker = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            timeout: Duration::from_millis(100),
            ..Default::default()
        });

        // Initial state should be closed
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
        assert!(breaker.allow_request());

        // Record failures to open circuit
        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);

        breaker.record_failure();
        assert_eq!(breaker.state(), CircuitBreakerState::Open);
        assert!(!breaker.allow_request());

        // Wait for timeout
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(breaker.allow_request()); // Should be half-open now

        // Record success to close circuit
        breaker.record_success();
        assert_eq!(breaker.state(), CircuitBreakerState::Closed);
    }

    #[tokio::test]
    async fn test_error_recovery_manager() {
        let manager = ErrorRecoveryManager::new();
        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = manager
            .execute_with_retry("test_operation", || {
                let counter = counter_clone.clone();
                async move {
                    let count = counter.fetch_add(1, Ordering::SeqCst);
                    if count < 2 {
                        Err(ClientError::network_error(
                            ErrorCode::NetworkTimeout,
                            "Timeout".to_string(),
                            "test".to_string(),
                            count,
                            "testing".to_string(),
                        ))
                    } else {
                        Ok("success")
                    }
                }
            })
            .await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "success");
        assert_eq!(counter.load(Ordering::SeqCst), 3); // Two failures + one success
    }
}
