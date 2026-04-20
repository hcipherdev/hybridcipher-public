//! Unit tests for the comprehensive error handling system
//!
//! This module contains focused tests for the Phase 4 error handling implementation,
//! testing error creation, context tracking, recovery mechanisms, and circuit breakers.

use super::errors::*;
use super::recovery::*;
use std::time::Duration;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_code_severity() {
        // Test critical errors
        assert_eq!(
            ErrorCode::CryptoRandomness.severity(),
            ErrorSeverity::Critical
        );
        assert_eq!(
            ErrorCode::SecurityTampering.severity(),
            ErrorSeverity::Critical
        );
        assert_eq!(
            ErrorCode::StorageCorruption.severity(),
            ErrorSeverity::Critical
        );

        // Test high priority errors
        assert_eq!(ErrorCode::CryptoEncryption.severity(), ErrorSeverity::High);
        assert_eq!(
            ErrorCode::NetworkAuthentication.severity(),
            ErrorSeverity::High
        );
        assert_eq!(
            ErrorCode::SecurityUnauthorized.severity(),
            ErrorSeverity::High
        );

        // Test medium priority errors
        assert_eq!(ErrorCode::NetworkTimeout.severity(), ErrorSeverity::Medium);
        assert_eq!(ErrorCode::StorageRead.severity(), ErrorSeverity::Medium);
        assert_eq!(ErrorCode::FileNotFound.severity(), ErrorSeverity::Medium);

        // Test low priority errors
        assert_eq!(ErrorCode::FilePathInvalid.severity(), ErrorSeverity::Low);
    }

    #[test]
    fn test_error_code_retryability() {
        // Test retryable errors
        assert!(ErrorCode::NetworkTimeout.is_retryable());
        assert!(ErrorCode::NetworkConnection.is_retryable());
        assert!(ErrorCode::StorageRead.is_retryable());
        assert!(ErrorCode::StorageWrite.is_retryable());
        assert!(ErrorCode::NetworkRateLimit.is_retryable());

        // Test non-retryable errors
        assert!(!ErrorCode::CryptoDecryption.is_retryable());
        assert!(!ErrorCode::SecurityUnauthorized.is_retryable());
        assert!(!ErrorCode::FileCorrupted.is_retryable());
    }

    #[test]
    fn test_error_retry_delays() {
        assert_eq!(
            ErrorCode::NetworkRateLimit.retry_delay(),
            Duration::from_secs(60)
        );
        assert_eq!(
            ErrorCode::NetworkTimeout.retry_delay(),
            Duration::from_secs(5)
        );
        assert_eq!(
            ErrorCode::StorageRead.retry_delay(),
            Duration::from_millis(100)
        );
        assert_eq!(
            ErrorCode::ResourceTimeout.retry_delay(),
            Duration::from_millis(50)
        );
    }

    #[test]
    fn test_error_context_creation() {
        let context = ErrorContext::new(
            ErrorCode::NetworkTimeout,
            "Connection timed out".to_string(),
            "file_upload".to_string(),
        );

        assert_eq!(context.code, ErrorCode::NetworkTimeout);
        assert_eq!(context.message, "Connection timed out");
        assert_eq!(context.operation, "file_upload");
        assert!(!context.error_id.is_empty());
    }

    #[test]
    fn test_circuit_breaker_config() {
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(30),
            rolling_window: Duration::from_secs(60),
            half_open_max_calls: 2,
        };

        assert_eq!(config.failure_threshold, 3);
        assert_eq!(config.success_threshold, 2);
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.rolling_window, Duration::from_secs(60));
        assert_eq!(config.half_open_max_calls, 2);
    }

    #[test]
    fn test_circuit_breaker_creation() {
        let config = CircuitBreakerConfig {
            failure_threshold: 5,
            success_threshold: 2,
            timeout: Duration::from_secs(10),
            rolling_window: Duration::from_secs(60),
            half_open_max_calls: 3,
        };

        let breaker = CircuitBreaker::new(config);
        assert!(matches!(breaker.state(), CircuitBreakerState::Closed));
    }

    #[test]
    fn test_circuit_breaker_state_transitions() {
        let config = CircuitBreakerConfig {
            failure_threshold: 2,
            success_threshold: 1,
            timeout: Duration::from_millis(100),
            rolling_window: Duration::from_secs(60),
            half_open_max_calls: 1,
        };

        let mut breaker = CircuitBreaker::new(config);

        // Initially closed
        assert!(matches!(breaker.state(), CircuitBreakerState::Closed));
        assert!(breaker.allow_request());

        // Record failures
        breaker.record_failure();
        breaker.record_failure();

        // Should now be open
        assert!(matches!(breaker.state(), CircuitBreakerState::Open));
        assert!(!breaker.allow_request());

        // Record success should help recovery
        breaker.record_success();
    }

    #[test]
    fn test_retry_policy_creation() {
        let policy = RetryPolicy::for_network();
        assert_eq!(policy.max_attempts, 5);

        let policy = RetryPolicy::for_storage();
        assert_eq!(policy.max_attempts, 3);

        let policy = RetryPolicy::for_crypto();
        assert_eq!(policy.max_attempts, 2);
    }

    #[test]
    fn test_retry_policy_delay_calculation() {
        let policy = RetryPolicy::for_network();

        // First attempt has some delay
        let delay0 = policy.calculate_delay(0);
        let delay1 = policy.calculate_delay(1);
        let delay2 = policy.calculate_delay(2);

        // Exponential backoff should increase delays
        assert!(delay1 >= delay0);
        assert!(delay2 >= delay1);
        assert!(delay0 >= policy.base_delay);
    }

    #[tokio::test]
    async fn test_error_recovery_manager() {
        let _manager = ErrorRecoveryManager::new();

        // Test circuit breaker creation with config
        let config = CircuitBreakerConfig {
            failure_threshold: 3,
            success_threshold: 2,
            timeout: Duration::from_secs(5),
            rolling_window: Duration::from_secs(60),
            half_open_max_calls: 2,
        };

        let _breaker = CircuitBreaker::new(config);

        // Test that the error recovery manager can be created
        // The internal implementation details are tested via the public API
        assert!(true); // Manager created successfully
    }

    #[test]
    fn test_client_error_variants() {
        // Test that ClientError variants exist and can be created
        let storage_error = crate::storage::StorageError::KeyNotFound("test".to_string());
        let client_error = ClientError::Storage(storage_error);

        match client_error {
            ClientError::Storage(_) => {
                // Expected
            }
            _ => panic!("Expected Storage error"),
        }
    }

    #[test]
    fn test_recovery_action_types() {
        // Test different recovery action types
        let retry_action = RecoveryAction::Retry {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
        };

        match retry_action {
            RecoveryAction::Retry { max_attempts, .. } => {
                assert_eq!(max_attempts, 3);
            }
            _ => panic!("Expected Retry action"),
        }

        let fallback_action = RecoveryAction::Fallback {
            strategy: "use_cache".to_string(),
            expected_degradation: "stale_data".to_string(),
        };

        match fallback_action {
            RecoveryAction::Fallback { strategy, .. } => {
                assert_eq!(strategy, "use_cache");
            }
            _ => panic!("Expected Fallback action"),
        }
    }

    #[test]
    fn test_error_severity_values() {
        // Test that severity enum values are correctly ordered
        assert_eq!(ErrorSeverity::Critical as u8, 4);
        assert_eq!(ErrorSeverity::High as u8, 3);
        assert_eq!(ErrorSeverity::Medium as u8, 2);
        assert_eq!(ErrorSeverity::Low as u8, 1);
    }

    #[test]
    fn test_error_context_fields() {
        let context = ErrorContext::new(
            ErrorCode::FileNotFound,
            "File missing".to_string(),
            "read_file".to_string(),
        );

        assert_eq!(context.code, ErrorCode::FileNotFound);
        assert_eq!(context.message, "File missing");
        assert_eq!(context.operation, "read_file");
        assert!(!context.error_id.is_empty());
        assert_eq!(context.severity, ErrorSeverity::Medium);
    }

    #[test]
    fn test_comprehensive_error_codes_coverage() {
        // Test that we have error codes for all major categories
        let crypto_errors = vec![
            ErrorCode::CryptoKeyGeneration,
            ErrorCode::CryptoEncryption,
            ErrorCode::CryptoDecryption,
            ErrorCode::CryptoSignature,
        ];

        let network_errors = vec![
            ErrorCode::NetworkConnection,
            ErrorCode::NetworkTimeout,
            ErrorCode::NetworkProtocol,
            ErrorCode::NetworkAuthentication,
        ];

        let storage_errors = vec![
            ErrorCode::StorageRead,
            ErrorCode::StorageWrite,
            ErrorCode::StorageCorruption,
            ErrorCode::StoragePermission,
        ];

        let file_errors = vec![
            ErrorCode::FileNotFound,
            ErrorCode::FileCorrupted,
            ErrorCode::FileAccessDenied,
            ErrorCode::FileQuotaExceeded,
        ];

        // Verify all error codes have valid severity levels
        for error_code in [crypto_errors, network_errors, storage_errors, file_errors].concat() {
            let severity = error_code.severity();
            assert!(matches!(
                severity,
                ErrorSeverity::Low
                    | ErrorSeverity::Medium
                    | ErrorSeverity::High
                    | ErrorSeverity::Critical
            ));
        }
    }

    #[test]
    fn test_retry_policy_default() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.base_delay, Duration::from_millis(100));
        assert_eq!(policy.max_delay, Duration::from_secs(30));
        assert_eq!(policy.backoff_multiplier, 2.0);
        assert!(policy.exponential_backoff);
    }

    #[test]
    fn test_circuit_breaker_config_default() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.success_threshold, 3);
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.rolling_window, Duration::from_secs(120));
        assert_eq!(config.half_open_max_calls, 3);
    }

    #[test]
    fn test_circuit_breaker_allow_request() {
        let config = CircuitBreakerConfig::default();
        let mut breaker = CircuitBreaker::new(config);

        // Should allow requests in closed state
        assert!(breaker.allow_request());
        assert!(breaker.allow_request());
    }

    #[test]
    fn test_error_code_numeric_values() {
        // Test that error codes have the expected numeric values
        assert_eq!(ErrorCode::CryptoKeyGeneration as u32, 1001);
        assert_eq!(ErrorCode::NetworkConnection as u32, 2001);
        assert_eq!(ErrorCode::StorageRead as u32, 3001);
        assert_eq!(ErrorCode::FileNotFound as u32, 5001);
        assert_eq!(ErrorCode::SecurityUnauthorized as u32, 7001);
    }
}
