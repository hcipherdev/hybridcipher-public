/// Tests for logging and metrics integration
///
/// Validates the structured logging and metrics collection systems
/// work correctly with the HybridCipher client operations.

#[cfg(test)]
mod tests {
    use crate::logging::{
        LogFormat, LogLevel, LogRotationConfig, LoggingConfig, PrivacyConfig, StructuredLogger,
    };
    use crate::metrics::{MetricsCollector, Timer};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::sleep;

    fn create_test_logging_config() -> LoggingConfig {
        LoggingConfig {
            level: LogLevel::Debug,
            enable_metrics: true,
            enable_security_logging: true,
            rotation: LogRotationConfig {
                max_file_size: 1024 * 1024,
                max_files: 3,
                compress: false,
            },
            format: LogFormat::Json,
            privacy: PrivacyConfig {
                log_user_ids: true,
                log_file_paths: false,
                redact_sensitive: true,
                max_string_length: 256,
            },
        }
    }

    #[tokio::test]
    async fn test_structured_logger_basic() {
        let config = create_test_logging_config();
        let logger = StructuredLogger::new(config, "test".to_string());

        // Test basic logging functionality
        logger.log(LogLevel::Info, "Test message", None);
        logger.log(LogLevel::Warn, "Warning message", None);
        logger.log(LogLevel::Error, "Error message", None);

        // Should not panic - basic smoke test
    }

    #[tokio::test]
    async fn test_metrics_collector_counters() {
        let collector = MetricsCollector::new();

        // Test counter operations
        collector.increment_counter("test_counter");
        collector.add_to_counter("test_counter", 5);

        // Verify counter values through export
        let json_metrics = collector.export_json_metrics().unwrap();
        assert!(json_metrics.contains("test_counter"));
    }

    #[tokio::test]
    async fn test_metrics_collector_gauges() {
        let collector = MetricsCollector::new();

        // Test gauge operations
        collector.set_gauge("cpu_usage", 45.2);
        collector.set_gauge("memory_usage", 78.9);

        // Test resource gauges
        collector.update_resource_gauge("active_connections", 12.0);

        // Export and verify
        let json_metrics = collector.export_json_metrics().unwrap();
        assert!(json_metrics.contains("cpu_usage"));
        assert!(json_metrics.contains("memory_usage"));
    }

    #[tokio::test]
    async fn test_metrics_collector_histograms() {
        let collector = Arc::new(MetricsCollector::new());

        // Test operation latency recording
        collector.record_operation_latency("file_read", Duration::from_millis(100));
        collector.record_operation_latency("file_read", Duration::from_millis(150));
        collector.record_operation_latency("file_read", Duration::from_millis(200));

        // Test timer functionality
        let timer = Timer::start("test_operation".to_string(), collector.clone());
        sleep(Duration::from_millis(10)).await;
        timer.stop();

        // Get stats
        let stats = collector.get_operation_latency_stats("file_read");
        assert!(stats.is_some());

        let stats = stats.unwrap();
        assert_eq!(stats.count, 3);
        assert!(stats.average > 0.0);
    }

    #[tokio::test]
    async fn test_metrics_collector_errors() {
        let collector = MetricsCollector::new();

        // Test error counting
        use crate::errors::ErrorCode;

        collector.increment_error_counter(ErrorCode::CryptoKeyGeneration);
        collector.increment_error_counter(ErrorCode::NetworkConnection);
        collector.increment_error_counter(ErrorCode::CryptoKeyGeneration);

        // Verify error counts
        assert_eq!(collector.get_error_count(ErrorCode::CryptoKeyGeneration), 2);
        assert_eq!(collector.get_error_count(ErrorCode::NetworkConnection), 1);
        assert_eq!(collector.get_total_error_count(), 3);
    }

    #[tokio::test]
    async fn test_metrics_prometheus_export() {
        let collector = MetricsCollector::new();

        // Add some test data
        collector.increment_counter("requests_total");
        collector.set_gauge("active_users", 42.0);
        collector.record_operation_latency("api_call", Duration::from_millis(250));

        // Export to Prometheus format
        let prometheus_output = collector.export_prometheus_metrics();

        // Verify format
        assert!(prometheus_output.contains("# HELP"));
        assert!(prometheus_output.contains("# TYPE"));
        assert!(prometheus_output.contains("uptime_seconds"));
    }

    #[tokio::test]
    async fn test_metrics_json_export() {
        let collector = MetricsCollector::new();

        // Add test data
        collector.set_gauge("test_metric", 123.45);
        collector.increment_counter("test_counter");

        // Export to JSON
        let json_output = collector.export_json_metrics().unwrap();

        // Verify it's valid JSON
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();

        // Check structure
        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("uptime_seconds").is_some());
        assert!(parsed.get("custom_gauges").is_some());
        assert!(parsed.get("custom_counters").is_some());
    }

    #[tokio::test]
    async fn test_group_metrics_update() {
        let collector = MetricsCollector::new();

        use crate::metrics::GroupMetrics;
        use std::collections::HashMap;

        let mut member_activity = HashMap::new();
        member_activity.insert("user1".to_string(), 0.85);
        member_activity.insert("user2".to_string(), 0.92);

        let group_metrics = GroupMetrics {
            group_size: 3,
            active_epochs: 2,
            total_files: 150,
            total_encrypted_bytes: 1024 * 1024 * 50, // 50MB
            average_file_size: 350.0 * 1024.0,       // 350KB
            rekey_frequency: 2.5,                    // per day
            member_activity,
        };

        collector.update_group_metrics(group_metrics);

        // Verify metrics were stored
        let retrieved = collector.get_group_metrics();
        assert_eq!(retrieved.group_size, 3);
        assert_eq!(retrieved.active_epochs, 2);
        assert_eq!(retrieved.total_files, 150);
    }

    #[tokio::test]
    async fn test_resource_metrics_update() {
        let collector = MetricsCollector::new();

        use crate::metrics::ResourceMetrics;

        let resource_metrics = ResourceMetrics {
            cpu_usage_percent: 45.2,
            memory_usage_bytes: 1024 * 1024 * 256, // 256MB
            memory_available_bytes: 1024 * 1024 * 1024 * 4, // 4GB
            disk_usage_bytes: 1024 * 1024 * 1024 * 10, // 10GB
            disk_available_bytes: 1024 * 1024 * 1024 * 50, // 50GB
            network_sent_bytes: 1024 * 1024 * 5,   // 5MB
            network_received_bytes: 1024 * 1024 * 12, // 12MB
        };

        collector.update_resource_metrics(resource_metrics);

        // Verify metrics were stored
        let retrieved = collector.get_resource_metrics();
        assert_eq!(retrieved.cpu_usage_percent, 45.2);
        assert_eq!(retrieved.memory_usage_bytes, 1024 * 1024 * 256);
    }

    #[tokio::test]
    async fn test_time_operation_macro() {
        use crate::metrics::get_metrics;
        use crate::time_operation;

        // Initialize global metrics
        let _metrics = crate::metrics::init_metrics();

        // Test the timing macro
        let result = time_operation!("test_macro_operation", {
            sleep(Duration::from_millis(50)).await;
            "success".to_string()
        });

        assert_eq!(result, "success");

        // Verify timing was recorded
        if let Some(metrics) = get_metrics() {
            let stats = metrics.get_operation_latency_stats("test_macro_operation");
            assert!(stats.is_some());

            let stats = stats.unwrap();
            assert_eq!(stats.count, 1);
            assert!(stats.average > 0.04); // Should be at least 40ms
        }
    }

    #[tokio::test]
    async fn test_concurrent_metrics_access() {
        let collector = Arc::new(MetricsCollector::new());
        let mut handles = Vec::new();

        // Spawn multiple tasks updating metrics concurrently
        for i in 0..10 {
            let collector_clone = collector.clone();
            let handle = tokio::spawn(async move {
                for j in 0..100 {
                    collector_clone.increment_counter(&format!("concurrent_counter_{}", i));
                    collector_clone.set_gauge(&format!("concurrent_gauge_{}", i), j as f64);
                    collector_clone.record_operation_latency(
                        "concurrent_operation",
                        Duration::from_micros(j * 10),
                    );
                }
            });
            handles.push(handle);
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.unwrap();
        }

        // Verify no panics occurred and metrics export works
        let json_output = collector.export_json_metrics().unwrap();
        assert!(json_output.contains("concurrent_counter"));
        assert!(json_output.contains("concurrent_gauge"));

        let prometheus_output = collector.export_prometheus_metrics();
        assert!(prometheus_output.contains("concurrent_operation"));
    }

    #[tokio::test]
    async fn test_error_recovery_logging() {
        let config = create_test_logging_config();
        let logger = StructuredLogger::new(config, "test".to_string());

        // Test error and recovery event logging
        logger.log(
            LogLevel::Error,
            "Operation failed: file_read",
            Some("file_read"),
        );
        logger.log(
            LogLevel::Info,
            "Retry initiated: file_read",
            Some("file_read"),
        );
        logger.log(
            LogLevel::Info,
            "Operation recovered: file_read",
            Some("file_read"),
        );

        // Should complete without errors
    }
}
