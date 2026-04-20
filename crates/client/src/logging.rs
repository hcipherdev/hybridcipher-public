use serde::{Deserialize, Serialize};
/// Structured Logging System for HybridCipher Client
///
/// Provides comprehensive logging capabilities with JSON formatting,
/// security event tracking, and operational metrics collection.
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::errors::{ClientError, ErrorCode, ErrorSeverity};

/// Logging configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Minimum log level to record
    pub level: LogLevel,

    /// Whether to include performance metrics
    pub enable_metrics: bool,

    /// Whether to log security events
    pub enable_security_logging: bool,

    /// Log rotation configuration
    pub rotation: LogRotationConfig,

    /// Output format configuration
    pub format: LogFormat,

    /// Privacy settings
    pub privacy: PrivacyConfig,
}

/// Log levels for filtering
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Critical = 5,
}

/// Log output formats
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    /// Human-readable text format
    Text,
    /// JSON format for machine parsing
    Json,
    /// Compact JSON format
    CompactJson,
}

/// Log rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum log file size in bytes
    pub max_file_size: u64,

    /// Maximum number of rotated files to keep
    pub max_files: u32,

    /// Whether to compress rotated files
    pub compress: bool,
}

/// Privacy configuration for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// Whether to log user identifiers
    pub log_user_ids: bool,

    /// Whether to log file paths
    pub log_file_paths: bool,

    /// Whether to redact sensitive information
    pub redact_sensitive: bool,

    /// Maximum length for logged strings
    pub max_string_length: usize,
}

/// Structured log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp in RFC3339 format
    pub timestamp: String,

    /// Log level
    pub level: LogLevel,

    /// Log message
    pub message: String,

    /// Operation context
    pub operation: Option<String>,

    /// Correlation ID for tracing
    pub correlation_id: Option<String>,

    /// Component that generated the log
    pub component: String,

    /// Additional structured data
    pub fields: HashMap<String, LogValue>,

    /// Error information if applicable
    pub error: Option<LoggedError>,

    /// Performance metrics if applicable
    pub metrics: Option<PerformanceMetrics>,
}

/// Values that can be logged
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LogValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Null,
}

/// Error information for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggedError {
    /// Error code
    pub code: ErrorCode,

    /// Error severity
    pub severity: ErrorSeverity,

    /// Error message (potentially redacted)
    pub message: String,

    /// Whether the error is recoverable
    pub recoverable: bool,

    /// Error context
    pub context: HashMap<String, String>,
}

/// Performance metrics for logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Operation duration in milliseconds
    pub duration_ms: f64,

    /// CPU usage during operation
    pub cpu_usage: Option<f64>,

    /// Memory usage in bytes
    pub memory_usage: Option<u64>,

    /// Network bytes transferred
    pub network_bytes: Option<u64>,

    /// Storage bytes accessed
    pub storage_bytes: Option<u64>,
}

/// Security event types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityEvent {
    /// Authentication attempt
    AuthenticationAttempt {
        device_id: String,
        success: bool,
        method: String,
        client_info: Option<String>,
    },

    /// Key generation event
    KeyGeneration {
        key_type: String,
        algorithm: String,
        key_usage: String,
    },

    /// Key rotation event
    KeyRotation {
        old_epoch: u64,
        new_epoch: u64,
        affected_files: u64,
    },

    /// Member management event
    MembershipChange {
        action: String, // "add", "remove", "update"
        member_id: String,
        performed_by: String,
        group_size: u32,
    },

    /// Suspicious activity detection
    SuspiciousActivity {
        activity_type: String,
        threat_level: ThreatLevel,
        details: HashMap<String, String>,
        recommended_action: String,
    },

    /// Access attempt
    AccessAttempt {
        resource: String,
        member_id: String,
        action: String,
        granted: bool,
        reason: Option<String>,
    },

    /// Encryption/Decryption event
    CryptographicOperation {
        operation: String, // "encrypt", "decrypt", "sign", "verify"
        algorithm: String,
        success: bool,
        data_size: u64,
    },
}

/// Threat levels for security events
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ThreatLevel {
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Main structured logger
pub struct StructuredLogger {
    config: LoggingConfig,
    correlation_id: Option<String>,
    component: String,
}

impl StructuredLogger {
    /// Create a new structured logger
    pub fn new(config: LoggingConfig, component: String) -> Self {
        Self {
            config,
            correlation_id: None,
            component,
        }
    }

    /// Set correlation ID for request tracing
    pub fn with_correlation_id(&mut self, correlation_id: String) {
        self.correlation_id = Some(correlation_id);
    }

    /// Generate a new correlation ID
    pub fn new_correlation_id(&mut self) -> String {
        let id = Uuid::new_v4().to_string();
        self.correlation_id = Some(id.clone());
        id
    }

    /// Clear correlation ID
    pub fn clear_correlation_id(&mut self) {
        self.correlation_id = None;
    }

    /// Log a general message
    pub fn log(&self, level: LogLevel, message: &str, operation: Option<&str>) {
        if level < self.config.level {
            return;
        }

        let entry = LogEntry {
            timestamp: self.current_timestamp(),
            level,
            message: message.to_string(),
            operation: operation.map(|s| s.to_string()),
            correlation_id: self.correlation_id.clone(),
            component: self.component.clone(),
            fields: HashMap::new(),
            error: None,
            metrics: None,
        };

        self.write_log_entry(&entry);
    }

    /// Log an operation with duration and result
    pub fn log_operation(
        &self,
        operation: &str,
        duration: Duration,
        result: &Result<(), ClientError>,
    ) {
        let level = match result {
            Ok(_) => LogLevel::Info,
            Err(error) => match error {
                _ => LogLevel::Error, // Map based on error severity
            },
        };

        let metrics = if self.config.enable_metrics {
            Some(PerformanceMetrics {
                duration_ms: duration.as_secs_f64() * 1000.0,
                cpu_usage: None, // Could be enhanced with actual CPU monitoring
                memory_usage: None,
                network_bytes: None,
                storage_bytes: None,
            })
        } else {
            None
        };

        let error = if let Err(client_error) = result {
            Some(self.error_to_logged_error(client_error))
        } else {
            None
        };

        let message = match result {
            Ok(_) => format!("Operation '{}' completed successfully", operation),
            Err(err) => format!("Operation '{}' failed: {}", operation, err),
        };

        let entry = LogEntry {
            timestamp: self.current_timestamp(),
            level,
            message,
            operation: Some(operation.to_string()),
            correlation_id: self.correlation_id.clone(),
            component: self.component.clone(),
            fields: HashMap::new(),
            error,
            metrics,
        };

        self.write_log_entry(&entry);
    }

    /// Log a security event
    pub fn log_security_event(&self, event: SecurityEvent) {
        if !self.config.enable_security_logging {
            return;
        }

        let level = match &event {
            SecurityEvent::SuspiciousActivity { threat_level, .. } => match threat_level {
                ThreatLevel::Low => LogLevel::Info,
                ThreatLevel::Medium => LogLevel::Warn,
                ThreatLevel::High => LogLevel::Error,
                ThreatLevel::Critical => LogLevel::Critical,
            },
            SecurityEvent::AuthenticationAttempt { success: false, .. } => LogLevel::Warn,
            _ => LogLevel::Info,
        };

        let message = self.format_security_event_message(&event);
        let mut fields = HashMap::new();

        // Add event-specific fields
        match &event {
            SecurityEvent::AuthenticationAttempt {
                device_id,
                success,
                method,
                ..
            } => {
                if !self.config.privacy.redact_sensitive {
                    fields.insert("device_id".to_string(), LogValue::String(device_id.clone()));
                }
                fields.insert("success".to_string(), LogValue::Boolean(*success));
                fields.insert("method".to_string(), LogValue::String(method.clone()));
            }
            SecurityEvent::KeyRotation {
                old_epoch,
                new_epoch,
                affected_files,
            } => {
                fields.insert("old_epoch".to_string(), LogValue::Number(*old_epoch as f64));
                fields.insert("new_epoch".to_string(), LogValue::Number(*new_epoch as f64));
                fields.insert(
                    "affected_files".to_string(),
                    LogValue::Number(*affected_files as f64),
                );
            }
            _ => {
                // Add other event-specific fields as needed
            }
        }

        fields.insert(
            "event_type".to_string(),
            LogValue::String("security".to_string()),
        );

        let entry = LogEntry {
            timestamp: self.current_timestamp(),
            level,
            message,
            operation: Some("security_event".to_string()),
            correlation_id: self.correlation_id.clone(),
            component: self.component.clone(),
            fields,
            error: None,
            metrics: None,
        };

        self.write_log_entry(&entry);
    }

    /// Log performance metrics
    pub fn log_performance_metric(&self, operation: &str, metrics: PerformanceMetrics) {
        if !self.config.enable_metrics {
            return;
        }

        let message = format!(
            "Performance metric for '{}': {:.2}ms",
            operation, metrics.duration_ms
        );

        let mut fields = HashMap::new();
        fields.insert(
            "metric_type".to_string(),
            LogValue::String("performance".to_string()),
        );
        fields.insert(
            "operation".to_string(),
            LogValue::String(operation.to_string()),
        );

        let entry = LogEntry {
            timestamp: self.current_timestamp(),
            level: LogLevel::Debug,
            message,
            operation: Some(operation.to_string()),
            correlation_id: self.correlation_id.clone(),
            component: self.component.clone(),
            fields,
            error: None,
            metrics: Some(metrics),
        };

        self.write_log_entry(&entry);
    }

    /// Helper methods
    fn current_timestamp(&self) -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    }

    fn error_to_logged_error(&self, error: &ClientError) -> LoggedError {
        // Extract error information while respecting privacy settings
        let message = if self.config.privacy.redact_sensitive {
            "Error details redacted for privacy".to_string()
        } else {
            error.to_string()
        };

        LoggedError {
            code: ErrorCode::CryptoEncryption, // Would need to extract from actual error
            severity: ErrorSeverity::High,     // Would need to extract from actual error
            message,
            recoverable: true, // Would need to determine from error type
            context: HashMap::new(),
        }
    }

    fn format_security_event_message(&self, event: &SecurityEvent) -> String {
        match event {
            SecurityEvent::AuthenticationAttempt {
                success, method, ..
            } => {
                if *success {
                    format!("Authentication successful using {}", method)
                } else {
                    format!("Authentication failed using {}", method)
                }
            }
            SecurityEvent::KeyGeneration {
                key_type,
                algorithm,
                ..
            } => {
                format!("Generated {} key using {}", key_type, algorithm)
            }
            SecurityEvent::KeyRotation {
                old_epoch,
                new_epoch,
                affected_files,
            } => {
                format!(
                    "Key rotation from epoch {} to epoch {} affecting {} files",
                    old_epoch, new_epoch, affected_files
                )
            }
            SecurityEvent::MembershipChange {
                action, group_size, ..
            } => {
                format!("Member {} - new group size: {}", action, group_size)
            }
            SecurityEvent::SuspiciousActivity {
                activity_type,
                threat_level,
                ..
            } => {
                format!(
                    "Suspicious activity detected: {} (threat level: {:?})",
                    activity_type, threat_level
                )
            }
            SecurityEvent::AccessAttempt {
                resource,
                action,
                granted,
                ..
            } => {
                if *granted {
                    format!("Access granted to {} for {}", resource, action)
                } else {
                    format!("Access denied to {} for {}", resource, action)
                }
            }
            SecurityEvent::CryptographicOperation {
                operation,
                algorithm,
                success,
                data_size,
            } => {
                if *success {
                    format!(
                        "Successful {} operation using {} ({} bytes)",
                        operation, algorithm, data_size
                    )
                } else {
                    format!("Failed {} operation using {}", operation, algorithm)
                }
            }
        }
    }

    fn write_log_entry(&self, entry: &LogEntry) {
        // Suppress JSON logging unless explicitly enabled via HYBRIDCIPHER_VERBOSE
        // This prevents verbose JSON output from cluttering CLI commands
        if matches!(self.config.format, LogFormat::Json | LogFormat::CompactJson) {
            if std::env::var("HYBRIDCIPHER_VERBOSE").is_err() {
                return;
            }
        }

        match self.config.format {
            LogFormat::Json | LogFormat::CompactJson => {
                if let Ok(json) = serde_json::to_string(entry) {
                    println!("{}", json); // In production, write to file/syslog/etc.
                }
            }
            LogFormat::Text => {
                println!(
                    "{} [{}] {}: {}",
                    entry.timestamp,
                    format!("{:?}", entry.level),
                    entry.component,
                    entry.message
                );
            }
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            enable_metrics: true,
            enable_security_logging: true,
            rotation: LogRotationConfig {
                max_file_size: 100 * 1024 * 1024, // 100MB
                max_files: 10,
                compress: true,
            },
            format: LogFormat::Json,
            privacy: PrivacyConfig {
                log_user_ids: false,
                log_file_paths: false,
                redact_sensitive: true,
                max_string_length: 1000,
            },
        }
    }
}

/// Global logger instance for convenient access
static GLOBAL_LOGGER: OnceLock<StructuredLogger> = OnceLock::new();

/// Initialize the global logger
pub fn init_logger(config: LoggingConfig, component: &str) {
    let logger = StructuredLogger::new(config, component.to_string());
    let _ = GLOBAL_LOGGER.set(logger);
}

/// Get a reference to the global logger
pub fn get_logger() -> Option<&'static StructuredLogger> {
    GLOBAL_LOGGER.get()
}

/// Convenience macros for logging
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if let Some(logger) = crate::logging::get_logger() {
            logger.log(crate::logging::LogLevel::Info, &format!($($arg)*), None);
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if let Some(logger) = crate::logging::get_logger() {
            logger.log(crate::logging::LogLevel::Error, &format!($($arg)*), None);
        }
    };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if let Some(logger) = crate::logging::get_logger() {
            logger.log(crate::logging::LogLevel::Warn, &format!($($arg)*), None);
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if let Some(logger) = crate::logging::get_logger() {
            logger.log(crate::logging::LogLevel::Debug, &format!($($arg)*), None);
        }
    };
}
