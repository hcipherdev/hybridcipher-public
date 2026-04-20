//! Security audit logging for HybridCipher
//!
//! This module provides comprehensive audit logging capabilities for tracking
//! security-relevant events throughout the HybridCipher system including:
//! - Authentication and authorization events
//! - Cryptographic operations and key management
//! - File access and modifications
//! - Group membership changes
//! - Security policy violations

use chrono::{DateTime, Local, Utc};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    net::{ToSocketAddrs, UdpSocket},
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
use thiserror::Error;

/// Errors that can occur during audit logging
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Failed to write audit log: {0}")]
    WriteError(#[from] std::io::Error),

    #[error("Failed to serialize audit event: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Audit log rotation failed: {0}")]
    RotationError(String),

    #[error("Invalid audit configuration: {0}")]
    ConfigurationError(String),

    #[error("Failed to forward audit event: {0}")]
    ForwardingError(String),
}

/// Types of security events that can be audited
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventType {
    /// Authentication events
    Authentication {
        method: String,
        client_id: Option<String>,
    },

    /// Authorization events
    Authorization {
        resource: String,
        action: String,
        requested_by: String,
    },

    /// Cryptographic operations
    Cryptographic {
        operation: String,
        key_type: String,
        algorithm: String,
    },

    /// Key management events
    KeyManagement {
        operation: String, // "generate", "rotate", "delete", "export"
        key_id: String,
        key_type: String,
    },

    /// File operations
    FileOperation {
        operation: String, // "create", "read", "write", "delete", "share"
        file_id: String,
        file_path: Option<String>,
    },

    /// Group membership events
    GroupMembership {
        operation: String, // "add", "remove", "update_permissions"
        group_id: String,
        member_id: String,
        role: Option<String>,
    },

    /// Epoch management events
    EpochManagement {
        operation: String, // "create", "migrate", "cutover", "rollback"
        old_epoch: Option<u64>,
        new_epoch: Option<u64>,
    },

    /// Security policy violations
    SecurityViolation {
        violation_type: String,
        severity: SecuritySeverity,
        details: String,
    },

    /// System administration events
    SystemAdmin {
        operation: String,
        component: String,
        admin_id: String,
    },
}

/// Severity levels for security events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecuritySeverity {
    /// Informational events
    Info,
    /// Warning events that may indicate issues
    Warning,
    /// Critical security events requiring immediate attention
    Critical,
    /// High-priority security incidents
    High,
    /// Medium-priority security events
    Medium,
    /// Low-priority security events
    Low,
}

/// Outcome of the audited event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditOutcome {
    /// Operation completed successfully
    Success,
    /// Operation failed
    Failure {
        error_code: String,
        error_message: String,
    },
    /// Operation was denied due to authorization
    Denied { reason: String },
    /// Operation is still in progress
    InProgress,
    /// Operation was aborted
    Aborted { reason: String },
}

/// Structured audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// When the event occurred
    pub timestamp: DateTime<Utc>,

    /// Type and details of the event
    pub event_type: AuditEventType,

    /// User or process that initiated the event
    pub user_id: Option<String>,

    /// Additional context and metadata
    pub details: serde_json::Value,

    /// Outcome of the event
    pub outcome: AuditOutcome,

    /// Session or request ID for correlation
    pub session_id: Option<String>,

    /// Source IP address (if applicable)
    pub source_ip: Option<String>,

    /// User agent or client information
    pub user_agent: Option<String>,
}

/// Configuration for audit logging
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Directory to store audit logs
    pub log_directory: PathBuf,

    /// Maximum size of a single log file before rotation
    pub max_file_size: u64,

    /// Maximum number of rotated log files to keep
    pub max_files: usize,

    /// Whether to enable structured JSON logging
    pub json_format: bool,

    /// Whether to enable real-time log forwarding
    pub enable_forwarding: bool,

    /// Remote syslog server (if forwarding enabled)
    pub syslog_server: Option<String>,

    /// Minimum severity level to log
    pub min_severity: SecuritySeverity,

    /// Whether to include sensitive data in logs (for debugging)
    pub include_sensitive: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_directory: PathBuf::from("./audit_logs"),
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_files: 10,
            json_format: true,
            enable_forwarding: false,
            syslog_server: None,
            min_severity: SecuritySeverity::Info,
            include_sensitive: false,
        }
    }
}

/// Security audit logger
pub struct AuditLogger {
    config: AuditConfig,
    current_file: Arc<Mutex<Option<BufWriter<File>>>>,
    current_size: Arc<Mutex<u64>>,
}

impl AuditLogger {
    /// Create a new audit logger with the specified configuration
    pub fn new(config: AuditConfig) -> Result<Self, AuditError> {
        // Ensure log directory exists
        std::fs::create_dir_all(&config.log_directory)?;

        let logger = Self {
            config,
            current_file: Arc::new(Mutex::new(None)),
            current_size: Arc::new(Mutex::new(0)),
        };

        // Initialize the first log file
        logger.rotate_if_needed()?;

        Ok(logger)
    }

    /// Log an audit event
    pub fn log_event(&self, event: AuditEvent) -> Result<(), AuditError> {
        // Check if event meets minimum severity threshold
        if let AuditEventType::SecurityViolation { severity, .. } = &event.event_type {
            if !self.should_log_severity(severity) {
                return Ok(());
            }
        }

        // Serialize the event
        let log_line = if self.config.json_format {
            serde_json::to_string(&event)?
        } else {
            self.format_human_readable(&event)
        };

        // Write to file
        {
            let mut file_guard = self.current_file.lock().unwrap();
            let mut size_guard = self.current_size.lock().unwrap();

            if let Some(ref mut writer) = file_guard.as_mut() {
                writeln!(writer, "{}", log_line)?;
                writer.flush()?;
                *size_guard += log_line.len() as u64 + 1; // +1 for newline
            }
        }

        // Check if rotation is needed
        self.rotate_if_needed()?;

        // Forward to remote system if configured
        if self.config.enable_forwarding {
            self.forward_event(&event, &log_line)?;
        }

        Ok(())
    }

    /// Log an authentication event
    pub fn log_authentication(
        &self,
        method: &str,
        client_id: Option<String>,
        outcome: AuditOutcome,
        session_id: Option<String>,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::Authentication {
                method: method.to_string(),
                client_id: client_id.clone(),
            },
            user_id: client_id,
            details: serde_json::json!({
                "method": method
            }),
            outcome,
            session_id,
            source_ip: None,
            user_agent: None,
        };

        self.log_event(event)
    }

    /// Log a key management event
    pub fn log_key_management(
        &self,
        operation: &str,
        key_id: &str,
        key_type: &str,
        user_id: Option<String>,
        outcome: AuditOutcome,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::KeyManagement {
                operation: operation.to_string(),
                key_id: key_id.to_string(),
                key_type: key_type.to_string(),
            },
            user_id,
            details: serde_json::json!({
                "operation": operation,
                "key_type": key_type,
                "key_id": if self.config.include_sensitive { key_id } else { "[REDACTED]" }
            }),
            outcome,
            session_id: None,
            source_ip: None,
            user_agent: None,
        };

        self.log_event(event)
    }

    /// Log a file operation event
    pub fn log_file_operation(
        &self,
        operation: &str,
        file_id: &str,
        file_path: Option<&str>,
        user_id: Option<String>,
        outcome: AuditOutcome,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::FileOperation {
                operation: operation.to_string(),
                file_id: file_id.to_string(),
                file_path: file_path.map(|s| s.to_string()),
            },
            user_id,
            details: serde_json::json!({
                "operation": operation,
                "file_path": file_path
            }),
            outcome,
            session_id: None,
            source_ip: None,
            user_agent: None,
        };

        self.log_event(event)
    }

    /// Log a security violation
    pub fn log_security_violation(
        &self,
        violation_type: &str,
        severity: SecuritySeverity,
        details: &str,
        user_id: Option<String>,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::SecurityViolation {
                violation_type: violation_type.to_string(),
                severity: severity.clone(),
                details: details.to_string(),
            },
            user_id,
            details: serde_json::json!({
                "violation_type": violation_type,
                "severity": severity,
                "details": details
            }),
            outcome: AuditOutcome::Failure {
                error_code: "SECURITY_VIOLATION".to_string(),
                error_message: details.to_string(),
            },
            session_id: None,
            source_ip: None,
            user_agent: None,
        };

        self.log_event(event)
    }

    /// Log an epoch management event
    pub fn log_epoch_management(
        &self,
        operation: &str,
        old_epoch: Option<u64>,
        new_epoch: Option<u64>,
        user_id: Option<String>,
        outcome: AuditOutcome,
    ) -> Result<(), AuditError> {
        let event = AuditEvent {
            timestamp: Utc::now(),
            event_type: AuditEventType::EpochManagement {
                operation: operation.to_string(),
                old_epoch,
                new_epoch,
            },
            user_id,
            details: serde_json::json!({
                "operation": operation,
                "old_epoch": old_epoch,
                "new_epoch": new_epoch
            }),
            outcome,
            session_id: None,
            source_ip: None,
            user_agent: None,
        };

        self.log_event(event)
    }

    /// Check if we should log events of this severity
    fn should_log_severity(&self, severity: &SecuritySeverity) -> bool {
        match (&self.config.min_severity, severity) {
            (SecuritySeverity::Critical, SecuritySeverity::Critical) => true,
            (SecuritySeverity::High, SecuritySeverity::Critical | SecuritySeverity::High) => true,
            (
                SecuritySeverity::Medium,
                SecuritySeverity::Critical | SecuritySeverity::High | SecuritySeverity::Medium,
            ) => true,
            (
                SecuritySeverity::Warning,
                SecuritySeverity::Critical
                | SecuritySeverity::High
                | SecuritySeverity::Medium
                | SecuritySeverity::Warning,
            ) => true,
            (SecuritySeverity::Info, _) => true,
            (SecuritySeverity::Low, _) => true,
            _ => false,
        }
    }

    /// Format event in human-readable format
    fn format_human_readable(&self, event: &AuditEvent) -> String {
        let local = event.timestamp.with_timezone(&Local);
        let offset = local.format("%:z");
        let local_display = format!("{} UTC{}", local.format("%Y-%m-%d %H:%M:%S"), offset);
        let utc_display = event.timestamp.format("%Y-%m-%d %H:%M:%S UTC");
        format!(
            "[{} ({})] {} - {:?} by {} - {}",
            local_display,
            utc_display,
            self.format_event_type(&event.event_type),
            event.outcome,
            event.user_id.as_deref().unwrap_or("system"),
            event.details
        )
    }

    /// Format event type for human reading
    fn format_event_type(&self, event_type: &AuditEventType) -> String {
        match event_type {
            AuditEventType::Authentication { method, .. } => format!("AUTH({})", method),
            AuditEventType::Authorization {
                action, resource, ..
            } => format!("AUTHZ({} on {})", action, resource),
            AuditEventType::Cryptographic { operation, .. } => format!("CRYPTO({})", operation),
            AuditEventType::KeyManagement {
                operation,
                key_type,
                ..
            } => format!("KEY({} {})", operation, key_type),
            AuditEventType::FileOperation { operation, .. } => format!("FILE({})", operation),
            AuditEventType::GroupMembership { operation, .. } => format!("GROUP({})", operation),
            AuditEventType::EpochManagement { operation, .. } => format!("EPOCH({})", operation),
            AuditEventType::SecurityViolation {
                violation_type,
                severity,
                ..
            } => format!("VIOLATION({:?} {})", severity, violation_type),
            AuditEventType::SystemAdmin {
                operation,
                component,
                ..
            } => format!("ADMIN({} {})", operation, component),
        }
    }

    /// Rotate log file if needed
    fn rotate_if_needed(&self) -> Result<(), AuditError> {
        let size = *self.current_size.lock().unwrap();

        if size >= self.config.max_file_size {
            self.rotate_logs()?;
        } else {
            // Ensure we have an open file
            let mut file_guard = self.current_file.lock().unwrap();
            if file_guard.is_none() {
                let log_path = self.get_current_log_path();
                let file = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&log_path)?;
                *file_guard = Some(BufWriter::new(file));

                // Reset size counter for new file
                *self.current_size.lock().unwrap() = 0;
            }
        }

        Ok(())
    }

    /// Perform log rotation
    fn rotate_logs(&self) -> Result<(), AuditError> {
        // Close current file
        {
            let mut file_guard = self.current_file.lock().unwrap();
            if let Some(writer) = file_guard.take() {
                drop(writer); // Ensure file is closed
            }
        }

        // Rotate existing files
        for i in (1..self.config.max_files).rev() {
            let old_path = self.get_rotated_log_path(i);
            let new_path = self.get_rotated_log_path(i + 1);

            if old_path.exists() {
                if i + 1 > self.config.max_files {
                    // Remove oldest file
                    std::fs::remove_file(&old_path).ok();
                } else {
                    std::fs::rename(&old_path, &new_path)
                        .map_err(|e| AuditError::RotationError(e.to_string()))?;
                }
            }
        }

        // Move current log to .1
        let current_path = self.get_current_log_path();
        let rotated_path = self.get_rotated_log_path(1);

        if current_path.exists() {
            std::fs::rename(&current_path, &rotated_path)
                .map_err(|e| AuditError::RotationError(e.to_string()))?;
        }

        // Create new current log file
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&current_path)?;

        {
            let mut file_guard = self.current_file.lock().unwrap();
            *file_guard = Some(BufWriter::new(file));

            // Reset size counter
            *self.current_size.lock().unwrap() = 0;
        }

        Ok(())
    }

    /// Get path for current log file
    fn get_current_log_path(&self) -> PathBuf {
        self.config.log_directory.join("hybridcipher_audit.log")
    }

    /// Get path for rotated log file
    fn get_rotated_log_path(&self, number: usize) -> PathBuf {
        self.config
            .log_directory
            .join(format!("hybridcipher_audit.log.{}", number))
    }

    /// Forward event to remote logging system via syslog over UDP
    fn forward_event(&self, event: &AuditEvent, serialized: &str) -> Result<(), AuditError> {
        if !self.config.enable_forwarding {
            return Ok(());
        }

        let server = self.config.syslog_server.as_ref().ok_or_else(|| {
            AuditError::ConfigurationError(
                "Syslog server must be configured when forwarding is enabled".into(),
            )
        })?;

        let mut addrs = server.to_socket_addrs().map_err(|err| {
            AuditError::ForwardingError(format!(
                "Failed to resolve syslog server '{}': {}",
                server, err
            ))
        })?;

        let addr = addrs.next().ok_or_else(|| {
            AuditError::ForwardingError(format!(
                "Syslog server '{}' resolved to no addresses",
                server
            ))
        })?;

        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| {
            AuditError::ForwardingError(format!("Failed to bind UDP socket: {}", err))
        })?;

        let priority = self.calculate_syslog_priority(event);
        let timestamp = event.timestamp.format("%Y-%m-%dT%H:%M:%SZ");
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "hybridcipher-client".to_string());
        let app_name = "hybridcipher-client";
        let proc_id = std::process::id();
        let msg_id = event.session_id.as_deref().unwrap_or("audit-event");

        let syslog_message = format!(
            "<{}>1 {} {} {} {} {} - {}",
            priority, timestamp, hostname, app_name, proc_id, msg_id, serialized
        );

        socket
            .send_to(syslog_message.as_bytes(), addr)
            .map(|_| ())
            .map_err(|err| AuditError::ForwardingError(format!("Syslog send failed: {}", err)))
    }

    fn calculate_syslog_priority(&self, event: &AuditEvent) -> i32 {
        let facility = 16; // local0
        let severity = match &event.event_type {
            AuditEventType::SecurityViolation { severity, .. } => match severity {
                SecuritySeverity::Critical => 2,
                SecuritySeverity::High => 1,
                SecuritySeverity::Medium => 4,
                SecuritySeverity::Warning => 4,
                SecuritySeverity::Info => 6,
                SecuritySeverity::Low => 5,
            },
            _ => match &event.outcome {
                AuditOutcome::Failure { .. } => 3,
                AuditOutcome::Denied { .. } => 4,
                AuditOutcome::Aborted { .. } => 5,
                AuditOutcome::InProgress => 6,
                AuditOutcome::Success => 6,
            },
        };

        facility * 8 + severity
    }
}

/// Global audit logger instance
static AUDIT_LOGGER: OnceLock<AuditLogger> = OnceLock::new();

/// Initialize the global audit logger
pub fn init_audit_logger(config: AuditConfig) -> Result<(), AuditError> {
    let logger = AuditLogger::new(config)?;
    AUDIT_LOGGER
        .set(logger)
        .map_err(|_| AuditError::ConfigurationError("Audit logger already initialized".into()))
}

/// Get reference to the global audit logger
pub fn audit_logger() -> Option<&'static AuditLogger> {
    AUDIT_LOGGER.get()
}

/// Convenience macro for logging audit events
#[macro_export]
macro_rules! audit_log {
    ($event_type:expr, $user_id:expr, $outcome:expr, $details:expr) => {
        if let Some(logger) = $crate::audit::audit_logger() {
            let event = $crate::audit::AuditEvent {
                timestamp: chrono::Utc::now(),
                event_type: $event_type,
                user_id: $user_id,
                details: $details,
                outcome: $outcome,
                session_id: None,
                source_ip: None,
                user_agent: None,
            };
            let _ = logger.log_event(event);
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_config() -> (AuditConfig, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let config = AuditConfig {
            log_directory: temp_dir.path().to_path_buf(),
            max_file_size: 1024, // Small for testing
            max_files: 3,
            json_format: true,
            enable_forwarding: false,
            syslog_server: None,
            min_severity: SecuritySeverity::Info,
            include_sensitive: false,
        };
        (config, temp_dir)
    }

    #[test]
    fn test_audit_logger_creation() {
        let (config, _temp_dir) = test_config();
        let logger = AuditLogger::new(config).unwrap();
        assert!(logger.current_file.lock().unwrap().is_some());
    }

    #[test]
    fn test_authentication_logging() {
        let (config, _temp_dir) = test_config();
        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_authentication(
                "password",
                Some("user123".to_string()),
                AuditOutcome::Success,
                Some("session456".to_string()),
            )
            .unwrap();
    }

    #[test]
    fn test_key_management_logging() {
        let (config, _temp_dir) = test_config();
        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_key_management(
                "generate",
                "key789",
                "Ed25519",
                Some("user123".to_string()),
                AuditOutcome::Success,
            )
            .unwrap();
    }

    #[test]
    fn test_security_violation_logging() {
        let (config, _temp_dir) = test_config();
        let logger = AuditLogger::new(config).unwrap();

        logger
            .log_security_violation(
                "unauthorized_access",
                SecuritySeverity::High,
                "Attempted access to restricted file",
                Some("user123".to_string()),
            )
            .unwrap();
    }

    #[test]
    fn test_log_rotation() {
        let (mut config, temp_dir) = test_config();
        config.max_file_size = 100; // Very small for testing

        let logger = AuditLogger::new(config).unwrap();

        // Write enough events to trigger rotation
        for i in 0..10 {
            logger
                .log_authentication(
                    "password",
                    Some(format!("user{}", i)),
                    AuditOutcome::Success,
                    None,
                )
                .unwrap();
        }

        // Check that rotated files exist
        let log_path = temp_dir.path().join("hybridcipher_audit.log.1");
        assert!(log_path.exists());
    }

    #[test]
    fn test_severity_filtering() {
        let (mut config, _temp_dir) = test_config();
        config.min_severity = SecuritySeverity::High;

        let logger = AuditLogger::new(config).unwrap();

        // This should be logged (High severity)
        logger
            .log_security_violation(
                "critical_breach",
                SecuritySeverity::Critical,
                "Critical security breach detected",
                None,
            )
            .unwrap();

        // This should be filtered out (Low severity)
        logger
            .log_security_violation(
                "minor_issue",
                SecuritySeverity::Low,
                "Minor security issue",
                None,
            )
            .unwrap();
    }
}
