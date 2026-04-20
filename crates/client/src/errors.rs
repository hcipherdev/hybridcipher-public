use serde::{Deserialize, Serialize};
/// Enterprise-grade error handling system for HybridCipher Client
///
/// Provides comprehensive error classification, recovery strategies, and operational
/// context for production-ready error management and monitoring.
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Error severity levels for monitoring and alerting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Critical errors requiring immediate attention
    Critical = 4,
    /// High priority errors affecting functionality
    High = 3,
    /// Medium priority errors with workarounds available
    Medium = 2,
    /// Low priority errors for informational purposes
    Low = 1,
}

/// Standardized error codes for automated monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCode {
    // Cryptographic Errors (1000-1999)
    CryptoKeyGeneration = 1001,
    CryptoEncryption = 1002,
    CryptoDecryption = 1003,
    CryptoSignature = 1004,
    CryptoVerification = 1005,
    CryptoRandomness = 1006,
    CryptoHkdf = 1007,
    CryptoInvalidKey = 1008,
    CryptoInvalidNonce = 1009,
    CryptoTimingAttack = 1010,

    // Network Errors (2000-2999)
    NetworkConnection = 2001,
    NetworkTimeout = 2002,
    NetworkProtocol = 2003,
    NetworkAuthentication = 2004,
    NetworkRateLimit = 2005,
    NetworkBandwidth = 2006,
    NetworkPartition = 2007,
    NetworkCertificate = 2008,
    NetworkDns = 2009,
    NetworkFirewall = 2010,

    // Storage Errors (3000-3999)
    StorageRead = 3001,
    StorageWrite = 3002,
    StorageDelete = 3003,
    StorageCorruption = 3004,
    StorageSpace = 3005,
    StoragePermission = 3006,
    StorageTransaction = 3007,
    StorageBackup = 3008,
    StorageMigration = 3009,
    StorageLock = 3010,

    // Group State Errors (4000-4999)
    GroupStateInconsistent = 4001,
    GroupStateOutdated = 4002,
    GroupStateMissing = 4003,
    GroupStateConflict = 4004,
    GroupMemberNotFound = 4005,
    GroupInvalidEpoch = 4006,
    GroupRekeyFailed = 4007,
    GroupMigrationFailed = 4008,
    GroupPermissionDenied = 4009,
    GroupSizeLimitExceeded = 4010,

    // File Operation Errors (5000-5999)
    FileNotFound = 5001,
    FileCorrupted = 5002,
    FileTooBig = 5003,
    FileAccessDenied = 5004,
    FileAlreadyExists = 5005,
    FileInvalidFormat = 5006,
    FileMetadataMissing = 5007,
    FileVersionConflict = 5008,
    FileQuotaExceeded = 5009,
    FilePathInvalid = 5010,

    // System Resource Errors (6000-6999)
    ResourceMemory = 6001,
    ResourceCpu = 6002,
    ResourceDisk = 6003,
    ResourceNetwork = 6004,
    ResourceThreadPool = 6005,
    ResourceFileDescriptors = 6006,
    ResourceLockContention = 6007,
    ResourceTimeout = 6008,
    ResourceQuotaExceeded = 6009,
    ResourceUnavailable = 6010,
    ResourceManagementFailed = 6011,
    CompressionFailed = 6012,
    ConfigurationInvalid = 6013,

    // Security Errors (7000-7999)
    SecurityUnauthorized = 7001,
    SecurityTampering = 7002,
    SecurityReplay = 7003,
    SecuritySidechannel = 7004,
    SecurityTiming = 7005,
    SecurityBruteforce = 7006,
    SecurityPrivilegeEscalation = 7007,
    SecurityDataLeak = 7008,
    SecurityAuditFailure = 7009,
    SecurityCompliance = 7010,
    SecurityValidationFailed = 7011,
}

impl ErrorCode {
    /// Get the severity level for this error code
    pub fn severity(&self) -> ErrorSeverity {
        match self {
            // Critical errors
            ErrorCode::CryptoRandomness
            | ErrorCode::SecurityTampering
            | ErrorCode::SecurityDataLeak
            | ErrorCode::StorageCorruption
            | ErrorCode::GroupStateInconsistent => ErrorSeverity::Critical,

            // High priority errors
            ErrorCode::CryptoDecryption
            | ErrorCode::CryptoEncryption
            | ErrorCode::NetworkAuthentication
            | ErrorCode::StorageWrite
            | ErrorCode::SecurityUnauthorized
            | ErrorCode::SecurityValidationFailed
            | ErrorCode::FileCorrupted => ErrorSeverity::High,

            // Medium priority errors
            ErrorCode::NetworkTimeout
            | ErrorCode::StorageRead
            | ErrorCode::GroupMemberNotFound
            | ErrorCode::FileNotFound
            | ErrorCode::ResourceMemory => ErrorSeverity::Medium,

            // Low priority errors
            _ => ErrorSeverity::Low,
        }
    }

    /// Check if this error type supports automatic retry
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ErrorCode::NetworkTimeout
                | ErrorCode::NetworkConnection
                | ErrorCode::StorageRead
                | ErrorCode::StorageWrite
                | ErrorCode::ResourceTimeout
                | ErrorCode::ResourceLockContention
                | ErrorCode::NetworkRateLimit
        )
    }

    /// Get recommended retry delay for retryable errors
    pub fn retry_delay(&self) -> Duration {
        match self {
            ErrorCode::NetworkRateLimit => Duration::from_secs(60),
            ErrorCode::NetworkTimeout | ErrorCode::NetworkConnection => Duration::from_secs(5),
            ErrorCode::StorageRead | ErrorCode::StorageWrite => Duration::from_millis(100),
            ErrorCode::ResourceTimeout | ErrorCode::ResourceLockContention => {
                Duration::from_millis(50)
            }
            _ => Duration::from_secs(1),
        }
    }
}

/// Recovery action recommendations for different error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryAction {
    /// Retry the operation with exponential backoff
    Retry {
        max_attempts: u32,
        base_delay: Duration,
        max_delay: Duration,
    },
    /// Fallback to an alternative approach
    Fallback {
        strategy: String,
        expected_degradation: String,
    },
    /// Escalate to human intervention
    Escalate {
        urgency: ErrorSeverity,
        notification_targets: Vec<String>,
    },
    /// Gracefully degrade functionality
    Degrade {
        disabled_features: Vec<String>,
        user_message: String,
    },
    /// Abort operation and report error
    Abort {
        safe_cleanup: bool,
        user_notification: String,
    },
}

/// Comprehensive error context for debugging and monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Unique error instance identifier for tracking
    pub error_id: String,

    /// Error code for classification
    pub code: ErrorCode,

    /// Human-readable error message
    pub message: String,

    /// Severity level for prioritization
    pub severity: ErrorSeverity,

    /// Timestamp when error occurred
    pub timestamp: SystemTime,

    /// Operation that was being performed
    pub operation: String,

    /// Additional context data
    pub details: HashMap<String, String>,

    /// Whether automatic recovery was attempted
    pub recovery_attempted: bool,

    /// Recommended recovery action
    pub recovery_action: RecoveryAction,

    /// Call stack or error chain
    pub error_chain: Vec<String>,

    /// Performance impact metrics
    pub performance_impact: Option<Duration>,
}

impl ErrorContext {
    /// Create a new error context with basic information
    pub fn new(code: ErrorCode, message: String, operation: String) -> Self {
        Self {
            error_id: uuid::Uuid::new_v4().to_string(),
            severity: code.severity(),
            code,
            message,
            timestamp: SystemTime::now(),
            operation,
            details: HashMap::new(),
            recovery_attempted: false,
            recovery_action: Self::default_recovery_action(&code),
            error_chain: Vec::new(),
            performance_impact: None,
        }
    }

    /// Add contextual details to the error
    pub fn with_detail(mut self, key: String, value: String) -> Self {
        self.details.insert(key, value);
        self
    }

    /// Add multiple details at once
    pub fn with_details(mut self, details: HashMap<String, String>) -> Self {
        self.details.extend(details);
        self
    }

    /// Set performance impact measurement
    pub fn with_performance_impact(mut self, duration: Duration) -> Self {
        self.performance_impact = Some(duration);
        self
    }

    /// Add error to the chain
    pub fn with_error_chain(mut self, error: String) -> Self {
        self.error_chain.push(error);
        self
    }

    /// Mark that recovery was attempted
    pub fn with_recovery_attempted(mut self) -> Self {
        self.recovery_attempted = true;
        self
    }

    /// Default recovery action based on error code
    fn default_recovery_action(code: &ErrorCode) -> RecoveryAction {
        if code.is_retryable() {
            RecoveryAction::Retry {
                max_attempts: 3,
                base_delay: code.retry_delay(),
                max_delay: Duration::from_secs(30),
            }
        } else {
            match code.severity() {
                ErrorSeverity::Critical => RecoveryAction::Escalate {
                    urgency: ErrorSeverity::Critical,
                    notification_targets: vec!["ops-team".to_string(), "security-team".to_string()],
                },
                ErrorSeverity::High => RecoveryAction::Fallback {
                    strategy: "Use cached data or offline mode".to_string(),
                    expected_degradation: "Limited functionality".to_string(),
                },
                ErrorSeverity::Medium => RecoveryAction::Degrade {
                    disabled_features: vec!["non-essential features".to_string()],
                    user_message: "Some features temporarily unavailable".to_string(),
                },
                ErrorSeverity::Low => RecoveryAction::Abort {
                    safe_cleanup: true,
                    user_notification: "Operation could not be completed".to_string(),
                },
            }
        }
    }
}

/// Enhanced ClientError with comprehensive error handling
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Cryptographic operation failed")]
    CryptographicError {
        context: ErrorContext,
        recoverable: bool,
        retry_after: Option<Duration>,
    },

    #[error("Network operation failed")]
    NetworkError {
        context: ErrorContext,
        retry_count: u32,
        last_attempt: SystemTime,
        connection_state: String,
    },

    #[error("{}", context.message)]
    StorageError {
        context: ErrorContext,
        transaction_id: Option<String>,
        data_integrity: bool,
    },

    #[error("Group state inconsistency detected")]
    ConsistencyError {
        context: ErrorContext,
        recovery_action: RecoveryAction,
        affected_operations: Vec<String>,
    },

    #[error("Member operation failed")]
    MemberError {
        context: ErrorContext,
        member_id: String,
        operation: String,
    },

    #[error("File operation failed")]
    FileError {
        context: ErrorContext,
        file_path: String,
        file_size: Option<u64>,
    },

    #[error("Resource constraint violation")]
    ResourceError {
        context: ErrorContext,
        resource_type: String,
        current_usage: f64,
        limit: f64,
    },

    #[error("Security policy violation")]
    SecurityError {
        context: ErrorContext,
        violation_type: String,
        threat_level: ErrorSeverity,
    },

    #[error("System configuration error")]
    ConfigurationError {
        context: ErrorContext,
        configuration_key: String,
        expected_format: String,
    },

    #[error("Operation timeout")]
    TimeoutError {
        context: ErrorContext,
        operation_duration: Duration,
        timeout_limit: Duration,
    },

    // Legacy error variants for backward compatibility
    #[error("Invalid client state: {0}")]
    InvalidState(String),

    #[error("Storage error: {0}")]
    Storage(#[from] crate::storage::StorageError),

    #[error("Network error: {0}")]
    Network(#[from] crate::network::NetworkError),

    #[error("Cryptography error: {0}")]
    Crypto(#[from] hybridcipher_crypto::error::CryptoError),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Member not found: {0}")]
    MemberNotFound(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Key pinning verification required: {0}")]
    PinningRequired(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Path excluded from encryption: {0}")]
    PathExcluded(String),
}

impl ClientError {
    /// Get error context if available
    pub fn context(&self) -> Option<&ErrorContext> {
        match self {
            ClientError::CryptographicError { context, .. }
            | ClientError::NetworkError { context, .. }
            | ClientError::StorageError { context, .. }
            | ClientError::ConsistencyError { context, .. }
            | ClientError::MemberError { context, .. }
            | ClientError::FileError { context, .. }
            | ClientError::ResourceError { context, .. }
            | ClientError::SecurityError { context, .. }
            | ClientError::ConfigurationError { context, .. }
            | ClientError::TimeoutError { context, .. } => Some(context),
            _ => None,
        }
    }

    /// Get error code for monitoring
    pub fn error_code(&self) -> Option<ErrorCode> {
        self.context().map(|ctx| ctx.code)
    }

    /// Get error severity
    pub fn severity(&self) -> ErrorSeverity {
        self.context()
            .map(|ctx| ctx.severity)
            .unwrap_or(ErrorSeverity::Medium)
    }

    /// Check if error is retryable
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::NetworkError { .. }
            | ClientError::StorageError { .. }
            | ClientError::TimeoutError { .. } => true,
            ClientError::CryptographicError { recoverable, .. } => *recoverable,
            _ => false,
        }
    }

    /// Get recommended retry delay
    pub fn retry_delay(&self) -> Option<Duration> {
        match self {
            ClientError::CryptographicError { retry_after, .. } => *retry_after,
            ClientError::NetworkError { context, .. } => Some(context.code.retry_delay()),
            _ => {
                if self.is_retryable() {
                    Some(Duration::from_millis(100))
                } else {
                    None
                }
            }
        }
    }

    /// Create a cryptographic error with context
    pub fn crypto_error(
        code: ErrorCode,
        message: String,
        operation: String,
        recoverable: bool,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);
        let retry_after = if recoverable {
            Some(code.retry_delay())
        } else {
            None
        };

        ClientError::CryptographicError {
            context,
            recoverable,
            retry_after,
        }
    }

    /// Create a network error with connection details
    pub fn network_error(
        code: ErrorCode,
        message: String,
        operation: String,
        retry_count: u32,
        connection_state: String,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);

        ClientError::NetworkError {
            context,
            retry_count,
            last_attempt: SystemTime::now(),
            connection_state,
        }
    }

    /// Create a storage error with transaction context
    pub fn storage_error(
        code: ErrorCode,
        message: String,
        operation: String,
        transaction_id: Option<String>,
        data_integrity: bool,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);

        ClientError::StorageError {
            context,
            transaction_id,
            data_integrity,
        }
    }

    /// Create a file operation error
    pub fn file_error(
        code: ErrorCode,
        message: String,
        operation: String,
        file_path: String,
        file_size: Option<u64>,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);

        ClientError::FileError {
            context,
            file_path,
            file_size,
        }
    }

    /// Create a security error
    pub fn security_error(
        code: ErrorCode,
        message: String,
        operation: String,
        violation_type: String,
        threat_level: ErrorSeverity,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);

        ClientError::SecurityError {
            context,
            violation_type,
            threat_level,
        }
    }

    /// Create a configuration error
    pub fn configuration_error(message: &str) -> Self {
        let context = ErrorContext::new(
            ErrorCode::ConfigurationInvalid,
            message.to_string(),
            "configuration_validation".to_string(),
        );

        ClientError::ConfigurationError {
            context,
            configuration_key: "unknown".to_string(),
            expected_format: "valid configuration".to_string(),
        }
    }

    /// Create a system error
    pub fn system_error(
        code: ErrorCode,
        message: String,
        operation: String,
        recoverable: bool,
    ) -> Self {
        let context = ErrorContext::new(code, message, operation);
        let retry_after = if recoverable {
            Some(code.retry_delay())
        } else {
            None
        };

        ClientError::CryptographicError {
            context,
            recoverable,
            retry_after,
        }
    }
}

/// Convert legacy errors to new format
impl From<String> for ClientError {
    fn from(message: String) -> Self {
        ClientError::InvalidState(message)
    }
}
