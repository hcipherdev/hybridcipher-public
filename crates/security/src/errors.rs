use thiserror::Error;

/// General security error type
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Testing error: {0}")]
    TestingError(String),

    #[error("Attack simulation failed: {0}")]
    AttackSimulationError(String),

    #[error("Attack error: {0}")]
    AttackError(String),

    #[error("Security validation failed: {0}")]
    ValidationError(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("I/O error: {source}")]
    IoError {
        #[source]
        source: std::io::Error,
    },

    #[error("Audit error: {source}")]
    AuditError {
        #[from]
        source: AuditError,
    },
}

/// Security audit errors
#[derive(Error, Debug)]
pub enum AuditError {
    #[error("Static analysis failed: {message}")]
    StaticAnalysisFailed { message: String },

    #[error("Dynamic analysis failed: {message}")]
    DynamicAnalysisFailed { message: String },

    #[error("Vulnerability scan failed: {message}")]
    VulnerabilityScanFailed { message: String },

    #[error("Cryptographic validation failed: {message}")]
    CryptoValidationFailed { message: String },

    #[error("Documentation generation failed: {message}")]
    DocumentationFailed { message: String },

    #[error("Report generation failed: {message}")]
    ReportGenerationFailed { message: String },

    #[error("Audit configuration invalid: {message}")]
    InvalidConfiguration { message: String },

    #[error("I/O error during audit")]
    IoError {
        #[source]
        source: std::io::Error,
    },

    #[error("Serialization error")]
    SerializationError {
        #[source]
        source: serde_json::Error,
    },

    #[error("Cryptographic validation error")]
    CryptoError {
        #[from]
        source: CryptoError,
    },

    #[error("Threat detection error")]
    ThreatError {
        #[from]
        source: ThreatError,
    },

    #[error("Vulnerability scanning error")]
    VulnerabilityError {
        #[from]
        source: VulnerabilityError,
    },

    #[error("Static analysis error")]
    StaticAnalysisError {
        #[from]
        source: StaticAnalysisError,
    },
}

/// Threat detection errors
#[derive(Error, Debug)]
pub enum ThreatError {
    #[error("Pattern matching failed: {message}")]
    PatternMatchingFailed { message: String },

    #[error("Anomaly detection failed: {message}")]
    AnomalyDetectionFailed { message: String },

    #[error("Behavioral analysis failed: {message}")]
    BehavioralAnalysisFailed { message: String },

    #[error("Timing analysis failed: {message}")]
    TimingAnalysisFailed { message: String },

    #[error("Insufficient data for analysis: {required_samples} samples needed")]
    InsufficientData { required_samples: usize },

    #[error("Invalid threshold configuration: {parameter}")]
    InvalidThreshold { parameter: String },

    #[error("Statistical analysis error: {message}")]
    StatisticalError { message: String },
}

/// Vulnerability scanner errors
#[derive(Error, Debug)]
pub enum VulnerabilityError {
    #[error("Database update failed: {message}")]
    DatabaseUpdateFailed { message: String },

    #[error("Dependency scan failed: {message}")]
    DependencyScanFailed { message: String },

    #[error("Code scan failed: {message}")]
    CodeScanFailed { message: String },

    #[error("Network vulnerability check failed: {message}")]
    NetworkCheckFailed { message: String },

    #[error("CVE lookup failed: {cve_id}")]
    CveLookupFailed { cve_id: String },

    #[error("Risk assessment failed: {message}")]
    RiskAssessmentFailed { message: String },
}

/// Cryptographic validation errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Algorithm validation failed: {algorithm}")]
    AlgorithmValidationFailed { algorithm: String },

    #[error("Key validation failed: {key_type}")]
    KeyValidationFailed { key_type: String },

    #[error("Side-channel test failed: {test_name}")]
    SideChannelTestFailed { test_name: String },

    #[error("Randomness test failed: {test_name}")]
    RandomnessTestFailed { test_name: String },

    #[error("Formal verification failed: {component}")]
    FormalVerificationFailed { component: String },

    #[error("Implementation vulnerability: {vulnerability}")]
    ImplementationVulnerability { vulnerability: String },

    #[error("Constant-time operation violation: {operation}")]
    ConstantTimeViolation { operation: String },
}

/// Static analysis errors
#[derive(Error, Debug)]
pub enum StaticAnalysisError {
    #[error("Code analysis failed: {message}")]
    AnalysisFailed { message: String },

    #[error("Pattern matching failed: {pattern}")]
    PatternMatchingFailed { pattern: String },

    #[error("Complexity analysis failed: {message}")]
    ComplexityAnalysisFailed { message: String },

    #[error("Tool execution failed: {tool}")]
    ToolExecutionFailed { tool: String },

    #[error("Invalid configuration: {message}")]
    ConfigurationError { message: String },
}

impl From<std::io::Error> for AuditError {
    fn from(error: std::io::Error) -> Self {
        AuditError::IoError { source: error }
    }
}

impl From<serde_json::Error> for AuditError {
    fn from(error: serde_json::Error) -> Self {
        AuditError::SerializationError { source: error }
    }
}

/// Security hardening errors
#[derive(Error, Debug)]
pub enum HardeningError {
    #[error("Runtime protection setup failed: {message}")]
    RuntimeProtectionFailed { message: String },

    #[error("HSM integration failed: {message}")]
    HsmIntegrationFailed { message: String },

    #[error("Key management failed: {message}")]
    KeyManagementFailed { message: String },

    #[error("Network security configuration failed: {message}")]
    NetworkSecurityFailed { message: String },

    #[error("Operational security setup failed: {message}")]
    OperationalSecurityFailed { message: String },

    #[error("Attack detection failed: {message}")]
    AttackDetectionFailed { message: String },

    #[error("Security configuration invalid: {parameter}")]
    InvalidSecurityConfiguration { parameter: String },

    #[error("System hardening failed: {component}")]
    SystemHardeningFailed { component: String },

    #[error("Security validation failed: {check}")]
    ValidationFailed { check: String },
}

/// HSM integration errors
#[derive(Error, Debug)]
pub enum HsmError {
    #[error("HSM connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Key generation failed: {key_type}")]
    KeyGenerationFailed { key_type: String },

    #[error("Signing operation failed: {message}")]
    SigningFailed { message: String },

    #[error("Encryption operation failed: {message}")]
    EncryptionFailed { message: String },

    #[error("Decryption operation failed: {message}")]
    DecryptionFailed { message: String },

    #[error("Key rotation failed: {key_id}")]
    KeyRotationFailed { key_id: String },

    #[error("HSM health check failed: {message}")]
    HealthCheckFailed { message: String },

    #[error("HSM authentication failed")]
    AuthenticationFailed,

    #[error("Invalid HSM configuration: {parameter}")]
    InvalidConfiguration { parameter: String },

    #[error("Policy not found for key type: {key_type}")]
    PolicyNotFound { key_type: String },

    #[error("Schedule not found for key type: {key_type}")]
    ScheduleNotFound { key_type: String },
}

/// Network security errors
#[derive(Error, Debug)]
pub enum NetworkSecurityError {
    #[error("TLS configuration failed: {message}")]
    TlsConfigurationFailed { message: String },

    #[error("Certificate validation failed: {message}")]
    CertificateValidationFailed { message: String },

    #[error("Traffic obfuscation failed: {message}")]
    TrafficObfuscationFailed { message: String },

    #[error("DDoS protection setup failed: {message}")]
    DdosProtectionFailed { message: String },

    #[error("Network monitoring failed: {message}")]
    NetworkMonitoringFailed { message: String },

    #[error("Rate limiting failed: {message}")]
    RateLimitingFailed { message: String },

    #[error("Connection throttling failed: {message}")]
    ConnectionThrottlingFailed { message: String },

    #[error("Invalid network configuration: {parameter}")]
    InvalidNetworkConfiguration { parameter: String },
}

/// Operational security errors
#[derive(Error, Debug)]
pub enum OperationalSecurityError {
    #[error("Incident response failed: {message}")]
    IncidentResponseFailed { message: String },

    #[error("Security logging failed: {message}")]
    SecurityLoggingFailed { message: String },

    #[error("Backup operation failed: {message}")]
    BackupOperationFailed { message: String },

    #[error("Access control enforcement failed: {message}")]
    AccessControlFailed { message: String },

    #[error("Policy enforcement failed: {message}")]
    PolicyEnforcementFailed { message: String },

    #[error("Log integrity check failed: {message}")]
    LogIntegrityFailed { message: String },

    #[error("Recovery procedure failed: {message}")]
    RecoveryFailed { message: String },

    #[error("Invalid operational configuration: {parameter}")]
    InvalidOperationalConfiguration { parameter: String },
}

// Error conversions for HardeningError
impl From<NetworkSecurityError> for HardeningError {
    fn from(err: NetworkSecurityError) -> Self {
        HardeningError::NetworkSecurityFailed {
            message: err.to_string(),
        }
    }
}

impl From<OperationalSecurityError> for HardeningError {
    fn from(err: OperationalSecurityError) -> Self {
        HardeningError::OperationalSecurityFailed {
            message: err.to_string(),
        }
    }
}

impl From<HsmError> for HardeningError {
    fn from(err: HsmError) -> Self {
        HardeningError::KeyManagementFailed {
            message: err.to_string(),
        }
    }
}

/// Runtime protection errors
#[derive(Error, Debug)]
pub enum RuntimeProtectionError {
    #[error("ASLR setup failed: {message}")]
    AslrSetupFailed { message: String },

    #[error("Stack protection failed: {message}")]
    StackProtectionFailed { message: String },

    #[error("CFI setup failed: {message}")]
    CfiSetupFailed { message: String },

    #[error("Attack detection failed: {message}")]
    AttackDetectionFailed { message: String },

    #[error("Memory protection failed: {message}")]
    MemoryProtectionFailed { message: String },

    #[error("System call filtering failed: {message}")]
    SyscallFilteringFailed { message: String },
}
