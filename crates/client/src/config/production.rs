use crate::errors::{ClientError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProductionConfig {
    /// Production deployment mode configuration
    pub deployment: DeploymentConfig,

    /// Logging configuration for production
    pub logging: LoggingConfig,

    /// Performance configuration
    pub performance: PerformanceConfig,

    /// Security hardening settings
    pub security: SecurityConfig,

    /// Error handling configuration
    pub error_handling: ErrorHandlingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    /// Production environment indicator
    pub is_production: bool,

    /// Application version
    pub version: String,

    /// Build timestamp
    pub build_timestamp: String,

    /// Feature flags for production
    pub feature_flags: FeatureFlags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level for production (Info, Warn, Error)
    pub level: LogLevel,

    /// Enable structured logging (JSON format)
    pub structured: bool,

    /// Log rotation settings
    pub rotation: LogRotationConfig,

    /// Disable debug logs in production
    pub disable_debug: bool,

    /// Enable audit logging
    pub audit_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRotationConfig {
    /// Maximum log file size in MB
    pub max_size_mb: u64,

    /// Number of rotated log files to keep
    pub keep_files: u32,

    /// Log file name pattern
    pub file_pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Connection pool size
    pub connection_pool_size: u32,

    /// Request timeout
    pub request_timeout: Duration,

    /// Maximum concurrent operations
    pub max_concurrent_ops: u32,

    /// Memory limit for operations
    pub memory_limit_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable strict TLS verification
    pub strict_tls: bool,

    /// Minimum TLS version
    pub min_tls_version: String,

    /// Enable certificate pinning
    pub cert_pinning: bool,

    /// Security validation level
    pub validation_level: SecurityValidationLevel,

    /// Enable security audit logging
    pub audit_security_events: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorHandlingConfig {
    /// Disable error details in production
    pub sanitize_errors: bool,

    /// Error reporting endpoint
    pub error_reporting_endpoint: Option<String>,

    /// Maximum error context to include
    pub max_error_context: u32,

    /// Enable error aggregation
    pub aggregate_errors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    /// Enable experimental features
    pub experimental: bool,

    /// Enable debug endpoints
    pub debug_endpoints: bool,

    /// Enable profiling
    pub profiling: bool,

    /// Enable metrics collection
    pub metrics: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityValidationLevel {
    Strict,
    Standard,
    Relaxed,
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self::production_defaults()
    }
}

impl ProductionConfig {
    /// Create production-hardened configuration
    pub fn production_defaults() -> Self {
        Self {
            deployment: DeploymentConfig {
                is_production: true,
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_timestamp: chrono::Utc::now().to_rfc3339(),
                feature_flags: FeatureFlags {
                    experimental: false,
                    debug_endpoints: false,
                    profiling: false,
                    metrics: true,
                },
            },
            logging: LoggingConfig {
                level: LogLevel::Info,
                structured: true,
                rotation: LogRotationConfig {
                    max_size_mb: 100,
                    keep_files: 10,
                    file_pattern: "pqcrypt-client-%Y%m%d-%H%M%S.log".to_string(),
                },
                disable_debug: true,
                audit_enabled: true,
            },
            performance: PerformanceConfig {
                connection_pool_size: 10,
                request_timeout: Duration::from_secs(30),
                max_concurrent_ops: 100,
                memory_limit_mb: 512,
            },
            security: SecurityConfig {
                strict_tls: true,
                min_tls_version: "1.3".to_string(),
                cert_pinning: true,
                validation_level: SecurityValidationLevel::Strict,
                audit_security_events: true,
            },
            error_handling: ErrorHandlingConfig {
                sanitize_errors: true,
                error_reporting_endpoint: None,
                max_error_context: 100,
                aggregate_errors: true,
            },
        }
    }

    /// Create development configuration
    pub fn development_defaults() -> Self {
        Self {
            deployment: DeploymentConfig {
                is_production: false,
                version: env!("CARGO_PKG_VERSION").to_string(),
                build_timestamp: chrono::Utc::now().to_rfc3339(),
                feature_flags: FeatureFlags {
                    experimental: true,
                    debug_endpoints: true,
                    profiling: true,
                    metrics: true,
                },
            },
            logging: LoggingConfig {
                level: LogLevel::Debug,
                structured: false,
                rotation: LogRotationConfig {
                    max_size_mb: 50,
                    keep_files: 5,
                    file_pattern: "pqcrypt-client-dev-%Y%m%d.log".to_string(),
                },
                disable_debug: false,
                audit_enabled: true,
            },
            performance: PerformanceConfig {
                connection_pool_size: 5,
                request_timeout: Duration::from_secs(60),
                max_concurrent_ops: 50,
                memory_limit_mb: 256,
            },
            security: SecurityConfig {
                strict_tls: false,
                min_tls_version: "1.2".to_string(),
                cert_pinning: false,
                validation_level: SecurityValidationLevel::Standard,
                audit_security_events: true,
            },
            error_handling: ErrorHandlingConfig {
                sanitize_errors: false,
                error_reporting_endpoint: None,
                max_error_context: 1000,
                aggregate_errors: false,
            },
        }
    }

    /// Validate production configuration
    pub fn validate(&self) -> Result<(), ClientError> {
        if self.deployment.is_production {
            // Production-specific validation
            if !self.logging.disable_debug {
                return Err(ClientError::configuration_error(
                    "Debug logging must be disabled in production",
                ));
            }

            if self.deployment.feature_flags.debug_endpoints {
                return Err(ClientError::configuration_error(
                    "Debug endpoints must be disabled in production",
                ));
            }

            if !self.error_handling.sanitize_errors {
                return Err(ClientError::configuration_error(
                    "Error sanitization must be enabled in production",
                ));
            }

            if !self.security.strict_tls {
                return Err(ClientError::configuration_error(
                    "Strict TLS must be enabled in production",
                ));
            }
        }

        // General validation
        if self.performance.connection_pool_size == 0 {
            return Err(ClientError::configuration_error(
                "Connection pool size must be greater than 0",
            ));
        }

        if self.performance.request_timeout.as_secs() == 0 {
            return Err(ClientError::configuration_error(
                "Request timeout must be greater than 0",
            ));
        }

        Ok(())
    }

    /// Check if running in production mode
    pub fn is_production(&self) -> bool {
        self.deployment.is_production
    }

    /// Get sanitized error message for production
    pub fn sanitize_error(&self, error: &str, error_code: ErrorCode) -> String {
        if self.error_handling.sanitize_errors && self.deployment.is_production {
            // Return generic message with error code only
            format!("Operation failed (Error: {})", error_code as u32)
        } else {
            // Return full error in development
            error.to_string()
        }
    }

    /// Create production logger configuration
    pub fn create_logger_config(&self) -> LoggerConfig {
        LoggerConfig {
            level: self.logging.level.clone(),
            structured: self.logging.structured,
            audit_enabled: self.logging.audit_enabled,
            file_pattern: self.logging.rotation.file_pattern.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LoggerConfig {
    pub level: LogLevel,
    pub structured: bool,
    pub audit_enabled: bool,
    pub file_pattern: String,
}

impl LogLevel {
    pub fn to_log_level_filter(&self) -> log::LevelFilter {
        match self {
            LogLevel::Error => log::LevelFilter::Error,
            LogLevel::Warn => log::LevelFilter::Warn,
            LogLevel::Info => log::LevelFilter::Info,
            LogLevel::Debug => log::LevelFilter::Debug,
            LogLevel::Trace => log::LevelFilter::Trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_production_config_validation() {
        let config = ProductionConfig::production_defaults();
        assert!(config.validate().is_ok());

        // Verify production hardening
        assert!(config.deployment.is_production);
        assert!(config.logging.disable_debug);
        assert!(!config.deployment.feature_flags.debug_endpoints);
        assert!(config.error_handling.sanitize_errors);
        assert!(config.security.strict_tls);
    }

    #[test]
    fn test_development_config_validation() {
        let config = ProductionConfig::development_defaults();
        assert!(config.validate().is_ok());

        // Verify development flexibility
        assert!(!config.deployment.is_production);
        assert!(!config.logging.disable_debug);
        assert!(config.deployment.feature_flags.debug_endpoints);
        assert!(!config.error_handling.sanitize_errors);
    }

    #[test]
    fn test_error_sanitization() {
        let prod_config = ProductionConfig::production_defaults();
        let dev_config = ProductionConfig::development_defaults();

        let error_msg = "Detailed error: database connection failed at line 123";
        let error_code = ErrorCode::StorageTransaction;

        // Production should sanitize
        let prod_result = prod_config.sanitize_error(error_msg, error_code);
        assert!(prod_result.contains("Operation failed"));
        assert!(!prod_result.contains("database connection"));

        // Development should preserve details
        let dev_result = dev_config.sanitize_error(error_msg, error_code);
        assert_eq!(dev_result, error_msg);
    }

    #[test]
    fn test_invalid_production_config() {
        let mut config = ProductionConfig::production_defaults();

        // Enable debug in production (should fail)
        config.logging.disable_debug = false;
        assert!(config.validate().is_err());

        // Enable debug endpoints in production (should fail)
        config.logging.disable_debug = true;
        config.deployment.feature_flags.debug_endpoints = true;
        assert!(config.validate().is_err());
    }
}
