// Security configuration validation and policy enforcement
// Ensures production deployments meet security requirements

use std::collections::HashMap;
use std::time::Duration;

use crate::audit::{audit_logger, AuditOutcome};
use crate::errors::{ClientError, ErrorCode};

/// Security policy configuration
#[derive(Debug, Clone)]
pub struct SecurityPolicy {
    /// Minimum password strength requirements
    pub min_password_length: usize,
    pub require_special_characters: bool,
    pub require_numbers: bool,
    pub require_uppercase: bool,

    /// Cryptographic requirements
    pub min_key_size_bits: usize,
    pub allowed_ciphers: Vec<String>,
    pub min_tls_version: TlsVersion,

    /// Session and timeout policies
    pub max_session_duration: Duration,
    pub idle_timeout: Duration,
    pub max_failed_attempts: u32,

    /// Development vs production settings
    pub allow_insecure_transport: bool,
    pub allow_weak_ciphers: bool,
    pub enable_debug_logging: bool,

    /// Resource limits
    pub max_concurrent_sessions: u32,
    pub max_file_size_mb: u64,
    pub max_group_size: u32,
}

/// TLS version requirements
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TlsVersion {
    V1_2,
    V1_3,
}

/// Security configuration validation results
#[derive(Debug)]
pub struct SecurityValidationResult {
    pub is_valid: bool,
    pub errors: Vec<SecurityError>,
    pub warnings: Vec<SecurityWarning>,
    pub recommendations: Vec<SecurityRecommendation>,
}

/// Security configuration errors (block deployment)
#[derive(Debug, Clone)]
pub struct SecurityError {
    pub code: String,
    pub message: String,
    pub severity: SecuritySeverity,
}

/// Security configuration warnings (allow with notification)
#[derive(Debug, Clone)]
pub struct SecurityWarning {
    pub code: String,
    pub message: String,
    pub recommendation: String,
}

/// Security recommendations for optimization
#[derive(Debug, Clone)]
pub struct SecurityRecommendation {
    pub area: String,
    pub suggestion: String,
    pub impact: String,
}

/// Security error severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecuritySeverity {
    Critical, // Blocks deployment
    High,     // Strong warning
    Medium,   // Warning
    Low,      // Recommendation
}

/// Security configuration validator
pub struct SecurityValidator {
    policy: SecurityPolicy,
    deployment_mode: DeploymentMode,
}

/// Deployment environment modes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentMode {
    Development,
    Testing,
    Staging,
    Production,
}

impl SecurityValidator {
    /// Create a new security validator with the specified policy
    pub fn new(policy: SecurityPolicy, deployment_mode: DeploymentMode) -> Self {
        Self {
            policy,
            deployment_mode,
        }
    }

    /// Create validator with production security policy
    pub fn production() -> Self {
        let policy = SecurityPolicy {
            min_password_length: 12,
            require_special_characters: true,
            require_numbers: true,
            require_uppercase: true,

            min_key_size_bits: 2048,
            allowed_ciphers: vec!["ChaCha20Poly1305".to_string(), "AES-256-GCM".to_string()],
            min_tls_version: TlsVersion::V1_3,

            max_session_duration: Duration::from_secs(8 * 3600), // 8 hours
            idle_timeout: Duration::from_secs(30 * 60),          // 30 minutes
            max_failed_attempts: 3,

            allow_insecure_transport: false,
            allow_weak_ciphers: false,
            enable_debug_logging: false,

            max_concurrent_sessions: 100,
            max_file_size_mb: 1024,
            max_group_size: 1000,
        };

        Self::new(policy, DeploymentMode::Production)
    }

    /// Create validator with development security policy (more permissive)
    pub fn development() -> Self {
        let policy = SecurityPolicy {
            min_password_length: 8,
            require_special_characters: false,
            require_numbers: false,
            require_uppercase: false,

            min_key_size_bits: 1024,
            allowed_ciphers: vec![
                "ChaCha20Poly1305".to_string(),
                "AES-256-GCM".to_string(),
                "AES-128-GCM".to_string(),
            ],
            min_tls_version: TlsVersion::V1_2,

            max_session_duration: Duration::from_secs(24 * 3600), // 24 hours
            idle_timeout: Duration::from_secs(2 * 3600),          // 2 hours
            max_failed_attempts: 10,

            allow_insecure_transport: true,
            allow_weak_ciphers: true,
            enable_debug_logging: true,

            max_concurrent_sessions: 10,
            max_file_size_mb: 100,
            max_group_size: 10,
        };

        Self::new(policy, DeploymentMode::Development)
    }

    /// Validate a complete security configuration
    pub async fn validate_configuration(
        &self,
        config: &ClientConfiguration,
    ) -> SecurityValidationResult {
        let mut result = SecurityValidationResult {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            recommendations: Vec::new(),
        };

        // Validate authentication settings
        self.validate_authentication(&mut result, &config.auth);

        // Validate cryptographic settings
        self.validate_cryptography(&mut result, &config.crypto);

        // Validate network security
        self.validate_network_security(&mut result, &config.network);

        // Validate session management
        self.validate_session_management(&mut result, &config.session);

        // Validate deployment-specific settings
        self.validate_deployment_settings(&mut result, config);

        // Log validation results
        self.log_validation_results(&result).await;

        result
    }

    /// Validate authentication configuration
    fn validate_authentication(
        &self,
        result: &mut SecurityValidationResult,
        auth_config: &AuthConfiguration,
    ) {
        // Password strength validation
        if auth_config.min_password_length < self.policy.min_password_length {
            result.errors.push(SecurityError {
                code: "AUTH_001".to_string(),
                message: format!(
                    "Password minimum length {} is below policy requirement of {}",
                    auth_config.min_password_length, self.policy.min_password_length
                ),
                severity: SecuritySeverity::High,
            });
        }

        // Password complexity requirements
        if self.policy.require_special_characters && !auth_config.require_special_characters {
            result.warnings.push(SecurityWarning {
                code: "AUTH_002".to_string(),
                message: "Special characters not required in passwords".to_string(),
                recommendation: "Enable special character requirement for stronger passwords"
                    .to_string(),
            });
        }

        // Failed attempt limits
        if auth_config.max_failed_attempts > self.policy.max_failed_attempts {
            result.errors.push(SecurityError {
                code: "AUTH_003".to_string(),
                message: format!(
                    "Max failed attempts {} exceeds policy limit of {}",
                    auth_config.max_failed_attempts, self.policy.max_failed_attempts
                ),
                severity: SecuritySeverity::Medium,
            });
        }
    }

    /// Validate cryptographic configuration
    fn validate_cryptography(
        &self,
        result: &mut SecurityValidationResult,
        crypto_config: &CryptoConfiguration,
    ) {
        // Key size validation
        if crypto_config.key_size_bits < self.policy.min_key_size_bits {
            result.errors.push(SecurityError {
                code: "CRYPTO_001".to_string(),
                message: format!(
                    "Key size {} bits is below minimum requirement of {} bits",
                    crypto_config.key_size_bits, self.policy.min_key_size_bits
                ),
                severity: SecuritySeverity::Critical,
            });
            result.is_valid = false;
        }

        // Cipher validation
        for cipher in &crypto_config.enabled_ciphers {
            if !self.policy.allowed_ciphers.contains(cipher) {
                if self.deployment_mode == DeploymentMode::Production {
                    result.errors.push(SecurityError {
                        code: "CRYPTO_002".to_string(),
                        message: format!("Cipher '{}' is not approved for production use", cipher),
                        severity: SecuritySeverity::High,
                    });
                } else {
                    result.warnings.push(SecurityWarning {
                        code: "CRYPTO_002".to_string(),
                        message: format!("Cipher '{}' is not recommended", cipher),
                        recommendation: "Use only approved ciphers for production deployment"
                            .to_string(),
                    });
                }
            }
        }

        // Weak cipher detection
        let weak_ciphers = ["DES", "3DES", "RC4", "MD5"];
        for cipher in &crypto_config.enabled_ciphers {
            if weak_ciphers.iter().any(|weak| cipher.contains(weak)) {
                result.errors.push(SecurityError {
                    code: "CRYPTO_003".to_string(),
                    message: format!("Weak cipher '{}' detected", cipher),
                    severity: SecuritySeverity::Critical,
                });
                result.is_valid = false;
            }
        }
    }

    /// Validate network security configuration
    fn validate_network_security(
        &self,
        result: &mut SecurityValidationResult,
        network_config: &NetworkConfiguration,
    ) {
        // TLS version validation
        if network_config.min_tls_version < self.policy.min_tls_version {
            if self.deployment_mode == DeploymentMode::Production {
                result.errors.push(SecurityError {
                    code: "NET_001".to_string(),
                    message: format!(
                        "TLS version {:?} is below minimum requirement of {:?}",
                        network_config.min_tls_version, self.policy.min_tls_version
                    ),
                    severity: SecuritySeverity::High,
                });
            } else {
                result.warnings.push(SecurityWarning {
                    code: "NET_001".to_string(),
                    message: "Using older TLS version".to_string(),
                    recommendation: "Upgrade to TLS 1.3 for production deployment".to_string(),
                });
            }
        }

        // Insecure transport detection
        if network_config.allow_insecure_transport && !self.policy.allow_insecure_transport {
            result.errors.push(SecurityError {
                code: "NET_002".to_string(),
                message: "Insecure transport is enabled but not allowed by policy".to_string(),
                severity: SecuritySeverity::Critical,
            });
            result.is_valid = false;
        }

        // Certificate validation
        if !network_config.verify_certificates && self.deployment_mode == DeploymentMode::Production
        {
            result.errors.push(SecurityError {
                code: "NET_003".to_string(),
                message: "Certificate verification is disabled in production mode".to_string(),
                severity: SecuritySeverity::Critical,
            });
            result.is_valid = false;
        }
    }

    /// Validate session management configuration
    fn validate_session_management(
        &self,
        result: &mut SecurityValidationResult,
        session_config: &SessionConfiguration,
    ) {
        // Session duration limits
        if session_config.max_duration > self.policy.max_session_duration {
            result.warnings.push(SecurityWarning {
                code: "SESSION_001".to_string(),
                message: "Session duration exceeds recommended maximum".to_string(),
                recommendation: "Reduce session duration to improve security".to_string(),
            });
        }

        // Idle timeout validation
        if session_config.idle_timeout > self.policy.idle_timeout {
            result.warnings.push(SecurityWarning {
                code: "SESSION_002".to_string(),
                message: "Idle timeout is longer than recommended".to_string(),
                recommendation: "Reduce idle timeout to prevent session hijacking".to_string(),
            });
        }

        // Concurrent session limits
        if session_config.max_concurrent > self.policy.max_concurrent_sessions {
            result.recommendations.push(SecurityRecommendation {
                area: "Session Management".to_string(),
                suggestion: "Consider reducing maximum concurrent sessions".to_string(),
                impact: "Lower resource usage and improved security monitoring".to_string(),
            });
        }
    }

    /// Validate deployment-specific settings
    fn validate_deployment_settings(
        &self,
        result: &mut SecurityValidationResult,
        config: &ClientConfiguration,
    ) {
        match self.deployment_mode {
            DeploymentMode::Production => {
                // Production-specific validations
                if config.debug_mode {
                    result.errors.push(SecurityError {
                        code: "DEPLOY_001".to_string(),
                        message: "Debug mode is enabled in production deployment".to_string(),
                        severity: SecuritySeverity::High,
                    });
                }

                if config.log_level == "DEBUG" || config.log_level == "TRACE" {
                    result.warnings.push(SecurityWarning {
                        code: "DEPLOY_002".to_string(),
                        message: "Debug logging enabled in production".to_string(),
                        recommendation: "Use INFO or WARN log level for production".to_string(),
                    });
                }

                // Check for development certificates
                if config.network.certificate_path.contains("dev")
                    || config.network.certificate_path.contains("test")
                {
                    result.errors.push(SecurityError {
                        code: "DEPLOY_003".to_string(),
                        message: "Development certificate detected in production".to_string(),
                        severity: SecuritySeverity::Critical,
                    });
                    result.is_valid = false;
                }
            }
            DeploymentMode::Development => {
                // Development-specific recommendations
                result.recommendations.push(SecurityRecommendation {
                    area: "Development Environment".to_string(),
                    suggestion: "Review security settings before production deployment".to_string(),
                    impact: "Ensure production security requirements are met".to_string(),
                });
            }
            _ => {
                // Staging/Testing validations
                if config.network.allow_insecure_transport {
                    result.warnings.push(SecurityWarning {
                        code: "DEPLOY_004".to_string(),
                        message: "Insecure transport allowed in non-production environment"
                            .to_string(),
                        recommendation: "Disable for production deployment".to_string(),
                    });
                }
            }
        }
    }

    /// Log validation results for audit trail
    async fn log_validation_results(&self, result: &SecurityValidationResult) {
        let outcome = if result.is_valid {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure {
                error_code: "SECURITY_VALIDATION_FAILED".to_string(),
                error_message: "Security validation failed".to_string(),
            }
        };

        let mut details = HashMap::new();
        details.insert(
            "deployment_mode".to_string(),
            format!("{:?}", self.deployment_mode),
        );
        details.insert("errors_count".to_string(), result.errors.len().to_string());
        details.insert(
            "warnings_count".to_string(),
            result.warnings.len().to_string(),
        );
        details.insert("is_valid".to_string(), result.is_valid.to_string());

        if let Some(logger) = audit_logger() {
            tokio::spawn(async move {
                use crate::audit::{AuditEvent, AuditEventType};
                use chrono::Utc;
                use serde_json::Value;

                let event = AuditEvent {
                    timestamp: Utc::now(),
                    event_type: AuditEventType::SystemAdmin {
                        operation: "security_validation".to_string(),
                        component: "SecurityValidator".to_string(),
                        admin_id: "system".to_string(),
                    },
                    user_id: None,
                    details: serde_json::to_value(details).unwrap_or(Value::Null),
                    outcome,
                    session_id: None,
                    source_ip: None,
                    user_agent: Some("SecurityValidator".to_string()),
                };

                if let Err(err) = logger.log_event(event) {
                    log::warn!("Failed to record security validation audit event: {}", err);
                }
            });
        }
    }

    /// Get security policy for deployment mode
    pub fn get_policy(&self) -> &SecurityPolicy {
        &self.policy
    }

    /// Check if configuration meets minimum security requirements
    pub fn meets_minimum_requirements(&self, config: &ClientConfiguration) -> bool {
        let result = futures::executor::block_on(self.validate_configuration(config));
        result.is_valid
            && result
                .errors
                .iter()
                .all(|e| e.severity != SecuritySeverity::Critical)
    }
}

/// Client configuration structure for validation
#[derive(Debug)]
pub struct ClientConfiguration {
    pub auth: AuthConfiguration,
    pub crypto: CryptoConfiguration,
    pub network: NetworkConfiguration,
    pub session: SessionConfiguration,
    pub debug_mode: bool,
    pub log_level: String,
}

/// Authentication configuration
#[derive(Debug)]
pub struct AuthConfiguration {
    pub min_password_length: usize,
    pub require_special_characters: bool,
    pub require_numbers: bool,
    pub require_uppercase: bool,
    pub max_failed_attempts: u32,
    pub lockout_duration: Duration,
}

/// Cryptographic configuration
#[derive(Debug)]
pub struct CryptoConfiguration {
    pub key_size_bits: usize,
    pub enabled_ciphers: Vec<String>,
    pub hash_algorithm: String,
    pub key_derivation_iterations: u32,
}

/// Network security configuration
#[derive(Debug)]
pub struct NetworkConfiguration {
    pub min_tls_version: TlsVersion,
    pub allow_insecure_transport: bool,
    pub verify_certificates: bool,
    pub certificate_path: String,
    pub trusted_ca_path: String,
}

/// Session management configuration
#[derive(Debug)]
pub struct SessionConfiguration {
    pub max_duration: Duration,
    pub idle_timeout: Duration,
    pub max_concurrent: u32,
    pub secure_cookies: bool,
    pub session_rotation: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        SecurityValidator::production().policy
    }
}

impl Default for ClientConfiguration {
    fn default() -> Self {
        Self {
            auth: AuthConfiguration {
                min_password_length: 8,
                require_special_characters: false,
                require_numbers: false,
                require_uppercase: false,
                max_failed_attempts: 5,
                lockout_duration: Duration::from_secs(15 * 60), // 15 minutes
            },
            crypto: CryptoConfiguration {
                key_size_bits: 2048,
                enabled_ciphers: vec!["ChaCha20Poly1305".to_string()],
                hash_algorithm: "SHA-256".to_string(),
                key_derivation_iterations: 100000,
            },
            network: NetworkConfiguration {
                min_tls_version: TlsVersion::V1_2,
                allow_insecure_transport: false,
                verify_certificates: true,
                certificate_path: "/etc/ssl/certs/hybridcipher.crt".to_string(),
                trusted_ca_path: "/etc/ssl/certs/ca-certificates.crt".to_string(),
            },
            session: SessionConfiguration {
                max_duration: Duration::from_secs(8 * 3600), // 8 hours
                idle_timeout: Duration::from_secs(30 * 60),  // 30 minutes
                max_concurrent: 100,
                secure_cookies: true,
                session_rotation: true,
            },
            debug_mode: false,
            log_level: "INFO".to_string(),
        }
    }
}

/// Runtime security checker for active monitoring
pub struct RuntimeSecurityChecker {
    validator: SecurityValidator,
    last_check: std::sync::Mutex<std::time::Instant>,
    check_interval: Duration,
}

impl RuntimeSecurityChecker {
    /// Create a new runtime security checker
    pub fn new(validator: SecurityValidator, check_interval: Duration) -> Self {
        Self {
            validator,
            last_check: std::sync::Mutex::new(std::time::Instant::now()),
            check_interval,
        }
    }

    /// Perform periodic security checks
    pub async fn periodic_check(&self, config: &ClientConfiguration) -> Result<(), ClientError> {
        let now = std::time::Instant::now();
        let should_check = {
            let mut last_check = self.last_check.lock().unwrap();
            if now.duration_since(*last_check) >= self.check_interval {
                *last_check = now;
                true
            } else {
                false
            }
        };

        if should_check {
            let result = self.validator.validate_configuration(config).await;
            if !result.is_valid {
                return Err(ClientError::security_error(
                    ErrorCode::SecurityValidationFailed,
                    "Runtime security validation failed".to_string(),
                    "periodic_security_check".to_string(),
                    "configuration_validation".to_string(),
                    crate::errors::ErrorSeverity::High,
                ));
            }

            // Log any new warnings
            for warning in &result.warnings {
                // Log warnings without using tracing directly
                eprintln!(
                    "Security warning {}: {} - {}",
                    warning.code, warning.message, warning.recommendation
                );
            }
        }

        Ok(())
    }

    /// Force immediate security check
    pub async fn immediate_check(
        &self,
        config: &ClientConfiguration,
    ) -> Result<SecurityValidationResult, ClientError> {
        let result = self.validator.validate_configuration(config).await;
        if !result.is_valid {
            return Err(ClientError::security_error(
                ErrorCode::SecurityValidationFailed,
                "Security validation failed".to_string(),
                "immediate_security_check".to_string(),
                "configuration_validation".to_string(),
                crate::errors::ErrorSeverity::High,
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_production_security_validation() {
        let validator = SecurityValidator::production();
        let config = ClientConfiguration::default();

        let result = validator.validate_configuration(&config).await;
        assert!(result.is_valid);
    }

    #[tokio::test]
    async fn test_insecure_configuration_detection() {
        let validator = SecurityValidator::production();
        let mut config = ClientConfiguration::default();
        config.crypto.key_size_bits = 512; // Weak key size
        config.network.allow_insecure_transport = true;

        let result = validator.validate_configuration(&config).await;
        assert!(!result.is_valid);
        assert!(!result.errors.is_empty());
    }

    #[tokio::test]
    async fn test_development_vs_production_policies() {
        let dev_validator = SecurityValidator::development();
        let prod_validator = SecurityValidator::production();

        let mut config = ClientConfiguration::default();
        config.auth.min_password_length = 6;

        let dev_result = dev_validator.validate_configuration(&config).await;
        let prod_result = prod_validator.validate_configuration(&config).await;

        // Development should be more permissive
        assert!(dev_result.is_valid);
        assert!(!prod_result.is_valid || !prod_result.errors.is_empty());
    }

    #[test]
    fn test_minimum_requirements_check() {
        let validator = SecurityValidator::production();
        let config = ClientConfiguration::default();

        assert!(validator.meets_minimum_requirements(&config));
    }
}
