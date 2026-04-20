// Security module for HybridCipher client
// Provides security policy enforcement, configuration validation, and runtime security checks

pub mod validation;

pub use validation::{
    AuthConfiguration, ClientConfiguration, CryptoConfiguration, DeploymentMode,
    NetworkConfiguration, RuntimeSecurityChecker, SecurityError, SecurityPolicy,
    SecurityRecommendation, SecuritySeverity, SecurityValidationResult, SecurityValidator,
    SecurityWarning, SessionConfiguration, TlsVersion,
};

/// Initialize security subsystem with appropriate policies
pub fn initialize_security(deployment_mode: DeploymentMode) -> SecurityValidator {
    match deployment_mode {
        DeploymentMode::Production => SecurityValidator::production(),
        DeploymentMode::Development => SecurityValidator::development(),
        _ => SecurityValidator::production(), // Default to production security for staging/testing
    }
}

/// Quick security check for common insecure configurations
pub async fn quick_security_check(config: &ClientConfiguration) -> Result<(), String> {
    let validator = SecurityValidator::production();
    let result = validator.validate_configuration(config).await;

    // Check for critical errors
    let critical_errors: Vec<_> = result
        .errors
        .iter()
        .filter(|e| e.severity == SecuritySeverity::Critical)
        .collect();

    if !critical_errors.is_empty() {
        let error_messages: Vec<String> = critical_errors
            .iter()
            .map(|e| format!("{}: {}", e.code, e.message))
            .collect();
        return Err(format!(
            "Critical security errors: {}",
            error_messages.join("; ")
        ));
    }

    Ok(())
}
