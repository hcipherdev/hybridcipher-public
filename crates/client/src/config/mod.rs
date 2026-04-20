pub mod production;

pub use production::{
    DeploymentConfig, ErrorHandlingConfig, FeatureFlags, LogLevel, LoggerConfig, LoggingConfig,
    PerformanceConfig, ProductionConfig, SecurityConfig, SecurityValidationLevel,
};

use crate::errors::ClientError;

/// Global configuration manager for the client
pub struct ConfigManager {
    config: ProductionConfig,
}

impl ConfigManager {
    /// Create configuration manager with production defaults
    pub fn production() -> Result<Self, ClientError> {
        let config = ProductionConfig::production_defaults();
        config.validate()?;
        Ok(Self { config })
    }

    /// Create configuration manager with development defaults
    pub fn development() -> Result<Self, ClientError> {
        let config = ProductionConfig::development_defaults();
        config.validate()?;
        Ok(Self { config })
    }

    /// Create configuration manager from custom config
    pub fn from_config(config: ProductionConfig) -> Result<Self, ClientError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// Get the current configuration
    pub fn config(&self) -> &ProductionConfig {
        &self.config
    }

    /// Update configuration (validates before applying)
    pub fn update_config(&mut self, config: ProductionConfig) -> Result<(), ClientError> {
        config.validate()?;
        self.config = config;
        Ok(())
    }

    /// Check if running in production mode
    pub fn is_production(&self) -> bool {
        self.config.is_production()
    }
}

impl Default for ConfigManager {
    fn default() -> Self {
        // Default to production settings for safety
        Self::production().expect("Default production config should be valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_manager_creation() {
        let prod_manager = ConfigManager::production().unwrap();
        assert!(prod_manager.is_production());

        let dev_manager = ConfigManager::development().unwrap();
        assert!(!dev_manager.is_production());
    }

    #[test]
    fn test_config_validation() {
        let mut invalid_config = ProductionConfig::production_defaults();
        invalid_config.performance.connection_pool_size = 0;

        let result = ConfigManager::from_config(invalid_config);
        assert!(result.is_err());
    }
}
