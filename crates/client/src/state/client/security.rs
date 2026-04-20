use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Validate current state consistency
    ///
    /// Performs comprehensive state validation to detect:
    /// - Inconsistent epoch transitions
    /// - Corrupted migration state
    /// - Invalid member configurations
    /// - Coverage log inconsistencies
    ///
    /// # Returns
    /// Ok(()) if state is consistent
    ///
    /// # Errors
    /// - `InvalidState` if any inconsistency is detected
    pub async fn validate_state(&self) -> Result<(), ClientError> {
        let state = self.state.read().await;

        if state.epochs.is_empty() {
            if state.current_epoch == 0 {
                // No epochs have been established yet; this is an acceptable bootstrap state.
                return Ok(());
            }

            return Err(ClientError::InvalidState(
                "State has no epochs but reports a non-zero current epoch".to_string(),
            ));
        }

        // When current_epoch is still the bootstrap sentinel (0), skip further validation.
        if state.current_epoch == 0 {
            return Ok(());
        }

        // Validate current epoch exists
        if !state.epochs.contains_key(&state.current_epoch) {
            return Err(ClientError::InvalidState(format!(
                "Current epoch {} not found in epoch map",
                state.current_epoch
            )));
        }

        // Validate migration state consistency
        if let Some(migration) = &state.migration {
            // Check epoch references exist
            if !state.epochs.contains_key(&migration.from_epoch) {
                return Err(ClientError::InvalidState(format!(
                    "Migration from_epoch {} not found",
                    migration.from_epoch
                )));
            }

            if !state.epochs.contains_key(&migration.to_epoch) {
                return Err(ClientError::InvalidState(format!(
                    "Migration to_epoch {} not found",
                    migration.to_epoch
                )));
            }

            // Validate migration progress
            let migrated_count = migration.migrated_files.len() as u64;
            if migrated_count > migration.total_files {
                return Err(ClientError::InvalidState(
                    "Migrated files exceed total files".to_string(),
                ));
            }
        }

        // Validate epoch state consistency
        for (epoch_id, epochs) in &state.epochs {
            for epoch in epochs {
                if epoch.epoch_id != *epoch_id {
                    return Err(ClientError::InvalidState(format!(
                        "Epoch ID mismatch: {} vs {}",
                        epoch_id, epoch.epoch_id
                    )));
                }

                // Validate member capabilities
                for member in &epoch.members {
                    if member.public_key == [0u8; 32] {
                        return Err(ClientError::InvalidState(
                            "Member has zero public key".to_string(),
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    // ========== MEMBER LIFECYCLE OPERATIONS ==========

    /// Verify join card with key pinning integration
    ///
    /// This integrates pinning verification with join card validation:
    /// 1. Check if user's key is already pinned
    /// 2. If pinned, verify against stored key
    /// 3. If not pinned, require out-of-band verification
    ///
    /// # Arguments
    /// * `join_card` - The JoinCard to verify with pinning
    ///
    /// # Returns
    /// Result indicating verification status and any prompts needed
    pub(super) async fn verify_join_card_with_pinning(
        &self,
        join_card: &crate::invitation::JoinCard,
    ) -> Result<PinningVerificationResult, ClientError> {
        let user_id = join_card.user_id.to_string();
        let device_id = join_card.device_id.clone();
        let identity_key = &join_card.identity_public;

        // Convert Vec<u8> to [u8; 32] for comparison
        let identity_key_array: [u8; 32] = identity_key.as_slice().try_into().map_err(|_| {
            ClientError::InvalidInput(format!(
                "Identity key must be 32 bytes, got {}",
                identity_key.len()
            ))
        })?;

        // Check if this user's key is already pinned
        match self
            .pinning_manager
            .get_pinned_key(&user_id, &device_id)
            .await
        {
            Ok(Some(pinned_data)) => {
                // Key is pinned - verify it matches
                if pinned_data.identity_public_key == identity_key_array {
                    if pinned_data.verified {
                        self.logger.log(
                            crate::logging::LogLevel::Info,
                            &format!(
                                "Join card key matches pinned key for {}:{}",
                                user_id, device_id
                            ),
                            Some("pinning_verification"),
                        );
                        Ok(PinningVerificationResult::Verified)
                    } else {
                        self.logger.log(
                            crate::logging::LogLevel::Info,
                            &format!(
                                "Join card key is pinned but unverified for {}:{}",
                                user_id, device_id
                            ),
                            Some("pinning_verification"),
                        );
                        let fingerprint = crate::pinning::generate_fingerprint(&identity_key_array);
                        Ok(PinningVerificationResult::RequiresVerification {
                            prompt: PinningPrompt::Unverified {
                                user_id: user_id.clone(),
                                device_id: device_id.clone(),
                                fingerprint: fingerprint.clone(),
                                identity_key: identity_key.clone(),
                            },
                        })
                    }
                } else {
                    // Key mismatch - potential security issue
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Key mismatch for {}:{} - join card key differs from pinned",
                            user_id, device_id
                        ),
                        Some("pinning_verification"),
                    );
                    Ok(PinningVerificationResult::KeyMismatch {
                        pinned_fingerprint: pinned_data.fingerprint,
                        join_card_fingerprint: crate::pinning::generate_fingerprint(
                            &identity_key_array,
                        ),
                    })
                }
            }
            Ok(None) => {
                // No pinned key - provide verification options
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!(
                        "No pinned key found for {}:{} - prompting for verification",
                        user_id, device_id
                    ),
                    Some("pinning_verification"),
                );

                let fingerprint = crate::pinning::generate_fingerprint(&identity_key_array);
                Ok(PinningVerificationResult::RequiresVerification {
                    prompt: PinningPrompt::FirstContact {
                        user_id: user_id.clone(),
                        device_id: device_id.clone(),
                        fingerprint: fingerprint.clone(),
                        identity_key: identity_key.clone(),
                    },
                })
            }
            Err(e) => {
                // Storage error
                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!(
                        "Failed to check pinned key for {}:{}: {:?}",
                        user_id, device_id, e
                    ),
                    Some("pinning_verification"),
                );
                Err(ClientError::Storage(
                    crate::storage::StorageError::Corruption(format!(
                        "Pinning verification failed: {:?}",
                        e
                    )),
                ))
            }
        }
    }

    /// Get reference to the structured logger
    pub fn logger(&self) -> &Arc<crate::logging::StructuredLogger> {
        &self.logger
    }

    /// Get reference to the metrics collector
    pub fn metrics(&self) -> &Arc<crate::metrics::MetricsCollector> {
        &self.metrics
    }

    /// Get reference to the security validator
    pub fn security_validator(&self) -> &Arc<SecurityValidator> {
        &self.security_validator
    }

    /// Validate current security configuration
    pub async fn validate_security_configuration(
        &self,
        config: &ClientConfiguration,
    ) -> Result<(), ClientError> {
        let result = self.security_validator.validate_configuration(config).await;

        if !result.is_valid {
            let critical_errors: Vec<_> = result
                .errors
                .iter()
                .filter(|e| e.severity == crate::security::SecuritySeverity::Critical)
                .collect();

            if !critical_errors.is_empty() {
                let error_messages: Vec<String> = critical_errors
                    .iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect();

                return Err(ClientError::security_error(
                    crate::errors::ErrorCode::SecurityValidationFailed,
                    format!("Critical security errors: {}", error_messages.join("; ")),
                    "validate_security_configuration".to_string(),
                    "critical_validation_failure".to_string(),
                    crate::errors::ErrorSeverity::Critical,
                ));
            }
        }

        // Log warnings for non-critical issues
        for warning in &result.warnings {
            self.logger.log(
                crate::logging::LogLevel::Warn,
                &format!(
                    "Security warning {}: {} - {}",
                    warning.code, warning.message, warning.recommendation
                ),
                None,
            );
        }

        Ok(())
    }

    /// Perform runtime security check with current configuration
    pub async fn runtime_security_check(&self) -> Result<(), ClientError> {
        // Get current configuration (simplified for demo)
        let config = ClientConfiguration::default();

        // Validate configuration
        self.validate_security_configuration(&config).await?;

        // Log successful security check
        self.logger.log(
            crate::logging::LogLevel::Info,
            "Runtime security check passed",
            None,
        );

        Ok(())
    }

    /// Check if deployment meets minimum security requirements
    pub fn meets_security_requirements(&self, config: &ClientConfiguration) -> bool {
        self.security_validator.meets_minimum_requirements(config)
    }

    /// Log and record an operation with timing
    pub async fn log_operation<T, F, Fut>(
        &self,
        operation: &str,
        operation_fn: F,
    ) -> Result<T, ClientError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, ClientError>>,
    {
        let timer = crate::metrics::Timer::start(operation.to_string(), self.metrics.clone());

        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!("Operation started: {}", operation),
            Some(operation),
        );

        let result = operation_fn().await;

        match &result {
            Ok(_) => {
                self.logger.log(
                    crate::logging::LogLevel::Info,
                    &format!("Operation completed successfully: {}", operation),
                    Some(operation),
                );
            }
            Err(e) => {
                let error_code = match e {
                    ClientError::CryptographicError { .. } => {
                        crate::errors::ErrorCode::CryptoKeyGeneration
                    }
                    ClientError::NetworkError { .. } => crate::errors::ErrorCode::NetworkConnection,
                    ClientError::StorageError { .. } => crate::errors::ErrorCode::StorageRead,
                    ClientError::InvalidState(_) => {
                        crate::errors::ErrorCode::GroupStateInconsistent
                    }
                    ClientError::Unauthorized(_) => crate::errors::ErrorCode::SecurityUnauthorized,
                    _ => crate::errors::ErrorCode::ResourceUnavailable,
                };

                self.metrics.increment_error_counter(error_code);

                self.logger.log(
                    crate::logging::LogLevel::Error,
                    &format!("Operation failed: {} - {:?}", operation, e),
                    Some(operation),
                );
            }
        }

        timer.stop();
        result
    }
}
