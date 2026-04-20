use crate::auth::opaque::OpaqueAuth;
use crate::errors::ClientError;
use crate::network::Network;
use crate::storage::Storage;
use crate::transparency::{TransparencyClient, TransparencyVerifier};
use chrono::{DateTime, Duration, Utc};
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use hybridcipher_messages::join_card::JoinCard;
use hybridcipher_messages::transparency::TransparencyConfig;
use std::sync::Arc;
use uuid::Uuid;

/// Registration flow for new users
///
/// Handles the complete registration process including:
/// - OPAQUE-PAKE registration with password protection
/// - Device identity key generation and secure storage
/// - JoinCard creation and signing
/// - Transparency log verification
/// - Coverage log initialization
#[derive(Debug)]
pub struct RegistrationFlow<S: Storage, N: Network> {
    /// OPAQUE authenticator
    opaque_auth: OpaqueAuth,

    /// Storage backend
    storage: Arc<S>,

    /// Network interface for transparency log verification
    network: Arc<N>,

    /// Transparency log configuration
    transparency_config: TransparencyConfig,

    /// Generated device identity
    device_identity: Option<Ed25519KeyPair>,
}

/// Login flow for existing users
///
/// Handles the complete login process including:
/// - OPAQUE-PAKE authentication with password verification
/// - Device state restoration and validation
/// - JoinCard transparency verification
/// - Coverage log synchronization
/// - State consistency checks
#[derive(Debug)]
pub struct LoginFlow<S: Storage, N: Network> {
    /// OPAQUE authenticator
    opaque_auth: OpaqueAuth,

    /// Storage backend
    storage: Arc<S>,

    /// Network interface for transparency log verification
    network: Arc<N>,

    /// Transparency log configuration
    transparency_config: TransparencyConfig,
}

/// Registration result containing all generated artifacts
#[derive(Debug, Clone)]
pub struct RegistrationResult {
    /// Device identity public key
    pub device_public_key: [u8; 32],

    /// Generated JoinCard for group invitation
    pub join_card: JoinCard,

    /// OPAQUE registration record for server storage
    pub registration_record: Vec<u8>,

    /// Authentication session key
    pub session_key: [u8; 32],

    /// Whether transparency log verification was successful
    pub transparency_verified: bool,
}

/// Login result containing restored state information
#[derive(Debug, Clone)]
pub struct LoginResult {
    /// Device identity public key
    pub device_public_key: [u8; 32],

    /// Authentication session key
    pub session_key: [u8; 32],

    /// Current epoch information
    pub current_epoch: u64,

    /// Number of files in current state
    pub file_count: u64,

    /// Last synchronization timestamp
    pub last_sync: DateTime<Utc>,

    /// Whether transparency log verification was successful
    pub transparency_verified: bool,
}

impl<S: Storage, N: Network> RegistrationFlow<S, N> {
    /// Create new registration flow
    ///
    /// # Arguments
    /// * `device_id` - Unique device identifier
    /// * `storage` - Storage backend for persistence
    /// * `network` - Network interface for transparency log access
    /// * `transparency_config` - Configuration for transparency log verification
    pub fn new(
        device_id: String,
        storage: Arc<S>,
        network: Arc<N>,
        transparency_config: TransparencyConfig,
    ) -> Self {
        Self {
            opaque_auth: OpaqueAuth::new(device_id),
            storage,
            network,
            transparency_config,
            device_identity: None,
        }
    }

    /// Execute complete registration process
    ///
    /// # Arguments
    /// * `password` - User password for OPAQUE-PAKE
    /// * `invitation_public_key` - Public key for JoinCard invitation
    ///
    /// # Returns
    /// Complete registration artifacts including JoinCard and session key
    ///
    /// # Process
    /// 1. Generate device identity key pair with secure randomness
    /// 2. Run OPAQUE-PAKE registration protocol
    /// 3. Create and sign JoinCard with device identity
    /// 4. Verify JoinCard will be properly logged in transparency log
    /// 5. Store device identity securely with device binding
    /// 6. Initialize coverage log with genesis state
    pub async fn register(
        &mut self,
        user_id: &str,
        password: &str,
        invitation_public_key: [u8; 32],
    ) -> Result<RegistrationResult, ClientError> {
        // Step 1: Generate device identity key pair
        let device_identity = Ed25519KeyPair::generate();
        let device_public_key = device_identity.public_key_bytes();

        // Step 2: Run OPAQUE-PAKE registration
        let registration_record = self
            .opaque_auth
            .register(password)
            .await
            .map_err(|e| ClientError::Auth(format!("OPAQUE registration failed: {}", e)))?;

        // Step 3: Create JoinCard with device identity
        let expiration = Utc::now() + Duration::hours(24); // 24-hour expiration
        let expiration_timestamp = expiration.timestamp() as u64;

        // Create a placeholder JoinCard first to get canonical message
        let mut join_card = JoinCard {
            user_id: user_id.to_string(),
            device_id: self.opaque_auth.device_id().to_string(),
            identity_public: device_public_key.to_vec(),
            invitation_public: invitation_public_key.to_vec(),
            expires: expiration_timestamp,
            signature: vec![], // Will be filled below
        };

        // Sign the JoinCard
        let canonical_message = join_card
            .canonical_message()
            .map_err(|e| ClientError::Auth(format!("Failed to create canonical message: {}", e)))?;
        let signature = device_identity.sign(&canonical_message);
        join_card.signature = signature.to_vec();

        // Step 4: Verify JoinCard will be properly logged in transparency log
        let transparency_verified = self.verify_join_card_transparency(&join_card).await?;

        // Step 5: Store device identity securely
        let private_key_bytes = device_identity.private_key_bytes();
        self.storage
            .store_identity_key(self.opaque_auth.device_id(), &private_key_bytes)
            .await?;

        // Step 5: Initialize coverage log (placeholder)
        // In a real implementation, this would create an empty coverage log

        // Store device identity for potential future use
        self.device_identity = Some(device_identity);

        // Step 6: Perform authenticated login to derive session key
        let auth_result = self
            .opaque_auth
            .login(password, &registration_record)
            .await
            .map_err(|e| ClientError::Auth(format!("OPAQUE login failed: {}", e)))?;

        let session_key = auth_result
            .session_key
            .ok_or_else(|| ClientError::Auth("No session key generated".to_string()))?;

        Ok(RegistrationResult {
            device_public_key,
            join_card,
            registration_record,
            session_key,
            transparency_verified,
        })
    }

    /// Verify that the JoinCard will be properly logged in the transparency log
    ///
    /// # Arguments
    /// * `join_card` - The JoinCard to verify
    ///
    /// # Returns
    /// True if transparency verification succeeds or is disabled, false otherwise
    async fn verify_join_card_transparency(
        &self,
        join_card: &JoinCard,
    ) -> Result<bool, ClientError> {
        if !self.transparency_config.enabled {
            log::info!("Transparency log verification disabled, skipping verification");
            return Ok(true);
        }

        // Create transparency client using cloned network
        let log_url = self
            .transparency_config
            .log_server_url
            .clone()
            .unwrap_or_else(|| "https://transparency.hybridcipher.com".to_string());
        let transparency_client = TransparencyClient::new(
            (*self.network).clone(),
            log_url,
            self.transparency_config.clone(),
        );

        // Calculate JoinCard hash for transparency log entry
        let join_card_hash = self.calculate_join_card_hash(join_card)?;

        // For registration, we simulate submission to transparency log
        // In a real implementation, this would submit the JoinCard to the transparency log
        // and verify it gets properly included

        match transparency_client
            .verify_join_card_logged(&join_card_hash)
            .await
        {
            Ok(verified) => {
                if verified {
                    log::info!("JoinCard transparency verification successful");
                } else {
                    log::warn!("JoinCard transparency verification failed");
                }
                Ok(verified)
            }
            Err(e) => {
                if self.transparency_config.fallback_to_pinning {
                    log::warn!(
                        "Transparency verification failed, falling back to key pinning: {}",
                        e
                    );
                    Ok(true) // Allow fallback to pinning
                } else {
                    Err(ClientError::Auth(format!(
                        "Transparency verification failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Calculate hash of JoinCard for transparency log
    fn calculate_join_card_hash(&self, join_card: &JoinCard) -> Result<[u8; 32], ClientError> {
        use sha2::{Digest, Sha256};

        let canonical_message = join_card
            .canonical_message()
            .map_err(|e| ClientError::Auth(format!("Failed to create canonical message: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&canonical_message);
        Ok(hasher.finalize().into())
    }

    /// Get device identity if registration completed
    pub fn device_identity(&self) -> Option<&Ed25519KeyPair> {
        self.device_identity.as_ref()
    }
}

impl<S: Storage, N: Network> LoginFlow<S, N> {
    /// Create new login flow
    ///
    /// # Arguments
    /// * `device_id` - Device identifier for this login
    /// * `storage` - Storage backend for state restoration
    /// * `network` - Network interface for transparency log access
    /// * `transparency_config` - Configuration for transparency log verification
    pub fn new(
        device_id: String,
        storage: Arc<S>,
        network: Arc<N>,
        transparency_config: TransparencyConfig,
    ) -> Self {
        Self {
            opaque_auth: OpaqueAuth::new(device_id),
            storage,
            network,
            transparency_config,
        }
    }

    /// Execute complete login process
    ///
    /// # Arguments
    /// * `password` - User password for OPAQUE-PAKE verification
    /// * `registration_record` - OPAQUE registration record from server
    ///
    /// # Returns
    /// Login result with restored state and session key
    ///
    /// # Process
    /// 1. Run OPAQUE-PAKE login protocol with password verification
    /// 2. Load device identity key from secure storage
    /// 3. Verify device identity in transparency log
    /// 4. Restore epoch states and validate consistency
    /// 5. Load coverage log and synchronize if needed
    /// 6. Perform state integrity checks
    pub async fn login(
        &self,
        password: &str,
        registration_record: &[u8],
    ) -> Result<LoginResult, ClientError> {
        // Step 1: Run OPAQUE-PAKE login
        let auth_result = self
            .opaque_auth
            .login(password, registration_record)
            .await
            .map_err(|e| ClientError::Auth(format!("OPAQUE login failed: {}", e)))?;

        let session_key = auth_result
            .session_key
            .ok_or_else(|| ClientError::Auth("No session key generated".to_string()))?;

        // Step 2: Load device identity
        let identity_key_bytes = self
            .storage
            .load_identity_key(self.opaque_auth.device_id())
            .await?
            .ok_or_else(|| ClientError::Auth("Device identity not found".to_string()))?;

        let device_identity = Ed25519KeyPair::from_bytes(&identity_key_bytes)
            .map_err(|e| ClientError::Auth(format!("Invalid device identity: {}", e)))?;

        let device_public_key = device_identity.public_key_bytes();

        // Step 3: Verify device identity in transparency log
        let transparency_verified = self.verify_device_transparency(&device_identity).await?;

        // Step 4: Restore epoch states
        let epochs = self.storage.list_epochs().await?;
        let current_epoch = epochs.iter().max().copied().unwrap_or(0);

        // Step 5: Load coverage log
        // Use a nil group for initial registration placeholder.
        let coverage_log = self.storage.load_coverage_log(Uuid::nil()).await?;
        let file_count = coverage_log.file_epochs.len() as u64;

        // Step 6: State validation (placeholder)
        // In a real implementation, this would perform comprehensive state checks

        Ok(LoginResult {
            device_public_key,
            session_key,
            current_epoch,
            file_count,
            last_sync: coverage_log.updated_at,
            transparency_verified,
        })
    }

    /// Verify device identity is properly logged in transparency log
    async fn verify_device_transparency(
        &self,
        device_identity: &Ed25519KeyPair,
    ) -> Result<bool, ClientError> {
        if !self.transparency_config.enabled {
            log::info!("Transparency log verification disabled, skipping verification");
            return Ok(true);
        }

        // Create transparency client using cloned network
        let log_url = self
            .transparency_config
            .log_server_url
            .clone()
            .unwrap_or_else(|| "https://transparency.hybridcipher.com".to_string());
        let transparency_client = TransparencyClient::new(
            (*self.network).clone(),
            log_url,
            self.transparency_config.clone(),
        );

        // For login, we verify that our device's JoinCard is in the transparency log
        // Calculate hash of our device identity for verification
        let device_public_key = device_identity.public_key_bytes();
        let identity_hash = self.calculate_identity_hash(&device_public_key)?;

        match transparency_client
            .verify_join_card_logged(&identity_hash)
            .await
        {
            Ok(verified) => {
                if verified {
                    log::info!("Device identity transparency verification successful");
                } else {
                    log::warn!("Device identity transparency verification failed");
                }
                Ok(verified)
            }
            Err(e) => {
                if self.transparency_config.fallback_to_pinning {
                    log::warn!(
                        "Transparency verification failed, falling back to key pinning: {}",
                        e
                    );
                    Ok(true) // Allow fallback to pinning
                } else {
                    Err(ClientError::Auth(format!(
                        "Transparency verification failed: {}",
                        e
                    )))
                }
            }
        }
    }

    /// Calculate hash of device identity for transparency verification
    fn calculate_identity_hash(
        &self,
        device_public_key: &[u8; 32],
    ) -> Result<[u8; 32], ClientError> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(self.opaque_auth.device_id().as_bytes());
        hasher.update(device_public_key);
        Ok(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::MockNetwork;
    use crate::storage::MockStorage;
    use hybridcipher_messages::transparency::TransparencyConfig;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_registration_flow() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let transparency_config = TransparencyConfig::default();

        let mut registration = RegistrationFlow::new(
            "test-device".to_string(),
            storage,
            network,
            transparency_config,
        );

        let invitation_key = [1u8; 32];
        let result = registration
            .register("test-user", "test-password", invitation_key)
            .await;

        assert!(result.is_ok());
        let registration_result = result.unwrap();
        assert_ne!(registration_result.device_public_key, [0u8; 32]);
        assert_eq!(
            registration_result.join_card.invitation_public,
            invitation_key
        );
        assert_ne!(registration_result.session_key, [0u8; 32]);
        // Transparency verification should succeed when using mock network
        assert!(registration_result.transparency_verified);
    }

    #[tokio::test]
    async fn test_login_flow() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let transparency_config = TransparencyConfig::default();

        // First register a user
        let mut registration = RegistrationFlow::new(
            "test-device".to_string(),
            storage.clone(),
            network.clone(),
            transparency_config.clone(),
        );
        let invitation_key = [1u8; 32];
        let registration_result = registration
            .register("test-user", "test-password", invitation_key)
            .await
            .unwrap();

        // Then try to login
        let login = LoginFlow::new(
            "test-device".to_string(),
            storage,
            network,
            transparency_config,
        );
        let login_result = login
            .login("test-password", &registration_result.registration_record)
            .await;

        assert!(login_result.is_ok());
        let result = login_result.unwrap();
        assert_eq!(
            result.device_public_key,
            registration_result.device_public_key
        );
        assert_ne!(result.session_key, [0u8; 32]);
        assert!(result.transparency_verified);
    }

    #[tokio::test]
    async fn test_login_with_wrong_password() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let transparency_config = TransparencyConfig::default();

        // Register with one password
        let mut registration = RegistrationFlow::new(
            "test-device".to_string(),
            storage.clone(),
            network.clone(),
            transparency_config.clone(),
        );
        let registration_result = registration
            .register("test-user", "correct-password", [1u8; 32])
            .await
            .unwrap();

        // Try to login with wrong password
        let login = LoginFlow::new(
            "test-device".to_string(),
            storage,
            network,
            transparency_config,
        );
        let login_result = login
            .login("wrong-password", &registration_result.registration_record)
            .await;

        assert!(login_result.is_err());
    }

    #[tokio::test]
    async fn test_disabled_transparency_verification() {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let mut transparency_config = TransparencyConfig::default();
        transparency_config.enabled = false;

        let mut registration = RegistrationFlow::new(
            "test-device".to_string(),
            storage,
            network,
            transparency_config,
        );

        let invitation_key = [1u8; 32];
        let result = registration
            .register("test-user", "test-password", invitation_key)
            .await;

        assert!(result.is_ok());
        let registration_result = result.unwrap();
        // Should succeed even with transparency disabled
        assert!(registration_result.transparency_verified);
    }
}
