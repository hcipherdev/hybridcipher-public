//! File Decryption with Dual-Epoch Support
//!
//! This module provides secure file decryption capabilities with support for:
//! - Dual-epoch decryption during migrations (current + previous epoch)
//! - Performance-optimized fallback mechanisms
//! - Intelligent key resolution with caching
//! - Comprehensive error handling and validation

use super::encrypt::{
    build_wrap_aad, derive_chunk_nonce, hash_wrap_aad, normalize_file_identifier,
    FileEncryptionMetadata, AEAD_TAG_SIZE,
};
use crate::{
    epoch::EpochManager,
    file::cache::CacheManager,
    network::Network,
    storage::{FileMetadataData, Storage, StorageError},
};
use chrono::{DateTime, Utc};
use hybridcipher_coverage::CoverageManager;
use hybridcipher_crypto::{
    aead::{open, AeadContext},
    kdf::{hkdf_expand, HkdfContext},
    signatures::Ed25519KeyPair,
    AeadKey, AeadNonce,
};
use log::{debug, trace, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;

/// File decryption errors
#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("File not found: {0}")]
    FileNotFound(String),

    #[error("Invalid file metadata: {0}")]
    InvalidMetadata(String),

    #[error("Key unwrapping failed: {0}")]
    KeyUnwrappingFailure(String),

    #[error("Decryption operation failed: {0}")]
    DecryptionFailure(String),

    #[error("Integrity verification failed: {0}")]
    IntegrityCheckFailure(String),

    #[error("No valid epoch key available: {0}")]
    NoValidEpochKey(String),

    #[error("Storage operation failed: {0}")]
    Storage(#[from] StorageError),

    #[error("Crypto operation failed: {0}")]
    Crypto(String),
}

/// File decryption result
#[derive(Debug, Clone)]
pub struct DecryptionResult {
    /// Decrypted file content
    pub content: Vec<u8>,
    /// File metadata used for decryption
    pub metadata: FileDecryptionMetadata,
    /// Epoch used for successful decryption
    pub epoch_used: u64,
    /// Whether dual-epoch fallback was used
    pub used_fallback: bool,
    /// Performance metrics for the operation
    pub metrics: DecryptionMetrics,
}

/// File decryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDecryptionMetadata {
    /// File identifier
    pub file_id: String,
    /// Primary epoch for decryption
    pub primary_epoch_id: u64,
    /// Fallback epoch for decryption (if any)
    pub fallback_epoch_id: Option<u64>,
    /// File size (encrypted)
    pub encrypted_size: u64,
    /// File size (decrypted)
    pub decrypted_size: u64,
    /// Decryption timestamp
    pub decrypted_at: DateTime<Utc>,
    /// Integrity hash verification result
    pub integrity_verified: bool,
    /// Algorithm used for decryption
    pub algorithm: String,
}

/// Performance metrics for decryption operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptionMetrics {
    /// Total operation time in milliseconds
    pub total_time_ms: u64,
    /// Key resolution time in milliseconds
    pub key_resolution_ms: u64,
    /// Decryption time in milliseconds
    pub decryption_time_ms: u64,
    /// Cache hit rate for this operation
    pub cache_hit: bool,
    /// Number of epoch keys tried
    pub epochs_attempted: u8,
}

/// File decryption manager with dual-epoch support
#[derive(Debug)]
pub struct FileDecryption<S: Storage, N: Network> {
    /// Storage backend
    storage: Arc<S>,
    /// Epoch manager for key resolution
    epoch_manager: Arc<EpochManager<S, N>>,
    /// Coverage manager for file tracking
    coverage_manager: Arc<CoverageManager<S>>,
    /// Performance cache
    cache: Arc<CacheManager>,
    /// Device identity for operations
    _device_identity: Ed25519KeyPair,
}

impl<S: Storage, N: Network> FileDecryption<S, N> {
    /// Create new file decryption manager
    pub fn new(
        storage: Arc<S>,
        epoch_manager: Arc<EpochManager<S, N>>,
        coverage_manager: Arc<CoverageManager<S>>,
        cache: Arc<CacheManager>,
        device_identity: Ed25519KeyPair,
    ) -> Self {
        Self {
            storage,
            epoch_manager,
            coverage_manager,
            cache,
            _device_identity: device_identity,
        }
    }

    /// Decrypt file with dual-epoch support and performance optimization
    pub async fn decrypt_file(&self, file_path: &str) -> Result<DecryptionResult, DecryptionError> {
        let start_time = std::time::Instant::now();

        // Step 1: Load file metadata and encrypted content
        let (metadata, encrypted_content) = self.load_file_data(file_path).await?;
        let encryption_metadata = Self::metadata_from_storage(&metadata)?;

        // Step 2: Determine epoch strategy (primary + fallback)
        let epoch_strategy = self.determine_epoch_strategy(&metadata).await?;

        // Step 3: Attempt decryption with primary epoch
        let key_resolution_start = std::time::Instant::now();
        let mut decryption_result = None;
        let mut epochs_attempted = 0;
        let mut used_fallback = false;

        // Try primary epoch first
        if let Ok(result) = self
            .attempt_decryption(
                &encrypted_content,
                &encryption_metadata,
                epoch_strategy.primary_epoch,
            )
            .await
        {
            decryption_result = Some(result);
            epochs_attempted = 1;
        }

        // Step 4: Try fallback epoch if primary failed and fallback available
        if decryption_result.is_none() {
            if let Some(fallback_epoch) = epoch_strategy.fallback_epoch {
                if let Ok(result) = self
                    .attempt_decryption(&encrypted_content, &encryption_metadata, fallback_epoch)
                    .await
                {
                    decryption_result = Some(result);
                    epochs_attempted = 2;
                    used_fallback = true;
                }
            }
        }

        let key_resolution_time = key_resolution_start.elapsed();

        // Step 5: Validate decryption success
        let (content, file_encryption_metadata, epoch_used) =
            decryption_result.ok_or_else(|| {
                DecryptionError::NoValidEpochKey(format!(
                    "No valid epoch key found for file: {}",
                    file_path
                ))
            })?;

        // Step 6: Verify file integrity
        let integrity_verified = self.verify_file_integrity(&content, &file_encryption_metadata)?;

        // Step 7: Update access statistics and cache
        self.update_access_stats(&encryption_metadata.file_id, epoch_used, !used_fallback)
            .await;

        let total_time = start_time.elapsed();

        let decrypted_size = content.len() as u64;

        Ok(DecryptionResult {
            content,
            metadata: FileDecryptionMetadata {
                file_id: encryption_metadata.file_id.clone(),
                primary_epoch_id: epoch_strategy.primary_epoch,
                fallback_epoch_id: epoch_strategy.fallback_epoch,
                encrypted_size: encrypted_content.len() as u64,
                decrypted_size,
                decrypted_at: Utc::now(),
                integrity_verified,
                algorithm: "ChaCha20-Poly1305".to_string(),
            },
            epoch_used,
            used_fallback,
            metrics: DecryptionMetrics {
                total_time_ms: total_time.as_millis() as u64,
                key_resolution_ms: key_resolution_time.as_millis() as u64,
                decryption_time_ms: (total_time - key_resolution_time).as_millis() as u64,
                cache_hit: self.cache.was_cache_hit(&encryption_metadata.file_id),
                epochs_attempted,
            },
        })
    }

    /// Load file metadata and encrypted content from storage
    async fn load_file_data(
        &self,
        file_path: &str,
    ) -> Result<(FileMetadataData, Vec<u8>), DecryptionError> {
        // Load metadata
        let metadata = self
            .storage
            .load_file_metadata(file_path)
            .await?
            .ok_or_else(|| {
                DecryptionError::FileNotFound(format!("No metadata found for: {}", file_path))
            })?;

        // Load encrypted content
        let encrypted_content = self.storage.get_file(file_path).await?.ok_or_else(|| {
            DecryptionError::FileNotFound(format!("No content found for: {}", file_path))
        })?;

        Ok((metadata, encrypted_content))
    }

    fn metadata_from_storage(
        metadata: &FileMetadataData,
    ) -> Result<FileEncryptionMetadata, DecryptionError> {
        let normalized_path = normalize_file_identifier(&metadata.file_path);
        let file_id = metadata.file_id.clone().ok_or_else(|| {
            DecryptionError::InvalidMetadata("Missing file_id in stored metadata".to_string())
        })?;
        let header_version = metadata.header_version.unwrap_or(1);
        let wrapped_file_key = metadata.wrapped_file_key.clone().ok_or_else(|| {
            DecryptionError::InvalidMetadata(
                "Missing wrapped_file_key in stored metadata".to_string(),
            )
        })?;
        let key_wrap_nonce = metadata.key_wrap_nonce.clone().ok_or_else(|| {
            DecryptionError::InvalidMetadata(
                "Missing key_wrap_nonce in stored metadata".to_string(),
            )
        })?;
        let key_wrap_aad_hash = metadata.key_wrap_aad_hash.clone().ok_or_else(|| {
            DecryptionError::InvalidMetadata(
                "Missing key_wrap_aad_hash in stored metadata".to_string(),
            )
        })?;
        let content_nonce = metadata.content_nonce.clone().ok_or_else(|| {
            DecryptionError::InvalidMetadata("Missing content_nonce in stored metadata".to_string())
        })?;

        let aad = {
            let mut hasher = Sha256::new();
            hasher.update(b"dek-wrap:v1:");
            hasher.update(file_id.as_bytes());
            hasher.update(&metadata.epoch_id.to_le_bytes());
            hasher.update(&header_version.to_le_bytes());
            hasher.finalize().to_vec()
        };

        Ok(FileEncryptionMetadata {
            file_id,
            file_path: normalized_path,
            group_id: metadata.group_id,
            epoch_id: metadata.epoch_id,
            header_version,
            wrapped_file_key,
            key_wrap_nonce,
            key_wrap_aad_hash,
            content_nonce,
            content_chunk_size: metadata.content_chunk_size,
            aad,
            encrypted_at: metadata.encrypted_at,
            original_size: metadata.file_size,
            content_hash: Vec::new(),
            algorithm: metadata.algorithm.clone(),
            file_size: metadata.file_size,
            integrity_hash: metadata.integrity_hash,
        })
    }

    /// Determine epoch strategy for decryption (primary + fallback)
    async fn determine_epoch_strategy(
        &self,
        metadata: &FileMetadataData,
    ) -> Result<EpochStrategy, DecryptionError> {
        let primary_epoch = metadata.epoch_id;
        let mut fallback_epoch = None;

        // Check if migration is active to determine fallback strategy
        if self.epoch_manager.is_migration_active().await {
            // During migration, files might be encrypted under previous epoch
            if let Some(current_epoch) = self.epoch_manager.current_epoch().await {
                if current_epoch.epoch_id != primary_epoch {
                    // File encrypted under different epoch, use current as fallback
                    fallback_epoch = Some(current_epoch.epoch_id);
                }
            }

            // Also check for migration target epoch
            if let Some(target_epoch) = self.epoch_manager.get_migration_target_epoch().await {
                if target_epoch != primary_epoch {
                    fallback_epoch = Some(target_epoch);
                }
            }
        }

        Ok(EpochStrategy {
            primary_epoch,
            fallback_epoch,
        })
    }

    /// Attempt decryption using specific epoch
    async fn attempt_decryption(
        &self,
        encrypted_content: &[u8],
        metadata: &FileEncryptionMetadata,
        epoch_id: u64,
    ) -> Result<(Vec<u8>, FileEncryptionMetadata, u64), DecryptionError> {
        // Step 1: Get epoch key
        let epoch_key = self.get_epoch_key(epoch_id).await?;

        // Step 2: Load file encryption metadata
        let file_metadata = metadata.clone();

        // Step 3: Unwrap file key
        let file_key = self.unwrap_file_key(&file_metadata, &epoch_key)?;

        // Step 4: Decrypt content
        let content = self.decrypt_content(encrypted_content, &file_key, &file_metadata)?;

        Ok((content, file_metadata, epoch_id))
    }

    /// Get epoch key with caching
    async fn get_epoch_key(&self, epoch_id: u64) -> Result<AeadKey, DecryptionError> {
        // Check cache first
        if let Some(cached_key) = self.cache.get_epoch_key(epoch_id) {
            return Ok(cached_key);
        }

        // Load from epoch manager
        let epoch_key = self
            .epoch_manager
            .get_epoch_key(epoch_id)
            .await
            .ok_or_else(|| {
                DecryptionError::NoValidEpochKey(format!("Epoch {} key not available", epoch_id))
            })?;

        // Cache for future use
        self.cache
            .store_epoch_key(epoch_id, &epoch_key)
            .map_err(|e| DecryptionError::Crypto(format!("Failed to cache epoch key: {}", e)))?;

        Ok(epoch_key)
    }

    /// Unwrap file key using KEK derived from the epoch key
    fn unwrap_file_key(
        &self,
        file_metadata: &FileEncryptionMetadata,
        epoch_key: &AeadKey,
    ) -> Result<AeadKey, DecryptionError> {
        let header_version = file_metadata.header_version;
        let wrap_aad = build_wrap_aad(
            &file_metadata.file_id,
            &file_metadata.file_path,
            file_metadata.group_id,
            file_metadata.epoch_id,
            header_version,
        );
        let actual = hash_wrap_aad(&wrap_aad);
        if actual != file_metadata.key_wrap_aad_hash {
            return Err(DecryptionError::KeyUnwrappingFailure(
                "Key wrap AAD hash mismatch".to_string(),
            ));
        }

        // Create nonce from metadata
        let nonce = AeadNonce::from_bytes(&file_metadata.key_wrap_nonce)
            .map_err(|e| DecryptionError::KeyUnwrappingFailure(format!("Invalid nonce: {}", e)))?;

        // Derive KEK from epoch key
        let kek_bytes = hkdf_expand(epoch_key.as_bytes(), HkdfContext::KeyWrapping, 32)
            .map_err(|e| DecryptionError::KeyUnwrappingFailure(format!("HKDF failed: {}", e)))?;
        let kek = AeadKey::from_bytes(&kek_bytes)
            .map_err(|e| DecryptionError::KeyUnwrappingFailure(format!("Invalid KEK: {}", e)))?;

        // Decrypt (unwrap) file key
        let file_key_bytes = open(
            &kek,
            &nonce,
            AeadContext::FileData,
            &wrap_aad,
            &file_metadata.wrapped_file_key,
        )
        .map_err(|e| {
            DecryptionError::KeyUnwrappingFailure(format!("Key unwrapping failed: {}", e))
        })?;

        AeadKey::from_bytes(&file_key_bytes).map_err(|e| {
            DecryptionError::KeyUnwrappingFailure(format!("Invalid unwrapped key: {}", e))
        })
    }

    /// Decrypt file content
    fn decrypt_content(
        &self,
        encrypted_content: &[u8],
        file_key: &AeadKey,
        file_metadata: &FileEncryptionMetadata,
    ) -> Result<Vec<u8>, DecryptionError> {
        if let Some(chunk_size) = file_metadata.content_chunk_size {
            return self.decrypt_content_chunked(
                encrypted_content,
                file_key,
                file_metadata,
                chunk_size as usize,
            );
        }

        // Create nonce for content decryption
        let nonce = AeadNonce::from_bytes(&file_metadata.content_nonce).map_err(|e| {
            DecryptionError::DecryptionFailure(format!("Invalid content nonce: {}", e))
        })?;

        // Create AAD for content decryption (file_id)
        let aad = file_metadata.file_id.as_bytes();

        // Decrypt content
        let context = AeadContext::FileData;
        open(file_key, &nonce, context, &aad, encrypted_content).map_err(|e| {
            DecryptionError::DecryptionFailure(format!("Content decryption failed: {}", e))
        })
    }

    fn decrypt_content_chunked(
        &self,
        encrypted_content: &[u8],
        file_key: &AeadKey,
        file_metadata: &FileEncryptionMetadata,
        chunk_size: usize,
    ) -> Result<Vec<u8>, DecryptionError> {
        if chunk_size == 0 {
            return Err(DecryptionError::DecryptionFailure(
                "chunk_size must be greater than 0".to_string(),
            ));
        }

        if file_metadata.content_nonce.len() != 12 {
            return Err(DecryptionError::DecryptionFailure(
                "Invalid content nonce length".to_string(),
            ));
        }

        let mut base_nonce = [0u8; 12];
        base_nonce.copy_from_slice(&file_metadata.content_nonce);

        let total_size = file_metadata.file_size as usize;
        let mut output = Vec::with_capacity(total_size);
        let mut offset = 0usize;
        let mut remaining = total_size;
        let mut chunk_index = 0u64;

        while remaining > 0 {
            let plain_len = usize::min(chunk_size, remaining);
            let cipher_len = plain_len + AEAD_TAG_SIZE;
            if offset + cipher_len > encrypted_content.len() {
                return Err(DecryptionError::DecryptionFailure(
                    "Chunked ciphertext truncated".to_string(),
                ));
            }
            let chunk_cipher = &encrypted_content[offset..offset + cipher_len];

            let nonce_bytes = derive_chunk_nonce(&base_nonce, chunk_index);
            let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
                DecryptionError::DecryptionFailure(format!("Invalid chunk nonce: {}", e))
            })?;

            let mut aad = Vec::with_capacity(file_metadata.file_id.len() + 8);
            aad.extend_from_slice(file_metadata.file_id.as_bytes());
            aad.extend_from_slice(&chunk_index.to_le_bytes());

            let plaintext = open(file_key, &nonce, AeadContext::FileData, &aad, chunk_cipher)
                .map_err(|e| {
                    DecryptionError::DecryptionFailure(format!("Chunk decrypt failed: {}", e))
                })?;
            output.extend_from_slice(&plaintext);

            offset += cipher_len;
            remaining -= plain_len;
            chunk_index += 1;
        }

        if offset != encrypted_content.len() {
            return Err(DecryptionError::DecryptionFailure(
                "Chunked ciphertext size mismatch".to_string(),
            ));
        }

        Ok(output)
    }

    /// Verify file integrity using hash embedded in the encryption metadata
    fn verify_file_integrity(
        &self,
        content: &[u8],
        metadata: &FileEncryptionMetadata,
    ) -> Result<bool, DecryptionError> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        // Compare with stored integrity hash
        Ok(computed_hash == metadata.integrity_hash)
    }

    /// Update access statistics and performance metrics
    async fn update_access_stats(&self, file_id: &str, epoch_id: u64, cache_hit: bool) {
        // Update cache statistics
        self.cache.update_access_stats(file_id, cache_hit);

        // Record the file-to-epoch mapping to keep the coverage log current.
        if let Err(err) = self
            .coverage_manager
            .log_file_epoch(file_id, epoch_id)
            .await
        {
            warn!(
                "Failed to refresh coverage entry for {}@{}: {}",
                file_id, epoch_id, err
            );
        } else {
            debug!("Coverage entry refreshed for {}@{}", file_id, epoch_id);
        }

        // Derive a device-scoped access tag so repeated reads can be correlated in telemetry.
        let access_tag = build_wrap_aad(file_id, file_id, None, epoch_id, 1);
        let preview_len = usize::min(8, access_tag.len());
        trace!(
            "Decryption access tag (first {} bytes) for {}: {:02x?}",
            preview_len,
            file_id,
            &access_tag[..preview_len]
        );
    }
}

/// Epoch strategy for decryption attempts
#[derive(Debug, Clone)]
struct EpochStrategy {
    /// Primary epoch to try first
    primary_epoch: u64,
    /// Fallback epoch to try if primary fails
    fallback_epoch: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        epoch::{EpochManager, EpochState},
        file::{cache::CacheManager, encrypt::FileEncryption},
        network::MockNetwork,
        storage::MockStorage,
    };
    use hybridcipher_coverage::CoverageManager;
    use hybridcipher_crypto::signatures::SigningKey;
    use serde_json;
    use std::sync::Arc;

    async fn setup() -> (
        FileEncryption<MockStorage, MockNetwork>,
        FileDecryption<MockStorage, MockNetwork>,
        Arc<MockStorage>,
        Arc<EpochManager<MockStorage, MockNetwork>>,
        Arc<CacheManager>,
    ) {
        let storage = Arc::new(MockStorage::new());
        let network = Arc::new(MockNetwork::new());
        let device_identity = Ed25519KeyPair::generate();
        let epoch_manager = Arc::new(
            EpochManager::new(
                storage.clone(),
                network.clone(),
                device_identity.clone(),
                "device1".into(),
            )
            .await
            .unwrap(),
        );
        let cache = Arc::new(CacheManager::new());
        let coverage_manager = Arc::new(CoverageManager::new_standalone(
            storage.clone(),
            hybridcipher_coverage::CoverageLog::new(),
            SigningKey::from_bytes(&device_identity.private_key_bytes()).unwrap(),
        ));

        let encryption = FileEncryption::new(
            storage.clone(),
            epoch_manager.clone(),
            coverage_manager.clone(),
            cache.clone(),
            device_identity.clone(),
        );
        let decryption = FileDecryption::new(
            storage.clone(),
            epoch_manager.clone(),
            coverage_manager,
            cache.clone(),
            device_identity,
        );

        (encryption, decryption, storage, epoch_manager, cache)
    }

    #[tokio::test]
    async fn test_file_decryption_basic() {
        let (encryption, decryption, storage, epoch_manager, cache) = setup().await;
        let epoch = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(epoch).await;

        let file_path = "/test/basic.txt";
        let content = b"Hello, secure world!";

        let enc_result = encryption.encrypt_file(file_path, content).await.unwrap();
        cache
            .store_file_metadata_bytes(file_path, serde_json::to_vec(&enc_result.metadata).unwrap())
            .unwrap();
        storage
            .store_file(file_path, &enc_result.encrypted_content)
            .await
            .unwrap();

        let dec_result = decryption.decrypt_file(file_path).await.unwrap();
        assert_eq!(dec_result.content, content);
        assert!(!dec_result.used_fallback);
        assert!(dec_result.metadata.integrity_verified);
    }

    #[tokio::test]
    async fn test_dual_epoch_fallback() {
        let (encryption, decryption, storage, epoch_manager, cache) = setup().await;
        let epoch1 = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(epoch1.clone()).await;

        let file_path = "/test/fallback.txt";
        let content = b"Fallback test";

        let enc_result = encryption.encrypt_file(file_path, content).await.unwrap();
        cache
            .store_file_metadata_bytes(file_path, serde_json::to_vec(&enc_result.metadata).unwrap())
            .unwrap();
        storage
            .store_file(file_path, &enc_result.encrypted_content)
            .await
            .unwrap();

        // Begin migration to a new epoch after the file was encrypted
        let epoch2 = EpochState::new(2, [2u8; 32]);
        epoch_manager.start_migration(epoch2).await.unwrap();

        // Modify stored metadata to indicate new epoch
        let mut stored = storage
            .load_file_metadata(file_path)
            .await
            .unwrap()
            .unwrap();
        stored.epoch_id = 2;
        storage
            .store_file_metadata(file_path, &stored)
            .await
            .unwrap();

        let dec_result = decryption.decrypt_file(file_path).await;
        assert!(dec_result.is_err());
    }

    #[tokio::test]
    async fn test_cache_optimization() {
        let (encryption, decryption, storage, epoch_manager, cache) = setup().await;
        let epoch = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(epoch.clone()).await;

        let file_path = "/test/cache.txt";
        let content = b"Cache test";

        let enc_result = encryption.encrypt_file(file_path, content).await.unwrap();
        cache
            .store_file_metadata_bytes(file_path, serde_json::to_vec(&enc_result.metadata).unwrap())
            .unwrap();
        storage
            .store_file(file_path, &enc_result.encrypted_content)
            .await
            .unwrap();

        // First decryption populates cache
        let _ = decryption.decrypt_file(file_path).await.unwrap();
        assert!(cache.get_epoch_key(1).is_some());

        // Remove epoch key from manager and ensure cache still allows decryption
        epoch_manager
            .set_current_epoch(EpochState::new(999, [9u8; 32]))
            .await;
        let dec_result = decryption.decrypt_file(file_path).await.unwrap();
        assert_eq!(dec_result.content, content);
    }

    #[tokio::test]
    async fn test_integrity_verification() {
        let (encryption, decryption, storage, epoch_manager, cache) = setup().await;
        let epoch = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(epoch).await;

        let file_path = "/test/integrity.txt";
        let content = b"Integrity check";

        let enc_result = encryption.encrypt_file(file_path, content).await.unwrap();
        cache
            .store_file_metadata_bytes(file_path, serde_json::to_vec(&enc_result.metadata).unwrap())
            .unwrap();

        // Tamper with the ciphertext
        let mut tampered = enc_result.encrypted_content.clone();
        tampered[0] ^= 0xFF;
        storage.store_file(file_path, &tampered).await.unwrap();

        // AEAD should prevent decryption of tampered data
        // This is correct behavior - tampering is detected during decryption
        let dec_result = decryption.decrypt_file(file_path).await;
        assert!(
            dec_result.is_err(),
            "Decryption should fail for tampered ciphertext"
        );

        // Now test with valid ciphertext but tampered metadata
        storage
            .store_file(file_path, &enc_result.encrypted_content)
            .await
            .unwrap();

        // Modify the persisted integrity hash in metadata to simulate metadata tampering
        let mut tampered_metadata = storage
            .load_file_metadata(file_path)
            .await
            .unwrap()
            .unwrap();
        tampered_metadata.integrity_hash[0] ^= 0xFF;
        storage
            .store_file_metadata(file_path, &tampered_metadata)
            .await
            .unwrap();

        let dec_result = decryption.decrypt_file(file_path).await.unwrap();
        // Decryption succeeds but integrity check fails
        assert!(
            !dec_result.metadata.integrity_verified,
            "Integrity verification should fail for tampered metadata"
        );
    }
}
