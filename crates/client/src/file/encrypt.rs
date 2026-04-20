/// Migration-aware file encryption with intelligent epoch selection
///
/// This module implements secure file encryption that automatically selects
/// the most appropriate epoch for encryption while maintaining consistency
/// and enabling seamless access during epoch transitions.
const ENCRYPTED_FILE_SEPARATOR: &[u8] = b"\n---ENCRYPTED_DATA---\n";
const COVERAGE_TMP_DIR_NAME: &str = ".hybridcipher-tmp";
use crate::{
    epoch::EpochManager,
    file::cache::CacheManager,
    network::Network,
    storage::{AccessControlData, FileMetadataData, Storage, StorageError},
};
use base64::Engine as _;
use chrono::{DateTime, Utc};
use hybridcipher_coverage::CoverageManager;
use hybridcipher_coverage::FileEpochEntry;
use hybridcipher_crypto::{
    aead::{seal, AeadContext},
    kdf::{hkdf_expand, HkdfContext},
    signatures::Ed25519KeyPair,
    AeadKey, AeadNonce,
};
use log::{debug, warn};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

/// File encryption errors
#[derive(Debug, Error)]
pub enum EncryptionError {
    #[error("No suitable epoch available for encryption")]
    NoEpochAvailable,

    #[error("Epoch key unavailable: {0}")]
    EpochKeyUnavailable(String),

    #[error("File key generation failed: {0}")]
    KeyGenerationFailure(String),

    #[error("Encryption operation failed: {0}")]
    EncryptionFailure(String),

    #[error("Coverage update failed: {0}")]
    CoverageUpdateFailure(String),

    #[error("Storage operation failed: {0}")]
    Storage(#[from] StorageError),

    #[error("Crypto operation failed: {0}")]
    Crypto(String),
}

/// File encryption result
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    /// Encrypted file content
    pub encrypted_content: Vec<u8>,
    /// File encryption metadata
    pub metadata: FileEncryptionMetadata,
    /// Coverage log entry for this encryption
    pub coverage_entry: FileEpochEntry,
    /// Epoch used for encryption
    pub target_epoch: u64,
    /// Whether file was encrypted during migration
    pub during_migration: bool,
}

/// File encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEncryptionMetadata {
    /// File identifier
    pub file_id: String,
    /// Canonical, normalized file path
    pub file_path: String,
    /// Group identifier (if available)
    pub group_id: Option<Uuid>,
    /// Epoch used for encryption
    pub epoch_id: u64,
    /// Header format version
    pub header_version: u32,
    /// Encrypted file key (wrapped with epoch key)
    pub wrapped_file_key: Vec<u8>,
    /// Nonce used for key wrapping
    pub key_wrap_nonce: Vec<u8>,
    /// Hash of wrap AAD for integrity checking
    pub key_wrap_aad_hash: Vec<u8>,
    /// Nonce used for file content encryption
    pub content_nonce: Vec<u8>,
    /// Chunk size for chunked content encryption (header_version >= 2)
    #[serde(default)]
    pub content_chunk_size: Option<u64>,
    /// Additional authenticated data
    pub aad: Vec<u8>,
    /// Timestamp of encryption
    pub encrypted_at: DateTime<Utc>,
    /// File size (unencrypted)
    pub original_size: u64,
    /// File hash (for integrity verification)
    pub content_hash: Vec<u8>,
    /// Algorithm used for encryption
    pub algorithm: String,
    /// File size in bytes
    pub file_size: u64,
    /// File integrity hash (SHA-256)
    pub integrity_hash: [u8; 32],
}

/// File encryption manager
#[derive(Debug)]
pub struct FileEncryption<S: Storage, N: Network> {
    /// Storage backend
    storage: Arc<S>,
    /// Epoch manager for key resolution
    epoch_manager: Arc<EpochManager<S, N>>,
    /// Coverage manager for tracking
    coverage_manager: Arc<CoverageManager<S>>,
    /// Cache manager for performance
    cache: Arc<CacheManager>,
    /// Device identity for signing
    device_identity: Ed25519KeyPair,
}

impl<S: Storage, N: Network> FileEncryption<S, N> {
    /// Create a new file encryption manager
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
            device_identity,
        }
    }

    /// Encrypt a file with migration-aware epoch selection
    pub async fn encrypt_file(
        &self,
        file_path: &str,
        content: &[u8],
    ) -> Result<EncryptionResult, EncryptionError> {
        // Step 1: Intelligent epoch selection
        let target_epoch = self.select_target_epoch().await?;
        let during_migration = self.is_migration_active().await;

        if during_migration && !self.epoch_manager.is_epoch_key_verified(target_epoch).await {
            return Err(EncryptionError::EpochKeyUnavailable(format!(
                "Epoch {} key is not verified yet (rekey in progress)",
                target_epoch
            )));
        }

        debug!(
            "Encrypting {} ({} bytes) for epoch {} using device {:02x?}",
            file_path,
            content.len(),
            target_epoch,
            &self.device_identity.public_key_bytes()[..8]
        );

        // Step 2: Generate file key with cryptographically strong randomness
        let file_key = self.generate_file_key()?;

        if let Err(err) = self.cache.cache_file_key(file_path, &file_key) {
            warn!("Failed to cache file key for {}: {}", file_path, err);
        }

        // Step 3: Get epoch key for wrapping
        let epoch_key = self.get_epoch_key(target_epoch).await?;

        if let Err(err) = self.cache.store_epoch_key(target_epoch, &epoch_key) {
            warn!(
                "Failed to cache epoch key {} while encrypting {}: {}",
                target_epoch, file_path, err
            );
        }

        // Normalize path and derive identifiers
        let normalized_path = normalize_file_identifier(file_path);
        let file_id = generate_file_id();
        let header_version = 1u32;
        let wrap_aad = build_wrap_aad(
            &file_id,
            &normalized_path,
            None,
            target_epoch,
            header_version,
        );

        // Step 4: Derive KEK and wrap file key with epoch key
        let kek_bytes =
            hkdf_expand(epoch_key.as_bytes(), HkdfContext::KeyWrapping, 32).map_err(|e| {
                EncryptionError::KeyGenerationFailure(format!("HKDF(KeyWrapping) failed: {e}"))
            })?;
        let kek = AeadKey::from_bytes(&kek_bytes).map_err(|e| {
            EncryptionError::KeyGenerationFailure(format!("Failed to create KEK: {}", e))
        })?;

        let (wrapped_file_key, key_wrap_nonce) = wrap_file_key(&file_key, &kek, &wrap_aad)?;
        let key_wrap_aad_hash = hash_wrap_aad(&wrap_aad);

        // Step 5: Encrypt file content
        let (encrypted_content, content_nonce) = encrypt_content(content, &file_key, &file_id)?;

        // Step 6: Create file metadata
        let metadata = self
            .create_metadata(
                &file_id,
                &normalized_path,
                target_epoch,
                header_version,
                wrapped_file_key,
                key_wrap_nonce,
                key_wrap_aad_hash,
                content_nonce,
                content.len() as u64,
                content,
            )
            .await?;

        if let Ok(serialized_metadata) = serde_json::to_vec(&metadata) {
            if let Err(err) = self
                .cache
                .store_file_metadata_bytes(&normalized_path, serialized_metadata)
            {
                warn!("Failed to cache metadata for {}: {}", file_path, err);
            }
        } else {
            warn!("Failed to serialise metadata for {} for caching", file_path);
        }

        // Step 7: Update coverage log atomically
        let coverage_entry = self.update_coverage_log(&file_id, target_epoch).await?;

        // Step 8: Store metadata
        self.store_metadata(&metadata).await?;

        Ok(EncryptionResult {
            encrypted_content,
            metadata,
            coverage_entry,
            target_epoch,
            during_migration,
        })
    }

    /// Select the most appropriate epoch for encryption
    async fn select_target_epoch(&self) -> Result<u64, EncryptionError> {
        // Try to get the newest available epoch
        if let Some(current_epoch) = self.epoch_manager.current_epoch().await {
            // Check if migration is active
            if let Some(target_epoch_id) = self.epoch_manager.get_migration_target_epoch().await {
                // During migration, prefer target epoch for forward compatibility
                return Ok(target_epoch_id);
            }
            return Ok(current_epoch.epoch_id);
        }

        Err(EncryptionError::NoEpochAvailable)
    }

    /// Check if migration is currently active
    async fn is_migration_active(&self) -> bool {
        self.epoch_manager.is_migration_active().await
    }

    /// Create authenticated data binding for key wrapping.
    pub fn create_aad(&self, file_path: &str, epoch_id: u64) -> Vec<u8> {
        let normalized_path = normalize_file_identifier(file_path);
        let mut hasher = Sha256::new();
        hasher.update(normalized_path.as_bytes());
        hasher.update(b"|");
        hasher.update(epoch_id.to_be_bytes());
        hasher.finalize().to_vec()
    }

    /// Generate a cryptographically strong file key
    fn generate_file_key(&self) -> Result<AeadKey, EncryptionError> {
        let mut key_bytes = [0u8; 32]; // 256-bit key for ChaCha20-Poly1305
        OsRng.fill_bytes(&mut key_bytes);

        AeadKey::from_bytes(&key_bytes).map_err(|e| {
            EncryptionError::KeyGenerationFailure(format!("Failed to create AEAD key: {}", e))
        })
    }

    /// Get epoch key for the specified epoch
    async fn get_epoch_key(&self, epoch_id: u64) -> Result<AeadKey, EncryptionError> {
        self.epoch_manager
            .get_epoch_key(epoch_id)
            .await
            .ok_or_else(|| {
                EncryptionError::EpochKeyUnavailable(format!(
                    "Epoch {} key not available",
                    epoch_id
                ))
            })
    }

    /// Create file encryption metadata
    async fn create_metadata(
        &self,
        file_id: &str,
        file_path: &str,
        epoch_id: u64,
        header_version: u32,
        wrapped_file_key: Vec<u8>,
        key_wrap_nonce: Vec<u8>,
        key_wrap_aad_hash: Vec<u8>,
        content_nonce: Vec<u8>,
        original_size: u64,
        content: &[u8],
    ) -> Result<FileEncryptionMetadata, EncryptionError> {
        // Calculate content hash for integrity verification
        let mut hasher = Sha256::new();
        hasher.update(content);
        let content_hash = hasher.finalize().to_vec();

        let mut hasher2 = Sha256::new();
        hasher2.update(content);
        let integrity_hash: [u8; 32] = hasher2.finalize().into();

        Ok(FileEncryptionMetadata {
            file_id: file_id.to_string(),
            file_path: file_path.to_string(),
            group_id: None,
            epoch_id,
            header_version,
            wrapped_file_key,
            key_wrap_nonce,
            key_wrap_aad_hash,
            content_nonce,
            content_chunk_size: None,
            aad: create_header_aad(file_id, epoch_id, header_version),
            encrypted_at: Utc::now(),
            original_size,
            content_hash,
            algorithm: "ChaCha20-Poly1305".to_string(),
            file_size: content.len() as u64,
            integrity_hash,
        })
    }

    /// Update coverage log with file-to-epoch assignment
    async fn update_coverage_log(
        &self,
        file_id: &str,
        epoch_id: u64,
    ) -> Result<FileEpochEntry, EncryptionError> {
        self.coverage_manager
            .log_file_epoch(file_id, epoch_id)
            .await
            .map_err(|e| EncryptionError::CoverageUpdateFailure(format!("{e}")))
    }

    /// Store file metadata atomically
    async fn store_metadata(
        &self,
        metadata: &FileEncryptionMetadata,
    ) -> Result<(), EncryptionError> {
        // Convert our internal metadata to the storage format
        let storage_metadata = FileMetadataData {
            file_path: metadata.file_path.clone(),
            file_id: Some(metadata.file_id.clone()),
            group_id: metadata.group_id,
            epoch_id: metadata.epoch_id,
            header_version: Some(metadata.header_version),
            wrapped_file_key: Some(metadata.wrapped_file_key.clone()),
            key_wrap_nonce: Some(metadata.key_wrap_nonce.clone()),
            key_wrap_aad_hash: Some(metadata.key_wrap_aad_hash.clone()),
            content_nonce: Some(metadata.content_nonce.clone()),
            content_chunk_size: metadata.content_chunk_size,
            algorithm: metadata.algorithm.clone(),
            file_size: metadata.file_size,
            modified_at: metadata.encrypted_at,
            integrity_hash: metadata.integrity_hash,
            permissions: AccessControlData {
                readers: vec![],  // Initialize with empty readers list
                writers: vec![],  // Initialize with empty writers list
                is_public: false, // Default to private
            },
            version: 1,
            chunks: Vec::new(), // No chunk data for now
            encrypted_size: metadata.file_size,
            encrypted_at: metadata.encrypted_at,
        };

        self.storage
            .store_file_metadata(&storage_metadata.file_path, &storage_metadata)
            .await
            .map_err(|e| EncryptionError::Storage(e))?;

        Ok(())
    }
}

/// Normalize a file identifier (portable path semantics).
pub fn normalize_file_identifier(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }

    let replaced = trimmed.replace('\\', "/");
    let mut segments: Vec<&str> = Vec::new();
    for part in replaced.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        segments.push(part);
    }

    let normalized = segments.join("/");
    if replaced.starts_with('/') {
        if normalized.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", normalized)
        }
    } else if normalized.is_empty() {
        "/".to_string()
    } else {
        normalized
    }
}

/// Generate a random 256-bit file identifier for new encryptions.
pub fn generate_file_id() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// No legacy path-based derivation: file IDs are purely random.

/// Build deterministic AAD for wrapping the per-file DEK.
pub fn build_wrap_aad(
    file_id: &str,
    normalized_file_path: &str,
    group_id: Option<Uuid>,
    epoch_id: u64,
    header_version: u32,
) -> Vec<u8> {
    // AAD is bound to the filename only (not full path) by design.
    let aad_label = aad_label_from_path(normalized_file_path);
    let mut hasher = Sha256::new();
    hasher.update(b"dek-wrap:v1:");
    hasher.update(file_id.as_bytes());
    hasher.update(aad_label.as_bytes());
    if let Some(g) = group_id {
        hasher.update(g.as_bytes());
    }
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&header_version.to_le_bytes());
    hasher.finalize().to_vec()
}

fn aad_label_from_path(path: &str) -> String {
    let normalized = normalize_file_identifier(path);
    normalized
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or("/")
        .to_string()
}

/// Hash the wrap AAD for integrity storage.
pub fn hash_wrap_aad(wrap_aad: &[u8]) -> Vec<u8> {
    Sha256::digest(wrap_aad).to_vec()
}

fn create_header_aad(file_id: &str, epoch_id: u64, header_version: u32) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(b"dek-wrap:v1:");
    hasher.update(file_id.as_bytes());
    hasher.update(&epoch_id.to_le_bytes());
    hasher.update(&header_version.to_le_bytes());
    hasher.finalize().to_vec()
}

/// Wrap a file key with the provided KEK and AAD.
pub fn wrap_file_key(
    file_key: &AeadKey,
    kek: &AeadKey,
    wrap_aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    // Generate nonce for key wrapping
    let mut nonce_bytes = [0u8; 12]; // 96-bit nonce for ChaCha20-Poly1305
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
        EncryptionError::EncryptionFailure(format!("Failed to create nonce: {}", e))
    })?;

    // Encrypt file key with KEK
    let wrapped = seal(
        kek,
        &nonce,
        AeadContext::FileData,
        wrap_aad,
        file_key.as_bytes(),
    )
    .map_err(|e| EncryptionError::EncryptionFailure(format!("Key wrapping failed: {}", e)))?;

    Ok((wrapped, nonce_bytes.to_vec()))
}

/// Encrypt file content with ChaCha20-Poly1305 using file_id as AAD.
pub fn encrypt_content(
    content: &[u8],
    file_key: &AeadKey,
    file_id: &str,
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    // Generate nonce for content encryption
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
        EncryptionError::EncryptionFailure(format!("Failed to create content nonce: {}", e))
    })?;

    // Create AAD for content encryption (file_id)
    let aad = file_id.as_bytes().to_vec();

    // Encrypt content
    let context = AeadContext::FileData;
    let encrypted_content = seal(file_key, &nonce, context, &aad, content).map_err(|e| {
        EncryptionError::EncryptionFailure(format!("Content encryption failed: {}", e))
    })?;

    Ok((encrypted_content, nonce_bytes.to_vec()))
}

/// Header version for chunked (streaming) ciphertexts.
pub const CHUNKED_HEADER_VERSION: u32 = 2;

/// ChaCha20-Poly1305 authentication tag size in bytes.
pub const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformXattr {
    pub name: String,
    pub value_base64: String,
}

impl PlatformXattr {
    pub fn from_bytes(name: impl Into<String>, value: &[u8]) -> Self {
        Self {
            name: name.into(),
            value_base64: base64::engine::general_purpose::STANDARD.encode(value),
        }
    }

    pub fn decode_value(&self) -> Option<Vec<u8>> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.value_base64)
            .ok()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsFileMetadata {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xattrs: Vec<PlatformXattr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acl_text: Option<String>,
}

impl MacOsFileMetadata {
    pub fn is_empty(&self) -> bool {
        self.xattrs.is_empty()
            && self
                .acl_text
                .as_ref()
                .map(|value| value.trim().is_empty())
                .unwrap_or(true)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformFileMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unix_mode: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub macos: Option<MacOsFileMetadata>,
}

impl PlatformFileMetadata {
    pub fn is_empty(&self) -> bool {
        self.unix_mode.is_none()
            && self
                .macos
                .as_ref()
                .map(MacOsFileMetadata::is_empty)
                .unwrap_or(true)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseExtent {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseFileMetadata {
    pub logical_size: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extents: Vec<SparseExtent>,
}

impl SparseFileMetadata {
    pub fn packed_size(&self) -> u64 {
        self.extents
            .iter()
            .fold(0u64, |total, extent| total.saturating_add(extent.length))
    }

    pub fn is_effectively_sparse(&self) -> bool {
        self.extents.is_empty()
            || self.extents.len() > 1
            || self
                .extents
                .first()
                .map(|extent| extent.offset != 0 || extent.length != self.logical_size)
                .unwrap_or(false)
    }
}

/// Derive a per-chunk nonce by XORing the base nonce with the chunk index.
pub fn derive_chunk_nonce(base_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce = *base_nonce;
    let index_bytes = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= index_bytes[i];
    }
    nonce
}

fn build_chunk_aad(file_id: &str, chunk_index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(file_id.len() + 8);
    aad.extend_from_slice(file_id.as_bytes());
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad
}

/// Compute expected encrypted size for chunked ciphertexts.
pub fn chunked_encrypted_size(
    content_size: u64,
    chunk_size: usize,
) -> Result<u64, EncryptionError> {
    if chunk_size == 0 {
        return Err(EncryptionError::EncryptionFailure(
            "chunk_size must be greater than 0".to_string(),
        ));
    }
    let chunk_size = chunk_size as u64;
    let chunks = content_size
        .checked_add(chunk_size.saturating_sub(1))
        .ok_or_else(|| EncryptionError::EncryptionFailure("chunked size overflow".to_string()))?
        / chunk_size;
    let overhead = chunks
        .checked_mul(AEAD_TAG_SIZE as u64)
        .ok_or_else(|| EncryptionError::EncryptionFailure("chunked size overflow".to_string()))?;
    content_size
        .checked_add(overhead)
        .ok_or_else(|| EncryptionError::EncryptionFailure("chunked size overflow".to_string()))
}

/// Encrypt content in fixed-size chunks and stream ciphertext to output.
pub fn encrypt_content_chunked<R: Read, W: Write>(
    mut input: R,
    mut output: W,
    file_key: &AeadKey,
    file_id: &str,
    base_nonce: &[u8; 12],
    chunk_size: usize,
) -> Result<(u64, [u8; 32]), EncryptionError> {
    if chunk_size == 0 {
        return Err(EncryptionError::EncryptionFailure(
            "chunk_size must be greater than 0".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    let mut total_read = 0u64;
    let mut chunk_index = 0u64;
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let bytes_read = input.read(&mut buffer).map_err(|e| {
            EncryptionError::EncryptionFailure(format!("Failed to read plaintext: {}", e))
        })?;
        if bytes_read == 0 {
            break;
        }

        let chunk = &buffer[..bytes_read];
        hasher.update(chunk);

        let nonce_bytes = derive_chunk_nonce(base_nonce, chunk_index);
        let nonce = AeadNonce::from_bytes(&nonce_bytes).map_err(|e| {
            EncryptionError::EncryptionFailure(format!("Invalid chunk nonce: {}", e))
        })?;
        let aad = build_chunk_aad(file_id, chunk_index);
        let encrypted =
            seal(file_key, &nonce, AeadContext::FileData, &aad, chunk).map_err(|e| {
                EncryptionError::EncryptionFailure(format!("Chunk encryption failed: {}", e))
            })?;

        output.write_all(&encrypted).map_err(|e| {
            EncryptionError::EncryptionFailure(format!("Failed to write ciphertext: {}", e))
        })?;

        total_read += bytes_read as u64;
        chunk_index += 1;
    }

    let hash: [u8; 32] = hasher.finalize().into();
    Ok((total_read, hash))
}

/// Serializable header fields for persisted ciphertexts.
pub struct SerializedEncryptedHeader<'a> {
    pub file_id: &'a str,
    pub file_path: &'a str,
    pub group_id: Option<Uuid>,
    pub epoch_id: u64,
    pub header_version: u32,
    pub wrapped_file_key: &'a [u8],
    pub key_wrap_nonce: &'a [u8],
    pub key_wrap_aad_hash: &'a [u8],
    pub content_nonce: &'a [u8],
    pub content_chunk_size: Option<u64>,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub encrypted_at: chrono::DateTime<chrono::Utc>,
    pub original_name: Option<&'a str>,
    pub platform_metadata: Option<&'a PlatformFileMetadata>,
    pub sparse_metadata: Option<&'a SparseFileMetadata>,
}

/// Write header + ciphertext to disk in the standard JSON+separator format used across clients.
pub fn write_encrypted_file(
    path: &std::path::Path,
    header: &SerializedEncryptedHeader<'_>,
    encrypted_content: &[u8],
) -> Result<(), EncryptionError> {
    let mut serialized = serialize_encrypted_header(header)?;
    serialized.extend_from_slice(encrypted_content);

    std::fs::write(path, serialized).map_err(|e| {
        EncryptionError::Storage(StorageError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to write encrypted file {}: {}", path.display(), e),
        )))
    })
}

/// Atomically write header + ciphertext via `.hybridcipher-tmp/temp_coverage_<filename>`.
pub fn write_encrypted_file_atomic_for_coverage(
    path: &Path,
    header: &SerializedEncryptedHeader<'_>,
    encrypted_content: &[u8],
) -> Result<(), EncryptionError> {
    write_encrypted_file_atomic_for_coverage_with_sync(path, header, encrypted_content, true)
}

/// Atomically write header + ciphertext via `.hybridcipher-tmp/temp_coverage_<filename>`.
/// When `sync_to_disk` is false, fsync calls are skipped for higher throughput.
pub fn write_encrypted_file_atomic_for_coverage_with_sync(
    path: &Path,
    header: &SerializedEncryptedHeader<'_>,
    encrypted_content: &[u8],
    sync_to_disk: bool,
) -> Result<(), EncryptionError> {
    let parent = path.parent().ok_or_else(|| {
        EncryptionError::Storage(StorageError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "Encrypted file path {} has no parent directory",
                path.display()
            ),
        )))
    })?;

    std::fs::create_dir_all(parent).map_err(|e| {
        EncryptionError::Storage(StorageError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to create parent directory {}: {}",
                parent.display(),
                e
            ),
        )))
    })?;

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "encrypted".to_string());
    let tmp_dir = parent.join(COVERAGE_TMP_DIR_NAME);
    std::fs::create_dir_all(&tmp_dir).map_err(|e| {
        EncryptionError::Storage(StorageError::Io(std::io::Error::new(
            e.kind(),
            format!(
                "Failed to create coverage temp directory {}: {}",
                tmp_dir.display(),
                e
            ),
        )))
    })?;

    let tmp_name = format!("temp_coverage_{}", file_name);
    let tmp_path = tmp_dir.join(tmp_name);

    let mut serialized = serialize_encrypted_header(header)?;
    serialized.extend_from_slice(encrypted_content);

    {
        let mut tmp_file = std::fs::File::create(&tmp_path).map_err(|e| {
            EncryptionError::Storage(StorageError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to create coverage temp file {}: {}",
                    tmp_path.display(),
                    e
                ),
            )))
        })?;
        tmp_file.write_all(&serialized).map_err(|e| {
            EncryptionError::Storage(StorageError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "Failed to write coverage temp file {}: {}",
                    tmp_path.display(),
                    e
                ),
            )))
        })?;
        if sync_to_disk {
            tmp_file.sync_all().map_err(|e| {
                EncryptionError::Storage(StorageError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to fsync coverage temp file {}: {}",
                        tmp_path.display(),
                        e
                    ),
                )))
            })?;
        }
    }

    #[cfg(target_os = "windows")]
    {
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                EncryptionError::Storage(StorageError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to remove existing encrypted file {}: {}",
                        path.display(),
                        e
                    ),
                )))
            })?;
        }
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(EncryptionError::Storage(StorageError::Io(
            std::io::Error::new(
                err.kind(),
                format!(
                    "Failed to move coverage temp file {} into {}: {}",
                    tmp_path.display(),
                    path.display(),
                    err
                ),
            ),
        )));
    }

    if sync_to_disk {
        if let Ok(dir) = std::fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Serialize the encrypted header (JSON + separator) without ciphertext.
pub fn serialize_encrypted_header(
    header: &SerializedEncryptedHeader<'_>,
) -> Result<Vec<u8>, EncryptionError> {
    let metadata_json = serde_json::json!({
        "file_id": header.file_id,
        "original_name": header.original_name,
        "original_size": header.original_size,
        "file_size": header.original_size,
        "encrypted_size": header.encrypted_size,
        "epoch_id": header.epoch_id,
        "group_id": header.group_id.map(|id| id.to_string()),
        "encrypted_at": header.encrypted_at.to_rfc3339(),
        "file_path": header.file_path,
        "header_version": header.header_version,
        "wrapped_file_key": base64::engine::general_purpose::STANDARD.encode(header.wrapped_file_key),
        "key_wrap_nonce": base64::engine::general_purpose::STANDARD.encode(header.key_wrap_nonce),
        "key_wrap_aad_hash": base64::engine::general_purpose::STANDARD.encode(header.key_wrap_aad_hash),
        "content_nonce": base64::engine::general_purpose::STANDARD.encode(header.content_nonce),
        "chunk_size": header.content_chunk_size,
        "platform_metadata": header.platform_metadata,
        "sparse_metadata": header.sparse_metadata,
    });

    let mut serialized = serde_json::to_vec(&metadata_json).map_err(|e| {
        EncryptionError::Storage(StorageError::Serialization(format!(
            "Failed to serialize encrypted metadata: {e}"
        )))
    })?;
    serialized.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);
    Ok(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        epoch::{EpochManager, EpochState},
        file::cache::CacheManager,
        network::MockNetwork,
        storage::MockStorage,
    };
    use hybridcipher_coverage::CoverageManager;
    use hybridcipher_crypto::signatures::SigningKey;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_file_encryption_with_epoch_selection() {
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

        // Initialize epoch
        let epoch = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(epoch.clone()).await;

        let encryption = FileEncryption::new(
            storage,
            epoch_manager.clone(),
            coverage_manager,
            cache,
            device_identity,
        );

        let test_content = b"Hello, secure world!";
        let file_path = "/test/file.txt";

        let result = encryption
            .encrypt_file(file_path, test_content)
            .await
            .unwrap();

        assert_eq!(result.target_epoch, epoch.epoch_id);
        assert_eq!(result.metadata.epoch_id, epoch.epoch_id);
        assert!(!result.encrypted_content.is_empty());
    }

    #[tokio::test]
    async fn test_encryption_fails_without_epoch() {
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
            storage,
            epoch_manager,
            coverage_manager,
            cache,
            device_identity,
        );

        let result = encryption.encrypt_file("/test/file.txt", b"content").await;

        assert!(matches!(result, Err(EncryptionError::NoEpochAvailable)));
    }

    #[tokio::test]
    async fn test_encryption_fails_with_corrupted_epoch() {
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

        // Set current epoch and start migration to a target epoch without storing its key
        let current_epoch = EpochState::new(1, [1u8; 32]);
        epoch_manager.set_current_epoch(current_epoch).await;
        let missing_epoch = EpochState::new(2, [2u8; 32]);
        epoch_manager.start_migration(missing_epoch).await.unwrap();

        let encryption = FileEncryption::new(
            storage,
            epoch_manager,
            coverage_manager,
            cache,
            device_identity,
        );

        let result = encryption.encrypt_file("/test/file.txt", b"content").await;

        assert!(matches!(
            result,
            Err(EncryptionError::EpochKeyUnavailable(_))
        ));
    }

    #[tokio::test]
    async fn test_file_key_generation() {
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
            storage,
            epoch_manager,
            coverage_manager,
            cache,
            device_identity,
        );

        // Test file key generation
        let file_key = encryption.generate_file_key();
        assert!(file_key.is_ok());

        // Generate multiple keys and ensure they're different
        let key1 = encryption.generate_file_key().unwrap();
        let key2 = encryption.generate_file_key().unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[tokio::test]
    async fn test_aad_creation() {
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
            storage,
            epoch_manager,
            coverage_manager,
            cache,
            device_identity,
        );

        let aad1 = encryption.create_aad("/test/file1.txt", 1);
        let aad2 = encryption.create_aad("/test/file2.txt", 1);
        let aad3 = encryption.create_aad("/test/file1.txt", 2);

        // AAD should be different for different files or epochs
        assert_ne!(aad1, aad2);
        assert_ne!(aad1, aad3);
        assert_eq!(aad1.len(), 32); // SHA256 hash length
    }
}
