use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hybridcipher_client::{
    network::MockNetwork,
    storage::LocalFsStorage,
    storage::{AccessControlData, FileMetadataData},
    Client, EncryptedFileMetadata, PlatformFileMetadata,
};
use hybridcipher_mount_sync::{
    encrypted_path_for, parse_encrypted_file_with_root, MountCrypto, MountSyncError,
    StreamingEncryptedFile,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use uuid::Uuid;

pub use hybridcipher_mount_sync::{
    LowSpaceMode, MountConflictRecord, MountRecoveryCopyRecord, MountSafetyReason,
    MountSyncRuntimeStatus,
};

const IDENTITY_VERSION: u16 = 1;
const DIRECTORY_METADATA_FILE_NAME: &str = ".hybridcipher_dir.encrypted";
const PROVIDER_STREAM_CHUNK_SIZE_BYTES: usize = 4 * 1024 * 1024;
const ENCRYPTED_TMP_DIR_NAME: &str = ".hybridcipher-tmp";

pub type LocalProviderClient = Client<LocalFsStorage, MockNetwork>;

#[derive(Debug, Error)]
pub enum ProviderCoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("provider identity serialization failed: {0}")]
    IdentitySerialization(#[from] serde_json::Error),
    #[error("invalid provider identity: {0}")]
    InvalidIdentity(String),
    #[error("encrypted metadata parse failed for {path}: {source}")]
    MetadataParse {
        path: PathBuf,
        source: MountSyncError,
    },
    #[error("path {path} is outside root {root}")]
    PathOutsideRoot { path: PathBuf, root: PathBuf },
    #[error("crypto operation failed: {0}")]
    Crypto(#[from] MountSyncError),
    #[error("provider mutation is not supported: {0}")]
    MutationUnsupported(String),
}

pub type Result<T> = std::result::Result<T, ProviderCoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEntryKind {
    Directory,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileIdentityV1 {
    pub version: u16,
    pub root_id: Uuid,
    pub kind: ProviderEntryKind,
    pub relative_path: String,
    pub path_hash_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_id: Option<u64>,
}

impl FileIdentityV1 {
    pub fn new(
        root_id: Uuid,
        kind: ProviderEntryKind,
        relative_path: impl Into<String>,
        file_id: Option<String>,
        epoch_id: Option<u64>,
    ) -> Self {
        let relative_path = normalize_relative_path(relative_path.into());
        let path_hash_hex = hash_relative_path(&relative_path);
        Self {
            version: IDENTITY_VERSION,
            root_id,
            kind,
            relative_path,
            path_hash_hex,
            file_id,
            epoch_id,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let identity: Self = serde_json::from_slice(bytes)?;
        if identity.version != IDENTITY_VERSION {
            return Err(ProviderCoreError::InvalidIdentity(format!(
                "unsupported identity version {}",
                identity.version
            )));
        }
        let expected_hash = hash_relative_path(&identity.relative_path);
        if identity.path_hash_hex != expected_hash {
            return Err(ProviderCoreError::InvalidIdentity(
                "relative path hash mismatch".to_string(),
            ));
        }
        Ok(identity)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEntry {
    pub root_id: Uuid,
    pub kind: ProviderEntryKind,
    pub relative_path: String,
    pub encrypted_path: PathBuf,
    pub identity: FileIdentityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<EncryptedFileMetadata>,
    pub logical_size: u64,
    pub encrypted_size: u64,
    pub modified_at: DateTime<Utc>,
}

impl ProviderEntry {
    fn directory(root_id: Uuid, relative_path: String, encrypted_path: PathBuf) -> Self {
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::Directory,
            relative_path.clone(),
            None,
            None,
        );
        Self {
            root_id,
            kind: ProviderEntryKind::Directory,
            relative_path,
            encrypted_path,
            identity,
            metadata: None,
            logical_size: 0,
            encrypted_size: 0,
            modified_at: Utc::now(),
        }
    }

    fn file(
        root_id: Uuid,
        relative_path: String,
        encrypted_path: PathBuf,
        metadata: EncryptedFileMetadata,
    ) -> Self {
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            relative_path.clone(),
            Some(metadata.file_id.clone()),
            Some(metadata.epoch_id),
        );
        Self {
            root_id,
            kind: ProviderEntryKind::File,
            relative_path,
            encrypted_path,
            identity,
            logical_size: metadata.content_size,
            encrypted_size: metadata.encrypted_size,
            modified_at: metadata.created_at,
            metadata: Some(metadata),
        }
    }

    pub fn cache_directory(
        root_id: Uuid,
        relative_path: impl Into<String>,
        encrypted_path: impl Into<PathBuf>,
        modified_at: DateTime<Utc>,
    ) -> Self {
        let relative_path = normalize_relative_path(relative_path.into());
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::Directory,
            relative_path.clone(),
            None,
            None,
        );
        Self {
            root_id,
            kind: ProviderEntryKind::Directory,
            relative_path,
            encrypted_path: encrypted_path.into(),
            identity,
            metadata: None,
            logical_size: 0,
            encrypted_size: 0,
            modified_at,
        }
    }

    pub fn cache_file(
        root_id: Uuid,
        relative_path: impl Into<String>,
        encrypted_path: impl Into<PathBuf>,
        logical_size: u64,
        encrypted_size: u64,
        modified_at: DateTime<Utc>,
        metadata: Option<EncryptedFileMetadata>,
    ) -> Self {
        let relative_path = normalize_relative_path(relative_path.into());
        let file_id = metadata.as_ref().map(|metadata| metadata.file_id.clone());
        let epoch_id = metadata.as_ref().map(|metadata| metadata.epoch_id);
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            relative_path.clone(),
            file_id,
            epoch_id,
        );
        Self {
            root_id,
            kind: ProviderEntryKind::File,
            relative_path,
            encrypted_path: encrypted_path.into(),
            identity,
            metadata,
            logical_size,
            encrypted_size,
            modified_at,
        }
    }

    pub fn cache_file_with_identity(
        root_id: Uuid,
        relative_path: impl Into<String>,
        encrypted_path: impl Into<PathBuf>,
        logical_size: u64,
        encrypted_size: u64,
        modified_at: DateTime<Utc>,
        metadata: Option<EncryptedFileMetadata>,
        file_id: Option<String>,
        epoch_id: Option<u64>,
    ) -> Self {
        let relative_path = normalize_relative_path(relative_path.into());
        let file_id =
            file_id.or_else(|| metadata.as_ref().map(|metadata| metadata.file_id.clone()));
        let epoch_id = epoch_id.or_else(|| metadata.as_ref().map(|metadata| metadata.epoch_id));
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            relative_path.clone(),
            file_id,
            epoch_id,
        );
        Self {
            root_id,
            kind: ProviderEntryKind::File,
            relative_path,
            encrypted_path: encrypted_path.into(),
            identity,
            metadata,
            logical_size,
            encrypted_size,
            modified_at,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptedInventory {
    root_id: Uuid,
    encrypted_root: PathBuf,
}

impl EncryptedInventory {
    pub fn new(root_id: Uuid, encrypted_root: impl Into<PathBuf>) -> Self {
        Self {
            root_id,
            encrypted_root: encrypted_root.into(),
        }
    }

    pub fn scan(&self) -> Result<Vec<ProviderEntry>> {
        let mut entries = Vec::new();
        if !self.encrypted_root.exists() {
            return Ok(entries);
        }
        self.scan_dir(&self.encrypted_root, &mut entries)?;
        entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(entries)
    }

    fn scan_dir(&self, dir: &Path, entries: &mut Vec<ProviderEntry>) -> Result<()> {
        for child in fs::read_dir(dir)? {
            let child = child?;
            let path = child.path();
            let file_type = child.file_type()?;
            if file_type.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some(ENCRYPTED_TMP_DIR_NAME) {
                    continue;
                }
                let relative_path = encrypted_relative_path(&self.encrypted_root, &path)?;
                if !relative_path.is_empty() {
                    entries.push(ProviderEntry::directory(
                        self.root_id,
                        relative_path,
                        path.clone(),
                    ));
                }
                self.scan_dir(&path, entries)?;
                continue;
            }

            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("encrypted")
                || path.file_name().and_then(|value| value.to_str())
                    == Some(DIRECTORY_METADATA_FILE_NAME)
            {
                continue;
            }

            let parsed =
                parse_encrypted_file_with_root(&self.encrypted_root, &path).map_err(|source| {
                    ProviderCoreError::MetadataParse {
                        path: path.clone(),
                        source,
                    }
                })?;
            let relative_path = decrypted_relative_path(&self.encrypted_root, &path, &parsed)?;
            entries.push(ProviderEntry::file(
                self.root_id,
                relative_path,
                path,
                parsed.metadata,
            ));
        }
        Ok(())
    }
}

#[async_trait]
pub trait ProviderBridge: Send + Sync {
    async fn inventory(&self, root_id: Uuid, encrypted_root: &Path) -> Result<Vec<ProviderEntry>>;

    async fn hydrate_file(&self, entry: &ProviderEntry) -> Result<Vec<u8>>;

    async fn hydrate_file_to_path(&self, entry: &ProviderEntry, output_path: &Path) -> Result<()> {
        let bytes = self.hydrate_file(entry).await?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(output_path, bytes)?;
        Ok(())
    }

    async fn writeback_file(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
    ) -> Result<ProviderEntry> {
        let _ = (
            root_id,
            encrypted_root,
            relative_path,
            plaintext_path,
            existing_identity,
        );
        Err(ProviderCoreError::MutationUnsupported(
            "writeback_file".to_string(),
        ))
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> Result<ProviderEntry> {
        let _ = (root_id, encrypted_root, relative_path);
        Err(ProviderCoreError::MutationUnsupported(
            "create_directory".to_string(),
        ))
    }

    async fn delete_entry(&self, encrypted_root: &Path, identity: &FileIdentityV1) -> Result<()> {
        let _ = (encrypted_root, identity);
        Err(ProviderCoreError::MutationUnsupported(
            "delete_entry".to_string(),
        ))
    }

    async fn lookup_identity(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> Result<Option<FileIdentityV1>> {
        let entries = self.inventory(root_id, encrypted_root).await?;
        let normalized = identifier.trim_start_matches('/').to_string();
        let parsed_identity = serde_json::from_str::<FileIdentityV1>(identifier).ok();
        Ok(entries.into_iter().find(|entry| {
            entry.relative_path == normalized
                || parsed_identity
                    .as_ref()
                    .map(|identity| entry.identity == *identity)
                    .unwrap_or(false)
        }).map(|entry| entry.identity))
    }

    async fn rename_entry(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> Result<Option<ProviderEntry>> {
        let _ = (
            root_id,
            encrypted_root,
            source_identity,
            target_relative_path,
            target_plaintext_path,
        );
        Err(ProviderCoreError::MutationUnsupported(
            "rename_entry".to_string(),
        ))
    }
}

pub struct LocalProviderBridge {
    crypto: Arc<dyn MountCrypto>,
}

impl LocalProviderBridge {
    pub fn new(crypto: Arc<dyn MountCrypto>) -> Self {
        Self { crypto }
    }
}

pub struct ClientMountCrypto {
    client: Arc<LocalProviderClient>,
}

impl ClientMountCrypto {
    pub fn new(client: Arc<LocalProviderClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl MountCrypto for ClientMountCrypto {
    async fn decrypt_file(
        &self,
        _encrypted_path: &Path,
        metadata: &EncryptedFileMetadata,
    ) -> std::result::Result<Vec<u8>, MountSyncError> {
        self.client
            .decrypt_file(metadata)
            .await
            .map_err(MountSyncError::from)
    }

    async fn decrypt_file_streaming(
        &self,
        encrypted_path: &Path,
        output_path: &Path,
        metadata: &EncryptedFileMetadata,
    ) -> std::result::Result<(), MountSyncError> {
        self.client
            .decrypt_file_streaming_to_path(encrypted_path, metadata, output_path)
            .await
            .map_err(MountSyncError::from)
    }

    async fn encrypt_file(
        &self,
        relative_path: &str,
        plaintext: &[u8],
    ) -> std::result::Result<EncryptedFileMetadata, MountSyncError> {
        self.client
            .encrypt_file(relative_path, plaintext)
            .await
            .map_err(MountSyncError::from)
    }

    async fn encrypt_file_with_id(
        &self,
        relative_path: &str,
        plaintext: &[u8],
        file_id: &str,
    ) -> std::result::Result<EncryptedFileMetadata, MountSyncError> {
        self.client
            .encrypt_file_with_id(relative_path, plaintext, file_id)
            .await
            .map_err(MountSyncError::from)
    }

    async fn encrypt_file_streaming(
        &self,
        relative_path: &str,
        plaintext_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        chunk_size: usize,
    ) -> std::result::Result<StreamingEncryptedFile, MountSyncError> {
        let (metadata, integrity_hash) = self
            .client
            .encrypt_file_streaming_to_path(
                relative_path,
                plaintext_path,
                output_path,
                original_name,
                platform_metadata,
                chunk_size,
            )
            .await
            .map_err(MountSyncError::from)?;
        Ok(StreamingEncryptedFile {
            metadata,
            integrity_hash,
        })
    }

    async fn encrypt_file_streaming_with_id(
        &self,
        relative_path: &str,
        plaintext_path: &Path,
        output_path: &Path,
        original_name: Option<&str>,
        platform_metadata: Option<&PlatformFileMetadata>,
        file_id: &str,
        chunk_size: usize,
    ) -> std::result::Result<StreamingEncryptedFile, MountSyncError> {
        let (metadata, integrity_hash) = self
            .client
            .encrypt_file_streaming_with_id_to_path(
                relative_path,
                plaintext_path,
                output_path,
                original_name,
                platform_metadata,
                file_id,
                chunk_size,
            )
            .await
            .map_err(MountSyncError::from)?;
        Ok(StreamingEncryptedFile {
            metadata,
            integrity_hash,
        })
    }

    async fn coverage_store_metadata(
        &self,
        metadata: FileMetadataData,
    ) -> std::result::Result<(), MountSyncError> {
        self.client
            .coverage_store_file_metadata(metadata)
            .await
            .map_err(MountSyncError::from)
    }
}

pub fn local_provider_bridge(client: Arc<LocalProviderClient>) -> Arc<dyn ProviderBridge> {
    let crypto: Arc<dyn MountCrypto> = Arc::new(ClientMountCrypto::new(client));
    Arc::new(LocalProviderBridge::new(crypto))
}

#[async_trait]
impl ProviderBridge for LocalProviderBridge {
    async fn inventory(&self, root_id: Uuid, encrypted_root: &Path) -> Result<Vec<ProviderEntry>> {
        EncryptedInventory::new(root_id, encrypted_root).scan()
    }

    async fn hydrate_file(&self, entry: &ProviderEntry) -> Result<Vec<u8>> {
        let metadata = entry.metadata.as_ref().ok_or_else(|| {
            ProviderCoreError::InvalidIdentity(format!(
                "{} is not a file entry",
                entry.relative_path
            ))
        })?;
        Ok(self
            .crypto
            .decrypt_file(&entry.encrypted_path, metadata)
            .await?)
    }

    async fn hydrate_file_to_path(&self, entry: &ProviderEntry, output_path: &Path) -> Result<()> {
        let metadata = entry.metadata.as_ref().ok_or_else(|| {
            ProviderCoreError::InvalidIdentity(format!(
                "{} is not a file entry",
                entry.relative_path
            ))
        })?;
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent)?;
        }
        self.crypto
            .decrypt_file_streaming(&entry.encrypted_path, output_path, metadata)
            .await?;
        Ok(())
    }

    async fn writeback_file(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
    ) -> Result<ProviderEntry> {
        writeback_plaintext_file(
            self.crypto.as_ref(),
            root_id,
            encrypted_root,
            relative_path,
            plaintext_path,
            existing_identity,
        )
        .await
    }

    async fn delete_entry(&self, encrypted_root: &Path, identity: &FileIdentityV1) -> Result<()> {
        let encrypted_path = encrypted_path_for_identity(encrypted_root, identity)?;
        match identity.kind {
            ProviderEntryKind::Directory => {
                if encrypted_path.exists() {
                    fs::remove_dir_all(&encrypted_path)?;
                }
            }
            ProviderEntryKind::File => {
                if encrypted_path.exists() {
                    fs::remove_file(&encrypted_path)?;
                }
            }
        }
        Ok(())
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> Result<ProviderEntry> {
        let normalized_relative_path = normalize_relative_path(relative_path);
        let mut directory_path = encrypted_root.to_path_buf();
        for component in normalized_relative_path.split('/') {
            if !component.is_empty() {
                directory_path.push(component);
            }
        }
        fs::create_dir_all(&directory_path)?;
        Ok(ProviderEntry::directory(
            root_id,
            normalized_relative_path,
            directory_path,
        ))
    }

    async fn rename_entry(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> Result<Option<ProviderEntry>> {
        if source_identity.kind == ProviderEntryKind::File {
            if let Some(target_plaintext_path) = target_plaintext_path {
                let entry = writeback_plaintext_file(
                    self.crypto.as_ref(),
                    root_id,
                    encrypted_root,
                    target_relative_path,
                    target_plaintext_path,
                    Some(source_identity),
                )
                .await?;
                let old_path = encrypted_path_for_identity(encrypted_root, source_identity)?;
                if old_path != entry.encrypted_path && old_path.exists() {
                    fs::remove_file(old_path)?;
                }
                return Ok(Some(entry));
            }
        }

        let old_path = encrypted_path_for_identity(encrypted_root, source_identity)?;
        let target_identity = FileIdentityV1::new(
            root_id,
            source_identity.kind,
            target_relative_path,
            source_identity.file_id.clone(),
            source_identity.epoch_id,
        );
        let new_path = encrypted_path_for_identity(encrypted_root, &target_identity)?;
        if let Some(parent) = new_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if old_path.exists() {
            fs::rename(old_path, &new_path)?;
        }
        Ok(None)
    }
}

pub fn normalize_relative_path(path: impl Into<String>) -> String {
    path.into()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
}

fn encrypted_relative_path(root: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| ProviderCoreError::PathOutsideRoot {
            path: path.to_path_buf(),
            root: root.to_path_buf(),
        })?;
    Ok(normalize_relative_path(relative.to_string_lossy()))
}

fn encrypted_path_for_identity(root: &Path, identity: &FileIdentityV1) -> Result<PathBuf> {
    let relative_path = PathBuf::from(identity.relative_path.replace('/', "\\"));
    Ok(match identity.kind {
        ProviderEntryKind::Directory => root.join(relative_path),
        ProviderEntryKind::File => {
            let fake_mount = Path::new("");
            encrypted_path_for(root, fake_mount, &relative_path)?
        }
    })
}

async fn writeback_plaintext_file(
    crypto: &dyn MountCrypto,
    root_id: Uuid,
    encrypted_root: &Path,
    relative_path: &str,
    plaintext_path: &Path,
    existing_identity: Option<&FileIdentityV1>,
) -> Result<ProviderEntry> {
    let normalized_relative_path = normalize_relative_path(relative_path);
    let encrypted_path = encrypted_path_for(
        encrypted_root,
        Path::new(""),
        &PathBuf::from(normalized_relative_path.replace('/', "\\")),
    )?;
    let desired_file_id = existing_identity.and_then(|identity| identity.file_id.as_deref());
    let original_name = Path::new(&normalized_relative_path)
        .file_name()
        .and_then(|name| name.to_str());
    let streaming = if let Some(file_id) = desired_file_id {
        crypto
            .encrypt_file_streaming_with_id(
                &normalized_relative_path,
                plaintext_path,
                &encrypted_path,
                original_name,
                None,
                file_id,
                PROVIDER_STREAM_CHUNK_SIZE_BYTES,
            )
            .await?
    } else {
        crypto
            .encrypt_file_streaming(
                &normalized_relative_path,
                plaintext_path,
                &encrypted_path,
                original_name,
                None,
                PROVIDER_STREAM_CHUNK_SIZE_BYTES,
            )
            .await?
    };
    let metadata = streaming.metadata;
    crypto
        .coverage_store_metadata(FileMetadataData {
            file_path: metadata.file_path.clone(),
            file_id: Some(metadata.file_id.clone()),
            group_id: metadata.group_id,
            epoch_id: metadata.epoch_id,
            header_version: metadata.header_version,
            wrapped_file_key: metadata.wrapped_file_key.clone(),
            key_wrap_nonce: metadata.key_wrap_nonce.clone(),
            key_wrap_aad_hash: metadata.key_wrap_aad_hash.clone(),
            content_nonce: metadata.content_nonce.clone(),
            content_chunk_size: metadata.content_chunk_size,
            algorithm: "ChaCha20-Poly1305".to_string(),
            file_size: metadata.content_size,
            modified_at: metadata.created_at,
            integrity_hash: streaming.integrity_hash,
            permissions: AccessControlData {
                readers: Vec::new(),
                writers: Vec::new(),
                is_public: true,
            },
            version: 1,
            chunks: Vec::new(),
            encrypted_size: metadata.encrypted_size,
            encrypted_at: metadata.created_at,
        })
        .await?;

    Ok(ProviderEntry::file(
        root_id,
        normalized_relative_path,
        encrypted_path,
        metadata,
    ))
}

fn decrypted_relative_path(
    root: &Path,
    encrypted_path: &Path,
    parsed: &hybridcipher_mount_sync::ParsedEncryptedFile,
) -> Result<String> {
    let relative =
        encrypted_path
            .strip_prefix(root)
            .map_err(|_| ProviderCoreError::PathOutsideRoot {
                path: encrypted_path.to_path_buf(),
                root: root.to_path_buf(),
            })?;
    let mut relative = relative.to_path_buf();
    let decrypted_name = parsed.original_name.clone().unwrap_or_else(|| {
        encrypted_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
            .trim_end_matches(".encrypted")
            .to_string()
    });
    relative.set_file_name(decrypted_name);
    Ok(normalize_relative_path(relative.to_string_lossy()))
}

fn hash_relative_path(path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.as_bytes());
    let digest = hasher.finalize();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_validates_hash() {
        let root_id = Uuid::new_v4();
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            r"folder\demo.txt",
            Some("file-1".to_string()),
            Some(7),
        );
        let bytes = identity.to_bytes().unwrap();
        let parsed = FileIdentityV1::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.relative_path, "folder/demo.txt");
        assert_eq!(parsed.file_id.as_deref(), Some("file-1"));
        assert_eq!(parsed.epoch_id, Some(7));
    }

    #[test]
    fn cache_file_entry_uses_cache_metadata_when_encrypted_metadata_is_missing() {
        let root_id = Uuid::new_v4();
        let modified_at = Utc::now();

        let entry = ProviderEntry::cache_file(
            root_id,
            "docs/draft.txt",
            PathBuf::from("/encrypted/docs/draft.txt.encrypted"),
            14,
            0,
            modified_at,
            None,
        );

        assert_eq!(entry.kind, ProviderEntryKind::File);
        assert_eq!(entry.relative_path, "docs/draft.txt");
        assert_eq!(entry.logical_size, 14);
        assert_eq!(entry.encrypted_size, 0);
        assert_eq!(entry.modified_at, modified_at);
        assert!(entry.metadata.is_none());
        assert!(entry.identity.file_id.is_none());
        assert!(entry.identity.epoch_id.is_none());
    }

    #[test]
    fn cache_file_entry_preserves_identity_from_existing_metadata() {
        let root_id = Uuid::new_v4();
        let modified_at = Utc::now();
        let metadata = EncryptedFileMetadata {
            file_id: "stable-file-id".to_string(),
            file_path: "docs/report.txt".to_string(),
            header_version: Some(2),
            group_id: Some(root_id),
            epoch_id: 42,
            wrapped_file_key: None,
            key_wrap_nonce: None,
            key_wrap_aad_hash: None,
            content_nonce: None,
            content_chunk_size: None,
            content_size: 12,
            encrypted_size: 80,
            created_at: modified_at - chrono::Duration::days(1),
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: Vec::new(),
        };

        let entry = ProviderEntry::cache_file(
            root_id,
            "docs/report.txt",
            PathBuf::from("/encrypted/docs/report.txt.encrypted"),
            17,
            82,
            modified_at,
            Some(metadata),
        );

        assert_eq!(entry.identity.file_id.as_deref(), Some("stable-file-id"));
        assert_eq!(entry.identity.epoch_id, Some(42));
        assert_eq!(entry.modified_at, modified_at);
        assert_eq!(entry.logical_size, 17);
        assert_eq!(entry.encrypted_size, 82);
        assert!(entry.metadata.is_some());
    }
}
