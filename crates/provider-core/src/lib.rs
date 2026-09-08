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
    collections::HashMap,
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
    #[error("provider content conflict at {path}")]
    ContentConflict {
        path: String,
        expected: Option<ProviderContentVersion>,
        actual: Option<ProviderContentVersion>,
    },
}

impl ProviderCoreError {
    pub fn is_path_excluded(&self) -> bool {
        matches!(self, Self::Crypto(MountSyncError::PathExcluded(_)))
    }
}

pub type Result<T> = std::result::Result<T, ProviderCoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderEntryKind {
    Directory,
    File,
}

/// A path-independent revision for encrypted file contents.
///
/// The fields included here are authenticated by the encrypted file format and
/// change whenever the encrypted body is replaced. The current relative path is
/// deliberately excluded so a rename does not manufacture a content conflict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct ProviderContentVersion(String);

impl ProviderContentVersion {
    pub fn from_metadata(metadata: &EncryptedFileMetadata) -> Self {
        Self::from_components(
            &metadata.file_id,
            metadata.group_id,
            metadata.epoch_id,
            metadata.header_version,
            metadata.content_size,
            metadata.encrypted_size,
            metadata.content_nonce.as_deref(),
            metadata.key_wrap_aad_hash.as_deref(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_components(
        file_id: &str,
        group_id: Option<Uuid>,
        epoch_id: u64,
        header_version: Option<u32>,
        content_size: u64,
        encrypted_size: u64,
        content_nonce: Option<&[u8]>,
        key_wrap_aad_hash: Option<&[u8]>,
    ) -> Self {
        fn update_bytes(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha256::new();
        update_bytes(&mut hasher, file_id.as_bytes());
        hasher.update(epoch_id.to_le_bytes());
        hasher.update(header_version.unwrap_or_default().to_le_bytes());
        hasher.update(content_size.to_le_bytes());
        hasher.update(encrypted_size.to_le_bytes());
        update_bytes(&mut hasher, content_nonce.unwrap_or_default());
        update_bytes(&mut hasher, key_wrap_aad_hash.unwrap_or_default());
        if let Some(group_id) = group_id {
            update_bytes(&mut hasher, group_id.as_bytes());
        } else {
            update_bytes(&mut hasher, &[]);
        }
        let digest = hasher.finalize();
        Self(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedProviderVersion {
    Unchecked,
    Absent,
    Exact(ProviderContentVersion),
}

pub fn validate_expected_content_version(
    relative_path: &str,
    expected: &ExpectedProviderVersion,
    actual: Option<&ProviderContentVersion>,
) -> Result<()> {
    let matches = match expected {
        ExpectedProviderVersion::Unchecked => true,
        ExpectedProviderVersion::Absent => actual.is_none(),
        ExpectedProviderVersion::Exact(expected) => actual == Some(expected),
    };
    if matches {
        Ok(())
    } else {
        Err(ProviderCoreError::ContentConflict {
            path: normalize_relative_path(relative_path),
            expected: match expected {
                ExpectedProviderVersion::Exact(version) => Some(version.clone()),
                ExpectedProviderVersion::Unchecked | ExpectedProviderVersion::Absent => None,
            },
            actual: actual.cloned(),
        })
    }
}

fn resolve_checked_delete_entry<'a>(
    inventory: &'a [ProviderEntry],
    identity: &FileIdentityV1,
) -> Result<Option<&'a ProviderEntry>> {
    let relative_path = normalize_relative_path(&identity.relative_path);
    let path_entry = inventory.iter().find(|entry| {
        entry.root_id == identity.root_id
            && entry.kind == identity.kind
            && entry.relative_path == relative_path
    });
    let same_object = |entry: &&ProviderEntry| {
        entry.root_id == identity.root_id
            && entry.kind == identity.kind
            && identity
                .file_id
                .as_ref()
                .zip(entry.identity.file_id.as_ref())
                .is_some_and(|(expected, actual)| expected == actual)
    };

    match path_entry {
        Some(entry) if identity.file_id.is_none() || same_object(&entry) => Ok(Some(entry)),
        Some(entry) => Err(ProviderCoreError::ContentConflict {
            path: relative_path,
            expected: None,
            actual: entry.content_version(),
        }),
        None => {
            if let Some(moved_entry) = inventory.iter().find(same_object) {
                Err(ProviderCoreError::ContentConflict {
                    path: relative_path,
                    expected: None,
                    actual: moved_entry.content_version(),
                })
            } else {
                Ok(None)
            }
        }
    }
}

fn resolve_checked_writeback_entry<'a>(
    inventory: &'a [ProviderEntry],
    root_id: Uuid,
    relative_path: &str,
    identity: &FileIdentityV1,
) -> Result<&'a ProviderEntry> {
    let relative_path = normalize_relative_path(relative_path);
    if identity.root_id != root_id
        || identity.kind != ProviderEntryKind::File
        || identity.file_id.is_none()
        || normalize_relative_path(&identity.relative_path) != relative_path
    {
        return Err(ProviderCoreError::InvalidIdentity(format!(
            "checked writeback identity is not a stable file identity for {relative_path}"
        )));
    }
    match resolve_checked_delete_entry(inventory, identity)? {
        Some(entry) => Ok(entry),
        None => Err(ProviderCoreError::ContentConflict {
            path: relative_path,
            expected: None,
            actual: None,
        }),
    }
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
    pub fn content_version(&self) -> Option<ProviderContentVersion> {
        self.metadata
            .as_ref()
            .map(ProviderContentVersion::from_metadata)
    }

    fn directory(
        root_id: Uuid,
        relative_path: String,
        encrypted_path: PathBuf,
        metadata: Option<EncryptedFileMetadata>,
    ) -> Self {
        let file_id = metadata.as_ref().map(|metadata| metadata.file_id.clone());
        let epoch_id = metadata.as_ref().map(|metadata| metadata.epoch_id);
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::Directory,
            relative_path.clone(),
            file_id,
            epoch_id,
        );
        let encrypted_size = metadata
            .as_ref()
            .map(|metadata| metadata.encrypted_size)
            .unwrap_or_default();
        let modified_at = metadata
            .as_ref()
            .map(|metadata| metadata.created_at)
            .unwrap_or_else(Utc::now);
        Self {
            root_id,
            kind: ProviderEntryKind::Directory,
            relative_path,
            encrypted_path,
            identity,
            metadata,
            logical_size: 0,
            encrypted_size,
            modified_at,
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

    pub fn cache_directory_with_identity(
        root_id: Uuid,
        relative_path: impl Into<String>,
        encrypted_path: impl Into<PathBuf>,
        modified_at: DateTime<Utc>,
        file_id: impl Into<String>,
        epoch_id: u64,
    ) -> Self {
        let relative_path = normalize_relative_path(relative_path.into());
        let identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::Directory,
            relative_path.clone(),
            Some(file_id.into()),
            Some(epoch_id),
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
        self.scan_filtered(&|_| false)
    }

    pub fn scan_filtered(
        &self,
        is_excluded: &impl Fn(&Path) -> bool,
    ) -> Result<Vec<ProviderEntry>> {
        let mut entries = Vec::new();
        if !self.encrypted_root.exists() {
            return Ok(entries);
        }
        self.scan_dir(&self.encrypted_root, &mut entries, is_excluded)?;
        entries.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
        Ok(entries)
    }

    fn scan_dir(
        &self,
        dir: &Path,
        entries: &mut Vec<ProviderEntry>,
        is_excluded: &impl Fn(&Path) -> bool,
    ) -> Result<()> {
        for child in fs::read_dir(dir)? {
            let child = child?;
            let path = child.path();
            let file_type = child.file_type()?;
            if file_type.is_dir() {
                if path.file_name().and_then(|name| name.to_str()) == Some(ENCRYPTED_TMP_DIR_NAME) {
                    continue;
                }
                let relative_path = encrypted_relative_path(&self.encrypted_root, &path)?;
                if is_excluded(Path::new(&relative_path)) {
                    continue;
                }
                if !relative_path.is_empty() {
                    entries.push(ProviderEntry::directory(
                        self.root_id,
                        relative_path,
                        path.clone(),
                        None,
                    ));
                }
                self.scan_dir(&path, entries, is_excluded)?;
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
            if is_excluded(Path::new(&relative_path)) {
                continue;
            }
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
    fn is_path_excluded(&self, _encrypted_root: &Path, _relative_path: &Path) -> bool {
        false
    }

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

    async fn writeback_file_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
        expected_version: &ExpectedProviderVersion,
    ) -> Result<ProviderEntry> {
        let inventory = self.inventory(root_id, encrypted_root).await?;
        let resolved_identity = match existing_identity {
            Some(identity) => Some(
                resolve_checked_writeback_entry(&inventory, root_id, relative_path, identity)?
                    .identity
                    .clone(),
            ),
            None => None,
        };
        let actual = match resolved_identity.as_ref() {
            Some(identity) => inventory
                .iter()
                .find(|entry| entry.identity == *identity)
                .and_then(ProviderEntry::content_version),
            None => inventory
                .iter()
                .find(|entry| entry.relative_path == normalize_relative_path(relative_path))
                .and_then(ProviderEntry::content_version),
        };
        validate_expected_content_version(relative_path, expected_version, actual.as_ref())?;
        self.writeback_file(
            root_id,
            encrypted_root,
            relative_path,
            plaintext_path,
            resolved_identity.as_ref(),
        )
        .await
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

    async fn delete_entry_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identity: &FileIdentityV1,
        expected_version: &ExpectedProviderVersion,
    ) -> Result<()> {
        let inventory = self.inventory(root_id, encrypted_root).await?;
        let Some(entry) = resolve_checked_delete_entry(&inventory, identity)? else {
            return Ok(());
        };
        let actual = entry.content_version();
        validate_expected_content_version(
            &identity.relative_path,
            expected_version,
            actual.as_ref(),
        )?;
        self.delete_entry(encrypted_root, &entry.identity).await
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
        Ok(entries
            .into_iter()
            .find(|entry| {
                entry.relative_path == normalized
                    || parsed_identity
                        .as_ref()
                        .map(|identity| entry.identity == *identity)
                        .unwrap_or(false)
            })
            .map(|entry| entry.identity))
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

    async fn rename_entry_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
        expected_version: &ExpectedProviderVersion,
    ) -> Result<Option<ProviderEntry>> {
        let inventory = self.inventory(root_id, encrypted_root).await?;
        let normalized_target = normalize_relative_path(target_relative_path);
        let target = inventory
            .iter()
            .find(|entry| entry.relative_path == normalized_target);
        let target_is_same_object = target.is_some_and(|entry| {
            entry.root_id == source_identity.root_id
                && entry.kind == source_identity.kind
                && source_identity
                    .file_id
                    .as_ref()
                    .zip(entry.identity.file_id.as_ref())
                    .map(|(expected, actual)| expected == actual)
                    .unwrap_or(false)
        });
        let source = match resolve_checked_delete_entry(&inventory, source_identity) {
            Ok(Some(source)) => source,
            Ok(None) if target_is_same_object => return Ok(target.cloned()),
            Ok(None) => {
                return Err(ProviderCoreError::ContentConflict {
                    path: normalize_relative_path(&source_identity.relative_path),
                    expected: None,
                    actual: None,
                })
            }
            Err(_) if target_is_same_object => return Ok(target.cloned()),
            Err(err) => return Err(err),
        };
        validate_expected_content_version(
            &source_identity.relative_path,
            expected_version,
            source.content_version().as_ref(),
        )?;
        if target_is_same_object {
            self.delete_entry(encrypted_root, &source.identity).await?;
            return Ok(target.cloned());
        }
        if inventory.iter().any(|entry| {
            entry.relative_path == normalize_relative_path(target_relative_path)
                && entry.identity.file_id != source_identity.file_id
        }) {
            return Err(ProviderCoreError::ContentConflict {
                path: normalize_relative_path(target_relative_path),
                expected: None,
                actual: inventory
                    .iter()
                    .find(|entry| {
                        entry.relative_path == normalize_relative_path(target_relative_path)
                    })
                    .and_then(ProviderEntry::content_version),
            });
        }
        self.rename_entry(
            root_id,
            encrypted_root,
            &source.identity,
            target_relative_path,
            target_plaintext_path,
        )
        .await
    }
}

pub struct LocalProviderBridge {
    crypto: Arc<dyn MountCrypto>,
}

impl LocalProviderBridge {
    pub fn new(crypto: Arc<dyn MountCrypto>) -> Self {
        Self { crypto }
    }

    fn path_or_ancestor_is_excluded(&self, encrypted_root: &Path, relative_path: &Path) -> bool {
        let mut candidate = Some(relative_path);
        while let Some(path) = candidate {
            if path.as_os_str().is_empty() {
                break;
            }
            if self.crypto.is_path_excluded(path)
                || self.crypto.is_path_excluded(&encrypted_root.join(path))
            {
                return true;
            }
            candidate = path.parent();
        }
        false
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
    fn is_path_excluded(&self, path: &Path) -> bool {
        self.client.is_path_excluded(path)
    }

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
    fn is_path_excluded(&self, encrypted_root: &Path, relative_path: &Path) -> bool {
        self.path_or_ancestor_is_excluded(encrypted_root, relative_path)
    }

    async fn inventory(&self, root_id: Uuid, encrypted_root: &Path) -> Result<Vec<ProviderEntry>> {
        let entries = EncryptedInventory::new(root_id, encrypted_root)
            .scan_filtered(&|path| self.path_or_ancestor_is_excluded(encrypted_root, path))?;
        let mut authenticated_entries = Vec::with_capacity(entries.len());
        let mut excluded_directory_prefixes = Vec::new();
        for mut entry in entries {
            if excluded_directory_prefixes.iter().any(|prefix: &String| {
                entry.relative_path == *prefix
                    || entry
                        .relative_path
                        .strip_prefix(prefix)
                        .is_some_and(|suffix| suffix.starts_with('/'))
            }) {
                continue;
            }
            if entry.kind != ProviderEntryKind::Directory {
                authenticated_entries.push(entry);
                continue;
            }
            let relative_path = entry.relative_path.clone();
            let directory_path = entry.encrypted_path.clone();
            entry = match ensure_directory_sidecar(
                self.crypto.as_ref(),
                root_id,
                encrypted_root,
                &relative_path,
                &directory_path,
            )
            .await
            {
                Ok(entry) => entry,
                // Encryption is the final authority for exclusions. Treat an exclusion
                // reported here as a filtered subtree even if a caller-side matcher and
                // the encryptor briefly disagree (for example across config reloads).
                Err(error) if error.is_path_excluded() => {
                    excluded_directory_prefixes.push(relative_path);
                    continue;
                }
                Err(error) => return Err(error),
            };
            entry.identity.file_id.as_ref().ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "authenticated directory {relative_path} has no file id"
                ))
            })?;
            authenticated_entries.push(entry);
        }
        let entries = authenticated_entries;

        let mut entries_by_id = HashMap::new();
        for entry in &entries {
            let Some(file_id) = entry.identity.file_id.as_ref() else {
                continue;
            };
            if let Some(existing_path) =
                entries_by_id.insert(file_id.clone(), entry.relative_path.clone())
            {
                return Err(ProviderCoreError::InvalidIdentity(format!(
                    "stable identity {file_id} is shared by {existing_path} and {}",
                    entry.relative_path
                )));
            }
        }
        Ok(entries)
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

    async fn writeback_file_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
        expected_version: &ExpectedProviderVersion,
    ) -> Result<ProviderEntry> {
        let inventory = self.inventory(root_id, encrypted_root).await?;
        let resolved_identity = match existing_identity {
            Some(identity) => Some(
                resolve_checked_writeback_entry(&inventory, root_id, relative_path, identity)?
                    .identity
                    .clone(),
            ),
            None => None,
        };
        writeback_plaintext_file_checked(
            self.crypto.as_ref(),
            root_id,
            encrypted_root,
            relative_path,
            plaintext_path,
            resolved_identity.as_ref(),
            expected_version,
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
        let mut component_path = String::new();
        let mut target_entry = None;
        for component in normalized_relative_path.split('/') {
            if !component.is_empty() {
                directory_path.push(component);
                if !component_path.is_empty() {
                    component_path.push('/');
                }
                component_path.push_str(component);
                fs::create_dir_all(&directory_path)?;
                target_entry = Some(
                    ensure_directory_sidecar(
                        self.crypto.as_ref(),
                        root_id,
                        encrypted_root,
                        &component_path,
                        &directory_path,
                    )
                    .await?,
                );
            }
        }
        target_entry.ok_or_else(|| {
            ProviderCoreError::InvalidIdentity("directory path must not be empty".to_string())
        })
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

    async fn rename_entry_checked(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
        expected_version: &ExpectedProviderVersion,
    ) -> Result<Option<ProviderEntry>> {
        let inventory = self.inventory(root_id, encrypted_root).await?;
        let normalized_target = normalize_relative_path(target_relative_path);
        let target = inventory
            .iter()
            .find(|entry| entry.relative_path == normalized_target);
        let target_is_same_object = target.is_some_and(|entry| {
            entry.root_id == source_identity.root_id
                && entry.kind == source_identity.kind
                && source_identity
                    .file_id
                    .as_ref()
                    .zip(entry.identity.file_id.as_ref())
                    .map(|(expected, actual)| expected == actual)
                    .unwrap_or(false)
        });
        let source = match resolve_checked_delete_entry(&inventory, source_identity) {
            Ok(Some(source)) => source,
            Ok(None) if target_is_same_object => return Ok(target.cloned()),
            Ok(None) => {
                return Err(ProviderCoreError::ContentConflict {
                    path: normalize_relative_path(&source_identity.relative_path),
                    expected: None,
                    actual: None,
                })
            }
            Err(_) if target_is_same_object => return Ok(target.cloned()),
            Err(err) => return Err(err),
        };
        validate_expected_content_version(
            &source_identity.relative_path,
            expected_version,
            source.content_version().as_ref(),
        )?;
        if target_is_same_object {
            self.delete_entry(encrypted_root, &source.identity).await?;
            return Ok(target.cloned());
        }
        if let Some(target) = target {
            return Err(ProviderCoreError::ContentConflict {
                path: normalized_target,
                expected: None,
                actual: target.content_version(),
            });
        }

        if source_identity.kind == ProviderEntryKind::File {
            if let Some(target_plaintext_path) = target_plaintext_path {
                let entry = writeback_plaintext_file_checked(
                    self.crypto.as_ref(),
                    root_id,
                    encrypted_root,
                    &normalized_target,
                    target_plaintext_path,
                    Some(&source.identity),
                    &ExpectedProviderVersion::Absent,
                )
                .await?;
                let old_path = encrypted_path_for_identity(encrypted_root, &source.identity)?;
                let source_now = content_version_at_path(encrypted_root, &old_path)?;
                validate_expected_content_version(
                    &source_identity.relative_path,
                    expected_version,
                    source_now.as_ref(),
                )?;
                if old_path != entry.encrypted_path && old_path.exists() {
                    fs::remove_file(old_path)?;
                }
                return Ok(Some(entry));
            }
        }

        self.rename_entry(
            root_id,
            encrypted_root,
            &source.identity,
            &normalized_target,
            target_plaintext_path,
        )
        .await
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

async fn ensure_directory_sidecar(
    crypto: &dyn MountCrypto,
    root_id: Uuid,
    encrypted_root: &Path,
    relative_path: &str,
    directory_path: &Path,
) -> Result<ProviderEntry> {
    let sidecar_path = directory_path.join(DIRECTORY_METADATA_FILE_NAME);
    if !sidecar_path.exists() {
        let result = crypto.encrypt_file(relative_path, b"").await?;
        let original_name = Path::new(relative_path)
            .file_name()
            .and_then(|name| name.to_str());
        let header = hybridcipher_client::file::SerializedEncryptedHeader {
            file_id: &result.file_id,
            file_path: &result.file_path,
            group_id: result.group_id,
            epoch_id: result.epoch_id,
            header_version: result.header_version.unwrap_or(1),
            wrapped_file_key: result.wrapped_file_key.as_deref().ok_or_else(|| {
                ProviderCoreError::Crypto(MountSyncError::Format(
                    "directory metadata is missing wrapped_file_key".into(),
                ))
            })?,
            key_wrap_nonce: result.key_wrap_nonce.as_deref().ok_or_else(|| {
                ProviderCoreError::Crypto(MountSyncError::Format(
                    "directory metadata is missing key_wrap_nonce".into(),
                ))
            })?,
            key_wrap_aad_hash: result.key_wrap_aad_hash.as_deref().ok_or_else(|| {
                ProviderCoreError::Crypto(MountSyncError::Format(
                    "directory metadata is missing key_wrap_aad_hash".into(),
                ))
            })?,
            content_nonce: result.content_nonce.as_deref().ok_or_else(|| {
                ProviderCoreError::Crypto(MountSyncError::Format(
                    "directory metadata is missing content_nonce".into(),
                ))
            })?,
            content_chunk_size: result.content_chunk_size,
            original_size: 0,
            encrypted_size: result.encrypted_size,
            encrypted_at: result.created_at,
            original_name,
            platform_metadata: result.platform_metadata.as_ref(),
            sparse_metadata: None,
        };
        publish_directory_sidecar_if_absent(directory_path, &sidecar_path, &header, &result)?;
    }
    let metadata = authenticate_directory_sidecar(crypto, encrypted_root, &sidecar_path).await?;

    let mut integrity_hash = [0u8; 32];
    integrity_hash.copy_from_slice(&Sha256::digest([]));
    store_streaming_coverage(
        crypto,
        &StreamingEncryptedFile {
            metadata: metadata.clone(),
            integrity_hash,
        },
    )
    .await?;

    Ok(ProviderEntry::directory(
        root_id,
        relative_path.to_string(),
        directory_path.to_path_buf(),
        Some(metadata),
    ))
}

fn publish_directory_sidecar_if_absent(
    directory_path: &Path,
    sidecar_path: &Path,
    header: &hybridcipher_client::file::SerializedEncryptedHeader<'_>,
    encrypted: &EncryptedFileMetadata,
) -> Result<()> {
    let staging_dir = directory_path.join(ENCRYPTED_TMP_DIR_NAME);
    fs::create_dir_all(&staging_dir)?;
    let staging_path = staging_dir.join(format!("directory-{}.encrypted", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        hybridcipher_client::file::write_encrypted_file(
            &staging_path,
            header,
            &encrypted.encrypted_content,
        )
        .map_err(|error| {
            ProviderCoreError::Crypto(MountSyncError::Format(format!(
                "failed to stage directory metadata: {error}"
            )))
        })?;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&staging_path)?
            .sync_all()?;
        match fs::hard_link(&staging_path, sidecar_path) {
            Ok(()) => {
                if let Ok(directory) = fs::File::open(directory_path) {
                    let _ = directory.sync_all();
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })();
    let _ = fs::remove_file(&staging_path);
    result
}

async fn authenticate_directory_sidecar(
    crypto: &dyn MountCrypto,
    encrypted_root: &Path,
    sidecar_path: &Path,
) -> Result<EncryptedFileMetadata> {
    let metadata = parse_encrypted_file_with_root(encrypted_root, sidecar_path)
        .map_err(|source| ProviderCoreError::MetadataParse {
            path: sidecar_path.to_path_buf(),
            source,
        })?
        .metadata;
    if metadata.content_size != 0 {
        return Err(ProviderCoreError::InvalidIdentity(format!(
            "directory metadata {} has non-empty declared content",
            sidecar_path.display()
        )));
    }
    let plaintext = crypto.decrypt_file(sidecar_path, &metadata).await?;
    if !plaintext.is_empty() {
        return Err(ProviderCoreError::InvalidIdentity(format!(
            "directory metadata {} decrypted to non-empty content",
            sidecar_path.display()
        )));
    }
    Ok(metadata)
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
    let streaming = encrypt_plaintext_to_path(
        crypto,
        &normalized_relative_path,
        plaintext_path,
        &encrypted_path,
        existing_identity,
    )
    .await?;
    store_streaming_coverage(crypto, &streaming).await?;
    Ok(ProviderEntry::file(
        root_id,
        normalized_relative_path,
        encrypted_path,
        streaming.metadata,
    ))
}

async fn writeback_plaintext_file_checked(
    crypto: &dyn MountCrypto,
    root_id: Uuid,
    encrypted_root: &Path,
    relative_path: &str,
    plaintext_path: &Path,
    existing_identity: Option<&FileIdentityV1>,
    expected_version: &ExpectedProviderVersion,
) -> Result<ProviderEntry> {
    let normalized_relative_path = normalize_relative_path(relative_path);
    let encrypted_path = encrypted_path_for(
        encrypted_root,
        Path::new(""),
        &PathBuf::from(normalized_relative_path.replace('/', "\\")),
    )?;
    let before = content_version_at_path(encrypted_root, &encrypted_path)?;
    validate_expected_content_version(
        &normalized_relative_path,
        expected_version,
        before.as_ref(),
    )?;

    let staging_dir = encrypted_root.join(ENCRYPTED_TMP_DIR_NAME);
    fs::create_dir_all(&staging_dir)?;
    let staging_path = staging_dir.join(format!("checked-{}.encrypted", Uuid::new_v4()));
    let streaming = match encrypt_plaintext_to_path(
        crypto,
        &normalized_relative_path,
        plaintext_path,
        &staging_path,
        existing_identity,
    )
    .await
    {
        Ok(streaming) => streaming,
        Err(err) => {
            let _ = fs::remove_file(&staging_path);
            return Err(err);
        }
    };

    let current = content_version_at_path(encrypted_root, &encrypted_path)?;
    if let Err(err) = validate_expected_content_version(
        &normalized_relative_path,
        expected_version,
        current.as_ref(),
    ) {
        let _ = fs::remove_file(&staging_path);
        return Err(err);
    }
    if let Some(parent) = encrypted_path.parent() {
        fs::create_dir_all(parent)?;
    }
    replace_encrypted_file(&staging_path, &encrypted_path)?;
    store_streaming_coverage(crypto, &streaming).await?;
    Ok(ProviderEntry::file(
        root_id,
        normalized_relative_path,
        encrypted_path,
        streaming.metadata,
    ))
}

async fn encrypt_plaintext_to_path(
    crypto: &dyn MountCrypto,
    normalized_relative_path: &str,
    plaintext_path: &Path,
    output_path: &Path,
    existing_identity: Option<&FileIdentityV1>,
) -> Result<StreamingEncryptedFile> {
    let desired_file_id = existing_identity.and_then(|identity| identity.file_id.as_deref());
    let original_name = Path::new(&normalized_relative_path)
        .file_name()
        .and_then(|name| name.to_str());
    Ok(if let Some(file_id) = desired_file_id {
        crypto
            .encrypt_file_streaming_with_id(
                &normalized_relative_path,
                plaintext_path,
                output_path,
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
                output_path,
                original_name,
                None,
                PROVIDER_STREAM_CHUNK_SIZE_BYTES,
            )
            .await?
    })
}

async fn store_streaming_coverage(
    crypto: &dyn MountCrypto,
    streaming: &StreamingEncryptedFile,
) -> Result<()> {
    let metadata = &streaming.metadata;
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
    Ok(())
}

fn content_version_at_path(
    encrypted_root: &Path,
    encrypted_path: &Path,
) -> Result<Option<ProviderContentVersion>> {
    if !encrypted_path.exists() {
        return Ok(None);
    }
    let parsed =
        parse_encrypted_file_with_root(encrypted_root, encrypted_path).map_err(|source| {
            ProviderCoreError::MetadataParse {
                path: encrypted_path.to_path_buf(),
                source,
            }
        })?;
    Ok(Some(ProviderContentVersion::from_metadata(
        &parsed.metadata,
    )))
}

#[cfg(not(target_os = "windows"))]
fn replace_encrypted_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    if let Some(parent) = destination.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_encrypted_file(source: &Path, destination: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error))?;
    }
    Ok(())
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
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct DirectoryTestCrypto {
        next_id: AtomicUsize,
        fail_coverage_once: AtomicBool,
        encrypt_barrier: Option<Arc<tokio::sync::Barrier>>,
        exclude_obsidian: bool,
        report_obsidian_exclusion: bool,
    }

    impl DirectoryTestCrypto {
        fn new(fail_coverage_once: bool) -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                fail_coverage_once: AtomicBool::new(fail_coverage_once),
                encrypt_barrier: None,
                exclude_obsidian: false,
                report_obsidian_exclusion: false,
            }
        }

        fn excluding_obsidian() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                fail_coverage_once: AtomicBool::new(false),
                encrypt_barrier: None,
                exclude_obsidian: true,
                report_obsidian_exclusion: true,
            }
        }

        fn encryptor_only_excluding_obsidian() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                fail_coverage_once: AtomicBool::new(false),
                encrypt_barrier: None,
                exclude_obsidian: true,
                report_obsidian_exclusion: false,
            }
        }

        fn concurrent() -> Self {
            Self {
                next_id: AtomicUsize::new(1),
                fail_coverage_once: AtomicBool::new(false),
                encrypt_barrier: Some(Arc::new(tokio::sync::Barrier::new(2))),
                exclude_obsidian: false,
                report_obsidian_exclusion: false,
            }
        }

        fn metadata(&self, relative_path: &str, plaintext: &[u8]) -> EncryptedFileMetadata {
            let id = self.next_id.fetch_add(1, Ordering::SeqCst);
            EncryptedFileMetadata {
                file_id: format!("directory-{id}"),
                file_path: relative_path.to_string(),
                header_version: Some(1),
                group_id: None,
                epoch_id: 7,
                wrapped_file_key: Some(vec![1; 32]),
                key_wrap_nonce: Some(vec![2; 24]),
                key_wrap_aad_hash: Some(vec![3; 32]),
                content_nonce: Some(vec![4; 24]),
                content_chunk_size: None,
                content_size: plaintext.len() as u64,
                encrypted_size: 32,
                created_at: Utc::now(),
                platform_metadata: None,
                sparse_metadata: None,
                encrypted_content: directory_auth_bytes(
                    &format!("directory-{id}"),
                    relative_path,
                    plaintext.len() as u64,
                )
                .to_vec(),
            }
        }
    }

    #[async_trait]
    impl MountCrypto for DirectoryTestCrypto {
        fn is_path_excluded(&self, path: &Path) -> bool {
            let normalized = path.to_string_lossy().replace('\\', "/");
            self.report_obsidian_exclusion
                && (normalized == ".obsidian"
                    || normalized.starts_with(".obsidian/")
                    || normalized.contains("/.obsidian/"))
        }

        async fn decrypt_file(
            &self,
            _encrypted_path: &Path,
            metadata: &EncryptedFileMetadata,
        ) -> std::result::Result<Vec<u8>, MountSyncError> {
            let expected = directory_auth_bytes(
                &metadata.file_id,
                &metadata.file_path,
                metadata.content_size,
            );
            if metadata.encrypted_content != expected {
                return Err(MountSyncError::Format(
                    "directory authentication failed".into(),
                ));
            }
            Ok(Vec::new())
        }

        async fn decrypt_file_streaming(
            &self,
            _encrypted_path: &Path,
            _output_path: &Path,
            _metadata: &EncryptedFileMetadata,
        ) -> std::result::Result<(), MountSyncError> {
            Err(MountSyncError::Format("unused streaming decrypt".into()))
        }

        async fn encrypt_file(
            &self,
            relative_path: &str,
            plaintext: &[u8],
        ) -> std::result::Result<EncryptedFileMetadata, MountSyncError> {
            if self.exclude_obsidian && relative_path.replace('\\', "/").starts_with(".obsidian") {
                return Err(MountSyncError::PathExcluded(relative_path.to_string()));
            }
            let metadata = self.metadata(relative_path, plaintext);
            if let Some(barrier) = &self.encrypt_barrier {
                barrier.wait().await;
            }
            Ok(metadata)
        }

        async fn encrypt_file_with_id(
            &self,
            relative_path: &str,
            plaintext: &[u8],
            file_id: &str,
        ) -> std::result::Result<EncryptedFileMetadata, MountSyncError> {
            let mut metadata = self.metadata(relative_path, plaintext);
            metadata.file_id = file_id.to_string();
            metadata.encrypted_content = directory_auth_bytes(
                &metadata.file_id,
                &metadata.file_path,
                metadata.content_size,
            )
            .to_vec();
            Ok(metadata)
        }

        async fn encrypt_file_streaming(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _chunk_size: usize,
        ) -> std::result::Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Format("unused streaming encrypt".into()))
        }

        async fn encrypt_file_streaming_with_id(
            &self,
            _relative_path: &str,
            _plaintext_path: &Path,
            _output_path: &Path,
            _original_name: Option<&str>,
            _platform_metadata: Option<&PlatformFileMetadata>,
            _file_id: &str,
            _chunk_size: usize,
        ) -> std::result::Result<StreamingEncryptedFile, MountSyncError> {
            Err(MountSyncError::Format("unused streaming encrypt".into()))
        }

        async fn coverage_store_metadata(
            &self,
            metadata: FileMetadataData,
        ) -> std::result::Result<(), MountSyncError> {
            if metadata.file_path == "docs/nested"
                && self.fail_coverage_once.swap(false, Ordering::SeqCst)
            {
                Err(MountSyncError::Format("injected coverage failure".into()))
            } else {
                Ok(())
            }
        }
    }

    fn directory_auth_bytes(file_id: &str, file_path: &str, content_size: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(file_id.as_bytes());
        hasher.update([0]);
        hasher.update(file_path.as_bytes());
        hasher.update(content_size.to_le_bytes());
        hasher.finalize().into()
    }

    fn write_directory_sidecar(path: &Path, relative_path: &str, file_id: &str) {
        let encrypted_at = Utc::now();
        let encrypted_content = directory_auth_bytes(file_id, relative_path, 0);
        let header = hybridcipher_client::file::SerializedEncryptedHeader {
            file_id,
            file_path: relative_path,
            group_id: None,
            epoch_id: 7,
            header_version: 1,
            wrapped_file_key: &[1; 32],
            key_wrap_nonce: &[2; 24],
            key_wrap_aad_hash: &[3; 32],
            content_nonce: &[4; 24],
            content_chunk_size: None,
            original_size: 0,
            encrypted_size: encrypted_content.len() as u64,
            encrypted_at,
            original_name: relative_path.rsplit('/').next(),
            platform_metadata: None,
            sparse_metadata: None,
        };
        hybridcipher_client::file::write_encrypted_file(path, &header, &encrypted_content).unwrap();
    }

    fn versioned_test_entry(
        root_id: Uuid,
        relative_path: &str,
        file_id: &str,
        nonce_byte: u8,
    ) -> ProviderEntry {
        let modified_at = Utc::now();
        let metadata = EncryptedFileMetadata {
            file_id: file_id.to_string(),
            file_path: relative_path.to_string(),
            header_version: Some(2),
            group_id: Some(root_id),
            epoch_id: 42,
            wrapped_file_key: None,
            key_wrap_nonce: None,
            key_wrap_aad_hash: None,
            content_nonce: Some(vec![nonce_byte; 12]),
            content_chunk_size: Some(4 * 1024 * 1024),
            content_size: 12,
            encrypted_size: 80,
            created_at: modified_at,
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: Vec::new(),
        };
        ProviderEntry::cache_file(
            root_id,
            relative_path,
            format!("/encrypted/{relative_path}.encrypted"),
            12,
            80,
            modified_at,
            Some(metadata),
        )
    }

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
    fn content_version_changes_when_authenticated_metadata_changes() {
        let root_id = Uuid::new_v4();
        let modified_at = Utc::now();
        let mut metadata = EncryptedFileMetadata {
            file_id: "stable-file-id".to_string(),
            file_path: "docs/report.txt".to_string(),
            header_version: Some(2),
            group_id: Some(root_id),
            epoch_id: 42,
            wrapped_file_key: None,
            key_wrap_nonce: None,
            key_wrap_aad_hash: None,
            content_nonce: Some(vec![1; 12]),
            content_chunk_size: Some(4 * 1024 * 1024),
            content_size: 12,
            encrypted_size: 80,
            created_at: modified_at,
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: Vec::new(),
        };

        let first = ProviderContentVersion::from_metadata(&metadata);
        metadata.content_nonce = Some(vec![2; 12]);
        let second = ProviderContentVersion::from_metadata(&metadata);

        assert_ne!(first, second);
    }

    #[test]
    fn content_version_ignores_current_path_for_rename_stability() {
        let root_id = Uuid::new_v4();
        let modified_at = Utc::now();
        let mut metadata = EncryptedFileMetadata {
            file_id: "stable-file-id".to_string(),
            file_path: "docs/report.txt".to_string(),
            header_version: Some(2),
            group_id: Some(root_id),
            epoch_id: 42,
            wrapped_file_key: None,
            key_wrap_nonce: None,
            key_wrap_aad_hash: None,
            content_nonce: Some(vec![1; 12]),
            content_chunk_size: Some(4 * 1024 * 1024),
            content_size: 12,
            encrypted_size: 80,
            created_at: modified_at,
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: Vec::new(),
        };

        let before = ProviderContentVersion::from_metadata(&metadata);
        metadata.file_path = "archive/report.txt".to_string();
        let after = ProviderContentVersion::from_metadata(&metadata);

        assert_eq!(before, after);
    }

    #[test]
    fn expected_version_rejects_changed_remote_content() {
        let expected = ProviderContentVersion::from_components(
            "file-1",
            None,
            1,
            Some(2),
            10,
            80,
            Some(&[1; 12]),
            None,
        );
        let actual = ProviderContentVersion::from_components(
            "file-1",
            None,
            1,
            Some(2),
            11,
            81,
            Some(&[2; 12]),
            None,
        );

        let error = validate_expected_content_version(
            "docs/report.txt",
            &ExpectedProviderVersion::Exact(expected.clone()),
            Some(&actual),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProviderCoreError::ContentConflict {
                expected: Some(found_expected),
                actual: Some(found_actual),
                ..
            } if found_expected == expected && found_actual == actual
        ));
    }

    #[test]
    fn expected_absent_rejects_existing_remote_content() {
        let actual = ProviderContentVersion::from_components(
            "file-1",
            None,
            1,
            Some(2),
            10,
            80,
            Some(&[1; 12]),
            None,
        );

        assert!(validate_expected_content_version(
            "docs/new.txt",
            &ExpectedProviderVersion::Absent,
            Some(&actual),
        )
        .is_err());
        assert!(validate_expected_content_version(
            "docs/new.txt",
            &ExpectedProviderVersion::Absent,
            None,
        )
        .is_ok());
    }

    #[test]
    fn checked_delete_rejects_moved_source_and_replacement_at_stale_path() {
        let root_id = Uuid::new_v4();
        let moved_source = versioned_test_entry(root_id, "archive/report.txt", "file-x", 1);
        let replacement = versioned_test_entry(root_id, "docs/report.txt", "file-y", 2);
        let stale_identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            "docs/report.txt",
            Some("file-x".to_string()),
            Some(42),
        );

        let error =
            resolve_checked_delete_entry(&[moved_source, replacement.clone()], &stale_identity)
                .unwrap_err();

        assert!(matches!(
            error,
            ProviderCoreError::ContentConflict {
                path,
                actual: Some(actual),
                ..
            } if path == "docs/report.txt" && actual == replacement.content_version().unwrap()
        ));
    }

    #[test]
    fn checked_writeback_rejects_identity_not_bound_to_target_object() {
        let root_id = Uuid::new_v4();
        let moved_source = versioned_test_entry(root_id, "archive/report.txt", "file-x", 1);
        let replacement = versioned_test_entry(root_id, "docs/report.txt", "file-y", 2);
        let stale_identity = FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            "docs/report.txt",
            Some("file-x".to_string()),
            Some(42),
        );

        let error = resolve_checked_writeback_entry(
            &[moved_source, replacement.clone()],
            root_id,
            "docs/report.txt",
            &stale_identity,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ProviderCoreError::ContentConflict {
                path,
                actual: Some(actual),
                ..
            } if path == "docs/report.txt" && actual == replacement.content_version().unwrap()
        ));
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

    #[tokio::test]
    async fn inventory_uses_directory_sidecar_identity_across_physical_rename() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let docs = temp.path().join("docs");
        fs::create_dir_all(&docs).unwrap();
        write_directory_sidecar(
            &docs.join(DIRECTORY_METADATA_FILE_NAME),
            "docs",
            "stable-directory-id",
        );

        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));
        let before = bridge.inventory(root_id, temp.path()).await.unwrap();
        let before = before
            .iter()
            .find(|entry| entry.kind == ProviderEntryKind::Directory)
            .unwrap();
        let before_version = before.content_version().unwrap();
        assert_eq!(
            before.identity.file_id.as_deref(),
            Some("stable-directory-id")
        );

        fs::rename(&docs, temp.path().join("archive")).unwrap();
        let after = bridge.inventory(root_id, temp.path()).await.unwrap();
        let after = after
            .iter()
            .find(|entry| entry.kind == ProviderEntryKind::Directory)
            .unwrap();

        assert_eq!(after.relative_path, "archive");
        assert_eq!(
            after.identity.file_id.as_deref(),
            Some("stable-directory-id")
        );
        assert_eq!(after.content_version(), Some(before_version));
    }

    #[tokio::test]
    async fn inventory_fails_closed_for_malformed_directory_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        fs::create_dir_all(&docs).unwrap();
        fs::write(
            docs.join(DIRECTORY_METADATA_FILE_NAME),
            b"not encrypted metadata",
        )
        .unwrap();

        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));
        let error = bridge
            .inventory(Uuid::new_v4(), temp.path())
            .await
            .unwrap_err();
        assert!(matches!(error, ProviderCoreError::MetadataParse { .. }));
    }

    #[tokio::test]
    async fn create_directory_sidecars_are_complete_and_retry_preserves_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let crypto = Arc::new(DirectoryTestCrypto::new(false));
        let bridge = LocalProviderBridge::new(crypto.clone());
        bridge
            .create_directory(root_id, temp.path(), "docs")
            .await
            .unwrap();
        crypto.fail_coverage_once.store(true, Ordering::SeqCst);

        let first = bridge
            .create_directory(root_id, temp.path(), "docs/nested")
            .await;
        assert!(first.is_err());
        let published = bridge.inventory(root_id, temp.path()).await.unwrap();
        let published_nested = published
            .iter()
            .find(|entry| entry.relative_path == "docs/nested")
            .unwrap();
        let published_id = published_nested.identity.file_id.clone().unwrap();

        let retried = bridge
            .create_directory(root_id, temp.path(), "docs/nested")
            .await
            .unwrap();
        assert_eq!(
            retried.identity.file_id.as_deref(),
            Some(published_id.as_str())
        );
        assert!(temp
            .path()
            .join("docs")
            .join(DIRECTORY_METADATA_FILE_NAME)
            .exists());

        let implicit = bridge
            .create_directory(root_id, temp.path(), "a/b/c")
            .await
            .unwrap();
        assert!(implicit.identity.file_id.is_some());
        for relative_path in ["a", "a/b", "a/b/c"] {
            assert!(temp
                .path()
                .join(relative_path)
                .join(DIRECTORY_METADATA_FILE_NAME)
                .exists());
        }
        assert!(temp
            .path()
            .join("docs")
            .join("nested")
            .join(DIRECTORY_METADATA_FILE_NAME)
            .exists());
    }

    #[tokio::test]
    async fn create_directory_fails_closed_for_existing_malformed_sidecar() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        fs::create_dir_all(&docs).unwrap();
        fs::write(
            docs.join(DIRECTORY_METADATA_FILE_NAME),
            b"not encrypted metadata",
        )
        .unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));

        let error = bridge
            .create_directory(Uuid::new_v4(), temp.path(), "docs")
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderCoreError::MetadataParse { .. }));
    }

    #[tokio::test]
    async fn bridge_inventory_backfills_legacy_directories_before_returning_them() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        let nested = docs.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let root_id = Uuid::new_v4();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));

        let entries = bridge.inventory(root_id, temp.path()).await.unwrap();

        for relative_path in ["docs", "docs/nested"] {
            let entry = entries
                .iter()
                .find(|entry| entry.relative_path == relative_path)
                .unwrap();
            assert!(entry.identity.file_id.is_some());
            assert!(entry.content_version().is_some());
            assert!(entry
                .encrypted_path
                .join(DIRECTORY_METADATA_FILE_NAME)
                .exists());
        }
    }

    #[tokio::test]
    async fn bridge_inventory_skips_excluded_directory_tree() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        let obsidian = temp.path().join(".obsidian").join("plugins");
        fs::create_dir_all(&docs).unwrap();
        fs::create_dir_all(&obsidian).unwrap();
        fs::write(obsidian.join("workspace.json"), b"local application state").unwrap();
        fs::write(
            obsidian.join("invalid.encrypted"),
            b"excluded ciphertext-like file",
        )
        .unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::excluding_obsidian()));

        let entries = bridge.inventory(Uuid::new_v4(), temp.path()).await.unwrap();

        assert!(bridge.is_path_excluded(temp.path(), Path::new(".obsidian/plugins/workspace.json")));
        assert!(entries.iter().any(|entry| entry.relative_path == "docs"));
        assert!(!entries
            .iter()
            .any(|entry| entry.relative_path.starts_with(".obsidian")));
        assert!(!temp
            .path()
            .join(".obsidian")
            .join(DIRECTORY_METADATA_FILE_NAME)
            .exists());
    }

    #[tokio::test]
    async fn bridge_inventory_treats_encryptor_path_exclusion_as_filtered_subtree() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        let obsidian = temp.path().join(".obsidian").join("plugins");
        fs::create_dir_all(&docs).unwrap();
        fs::create_dir_all(&obsidian).unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(
            DirectoryTestCrypto::encryptor_only_excluding_obsidian(),
        ));

        let entries = bridge.inventory(Uuid::new_v4(), temp.path()).await.unwrap();

        assert!(entries.iter().any(|entry| entry.relative_path == "docs"));
        assert!(!entries
            .iter()
            .any(|entry| entry.relative_path.starts_with(".obsidian")));
        assert!(!temp
            .path()
            .join(".obsidian")
            .join(DIRECTORY_METADATA_FILE_NAME)
            .exists());
    }

    #[tokio::test]
    async fn concurrent_directory_creation_returns_the_single_published_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let bridge = Arc::new(LocalProviderBridge::new(Arc::new(
            DirectoryTestCrypto::concurrent(),
        )));

        let first = bridge.create_directory(root_id, temp.path(), "docs");
        let second = bridge.create_directory(root_id, temp.path(), "docs");
        let (first, second) = tokio::join!(first, second);
        let first = first.unwrap();
        let second = second.unwrap();
        let inventory = bridge.inventory(root_id, temp.path()).await.unwrap();
        let published = inventory
            .iter()
            .find(|entry| entry.relative_path == "docs")
            .unwrap();

        assert_eq!(first.identity.file_id, second.identity.file_id);
        assert_eq!(first.identity.file_id, published.identity.file_id);
    }

    #[tokio::test]
    async fn inventory_rejects_tampered_authenticated_directory_identity() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        fs::create_dir_all(&docs).unwrap();
        let sidecar = docs.join(DIRECTORY_METADATA_FILE_NAME);
        write_directory_sidecar(&sidecar, "docs", "stable-directory-id");
        let mut tampered = fs::read(&sidecar).unwrap();
        let original = b"stable-directory-id";
        let replacement = b"attack-directory-id";
        let offset = tampered
            .windows(original.len())
            .position(|window| window == original)
            .unwrap();
        tampered[offset..offset + original.len()].copy_from_slice(replacement);
        fs::write(&sidecar, tampered).unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));

        let error = bridge
            .inventory(Uuid::new_v4(), temp.path())
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderCoreError::Crypto(_)));
    }

    #[tokio::test]
    async fn inventory_rejects_duplicate_authenticated_directory_identity() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        let archive = temp.path().join("archive");
        fs::create_dir_all(&docs).unwrap();
        fs::create_dir_all(&archive).unwrap();
        let source = docs.join(DIRECTORY_METADATA_FILE_NAME);
        write_directory_sidecar(&source, "docs", "stable-directory-id");
        fs::copy(&source, archive.join(DIRECTORY_METADATA_FILE_NAME)).unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));

        let error = bridge
            .inventory(Uuid::new_v4(), temp.path())
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderCoreError::InvalidIdentity(_)));
    }

    #[tokio::test]
    async fn inventory_rejects_file_directory_identity_collision() {
        let temp = tempfile::tempdir().unwrap();
        let docs = temp.path().join("docs");
        fs::create_dir_all(&docs).unwrap();
        let sidecar = docs.join(DIRECTORY_METADATA_FILE_NAME);
        write_directory_sidecar(&sidecar, "docs", "shared-object-id");
        fs::copy(&sidecar, temp.path().join("shared.encrypted")).unwrap();
        let bridge = LocalProviderBridge::new(Arc::new(DirectoryTestCrypto::new(false)));

        let error = bridge
            .inventory(Uuid::new_v4(), temp.path())
            .await
            .unwrap_err();

        assert!(matches!(error, ProviderCoreError::InvalidIdentity(_)));
    }
}
