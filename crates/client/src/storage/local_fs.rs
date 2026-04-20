use async_trait::async_trait;
use hybridcipher_crypto::account_protection::{
    decrypt_with_ad, encrypt_with_ad, ProtectedData, PROTECTED_DATA_MAGIC,
};
use serde::Deserialize;
use serde_cbor;
use serde_json;
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt,
    sync::{mpsc, oneshot},
};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::mock::MockStorage;
use super::{
    CoverageLogData, CoverageLogDeltaData, EpochStateData, FileMetadataData, Storage, StorageError,
    StorageStats, StorageTransaction,
};
use crate::coverage::FileIndexEntry;

/// Simple on-disk storage that wraps `MockStorage` but persist the key‐value
/// configuration entries (used for client state) to the local filesystem so that
/// they survive across separate CLI invocations.
///
/// Only the `store_config` and `load_config` methods are persisted. All other
/// operations are delegated to the in-memory `MockStorage` that already
/// fulfils the `Storage` contract and is sufficient for local-only workflows
/// (encryption / decryption on a single machine).
#[derive(Clone)]
pub struct LocalFsStorage {
    inner: Arc<MockStorage>,
    base_path: PathBuf,
    account_key: Arc<RwLock<Option<Zeroizing<[u8; 32]>>>>,
    file_index_sender: mpsc::Sender<FileIndexOp>,
}

const GLOBAL_CONFIG_KEYS: &[&str] = &["coverage_root_registry"];
const FILE_INDEX_QUEUE_CAPACITY: usize = 5120;

enum FileIndexOp {
    StoreEntry {
        entry: FileIndexEntry,
        response: oneshot::Sender<Result<(), StorageError>>,
    },
    StoreEntries {
        entries: Vec<FileIndexEntry>,
        response: oneshot::Sender<Result<(), StorageError>>,
    },
    ReplaceRoot {
        root_id: Uuid,
        entries: Vec<FileIndexEntry>,
        response: oneshot::Sender<Result<(), StorageError>>,
    },
    LoadByUuid {
        file_uuid: Uuid,
        response: oneshot::Sender<Result<Option<FileIndexEntry>, StorageError>>,
    },
    LoadByRootPath {
        root_id: Uuid,
        relative_path: String,
        response: oneshot::Sender<Result<Option<FileIndexEntry>, StorageError>>,
    },
    ListByRoot {
        root_id: Uuid,
        response: oneshot::Sender<Result<Vec<FileIndexEntry>, StorageError>>,
    },
    RemoveByUuid {
        file_uuid: Uuid,
        response: oneshot::Sender<Result<(), StorageError>>,
    },
}

impl LocalFsStorage {
    /// Create a new disk backed storage. It will create the directory if it
    /// does not exist.
    pub fn new<P: AsRef<Path>>(base_path: P) -> Self {
        let base_path = base_path.as_ref().to_path_buf();
        // ensure directory exists synchronously – fine for CLI start-up
        std::fs::create_dir_all(&base_path).ok();
        let file_index_path = base_path.join("file_index_db");
        let db = sled::Config::new()
            .path(&file_index_path)
            .open()
            .unwrap_or_else(|err| {
                log::warn!(
                    "Failed to open file index database at {}: {}. Falling back to temporary store.",
                    file_index_path.display(),
                    err
                );
                sled::Config::new()
                    .temporary(true)
                    .open()
                    .expect("temporary sled database should open")
            });
        let file_index_entries = db
            .open_tree("file_index_entries")
            .expect("file index entries tree");
        let file_index_by_uuid = db
            .open_tree("file_index_by_uuid")
            .expect("file index uuid tree");
        let file_index_by_path = db
            .open_tree("file_index_by_path")
            .expect("file index path tree");
        let file_index_sender = Self::spawn_file_index_worker(
            db.clone(),
            file_index_entries.clone(),
            file_index_by_uuid.clone(),
            file_index_by_path.clone(),
        );
        Self {
            inner: Arc::new(MockStorage::new()),
            base_path,
            account_key: Arc::new(RwLock::new(None)),
            file_index_sender,
        }
    }

    /// Helper to create storage rooted in a specific per-user directory
    pub fn new_for_user(base_path: &Path, user_id: &str) -> Self {
        let user_path = base_path.join("users").join(user_id);
        Self::new(&user_path)
    }

    fn config_file(&self, key: &str) -> PathBuf {
        if Self::is_global_config_key(key) {
            let shared_dir = self
                .base_path
                .parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| self.base_path.clone());
            return shared_dir.join(format!("{key}.json"));
        }
        // store each key in a separate file to avoid concurrent write issues
        self.base_path.join(format!("{key}.json"))
    }

    fn is_global_config_key(key: &str) -> bool {
        GLOBAL_CONFIG_KEYS.iter().any(|candidate| candidate == &key)
    }

    fn should_encrypt_config(key: &str) -> bool {
        !Self::is_global_config_key(key)
    }

    fn encryption_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        self.account_key.read().ok().and_then(|guard| guard.clone())
    }

    fn set_encryption_key_internal(&self, key: [u8; 32]) {
        if let Ok(mut guard) = self.account_key.write() {
            *guard = Some(Zeroizing::new(key));
        }
    }

    fn clear_encryption_key_internal(&self) {
        if let Ok(mut guard) = self.account_key.write() {
            *guard = None;
        }
    }

    fn coverage_group_dir(&self, group_id: Uuid) -> PathBuf {
        self.base_path
            .join("logs")
            .join("coverage_logs")
            .join(group_id.to_string())
    }

    fn coverage_log_file(&self, group_id: Uuid) -> PathBuf {
        self.coverage_group_dir(group_id).join("coverage_log.json")
    }

    fn coverage_log_journal_file(&self, group_id: Uuid) -> PathBuf {
        self.coverage_group_dir(group_id)
            .join("coverage_log.journal")
    }

    fn file_metadata_dir(&self) -> PathBuf {
        self.base_path.join("file_metadata")
    }

    fn file_metadata_file(&self, file_path: &str) -> PathBuf {
        let digest = Sha256::digest(file_path.as_bytes());
        let hex = hex::encode(digest);
        let (prefix_a, rest) = hex.split_at(2);
        let (prefix_b, tail) = rest.split_at(2);
        self.file_metadata_dir()
            .join(prefix_a)
            .join(prefix_b)
            .join(format!("{tail}.json"))
    }

    fn file_index_entry_key(root_id: Uuid, file_uuid: Uuid) -> Vec<u8> {
        let mut key = Vec::with_capacity(32);
        key.extend_from_slice(root_id.as_bytes());
        key.extend_from_slice(file_uuid.as_bytes());
        key
    }

    fn normalize_file_index_path(path: &str) -> String {
        const SUFFIX: &str = ".encrypted";
        if path.len() <= SUFFIX.len() {
            return path.to_string();
        }
        let (body, suffix) = path.split_at(path.len() - SUFFIX.len());
        if suffix.eq_ignore_ascii_case(SUFFIX) {
            body.to_string()
        } else {
            path.to_string()
        }
    }

    fn file_index_path_key(root_id: Uuid, relative_path: &str) -> Vec<u8> {
        let normalized = Self::normalize_file_index_path(relative_path);
        let mut key = Vec::with_capacity(16 + 1 + normalized.len());
        key.extend_from_slice(root_id.as_bytes());
        key.push(0);
        key.extend_from_slice(normalized.as_bytes());
        key
    }

    fn uuid_key(uuid: Uuid) -> Vec<u8> {
        uuid.as_bytes().to_vec()
    }

    fn spawn_file_index_worker(
        db: sled::Db,
        entries_tree: sled::Tree,
        by_uuid_tree: sled::Tree,
        by_path_tree: sled::Tree,
    ) -> mpsc::Sender<FileIndexOp> {
        let (tx, mut rx) = mpsc::channel(FILE_INDEX_QUEUE_CAPACITY);
        std::thread::Builder::new()
            .name("file_index_worker".to_string())
            .spawn(move || {
                while let Some(op) = rx.blocking_recv() {
                    match op {
                        FileIndexOp::StoreEntry { entry, response } => {
                            let result = Self::store_file_index_entries_blocking(
                                &entries_tree,
                                &by_uuid_tree,
                                &by_path_tree,
                                &[entry],
                            );
                            let _ = response.send(result);
                        }
                        FileIndexOp::StoreEntries { entries, response } => {
                            let result = Self::store_file_index_entries_blocking(
                                &entries_tree,
                                &by_uuid_tree,
                                &by_path_tree,
                                &entries,
                            );
                            if result.is_ok() {
                                if let Err(e) = db.flush() {
                                    log::warn!(
                                        "Failed to flush file index after StoreEntries: {}",
                                        e
                                    );
                                }
                            }
                            let _ = response.send(result);
                        }
                        FileIndexOp::ReplaceRoot {
                            root_id,
                            entries,
                            response,
                        } => {
                            let result = Self::replace_file_index_entries_blocking(
                                &entries_tree,
                                &by_uuid_tree,
                                &by_path_tree,
                                root_id,
                                &entries,
                            );
                            if result.is_ok() {
                                if let Err(e) = db.flush() {
                                    log::warn!(
                                        "Failed to flush file index after ReplaceRoot: {}",
                                        e
                                    );
                                }
                            }
                            let _ = response.send(result);
                        }
                        FileIndexOp::LoadByUuid {
                            file_uuid,
                            response,
                        } => {
                            let result = Self::load_file_index_entry_blocking(
                                &entries_tree,
                                &by_uuid_tree,
                                file_uuid,
                            );
                            let _ = response.send(result);
                        }
                        FileIndexOp::LoadByRootPath {
                            root_id,
                            relative_path,
                            response,
                        } => {
                            let result = Self::load_file_index_entry_by_root_path_blocking(
                                &entries_tree,
                                &by_path_tree,
                                root_id,
                                &relative_path,
                            );
                            let _ = response.send(result);
                        }
                        FileIndexOp::ListByRoot { root_id, response } => {
                            let result = Self::list_file_index_entries_by_root_blocking(
                                &entries_tree,
                                root_id,
                            );
                            let _ = response.send(result);
                        }
                        FileIndexOp::RemoveByUuid {
                            file_uuid,
                            response,
                        } => {
                            let result = Self::remove_file_index_entry_blocking(
                                &entries_tree,
                                &by_uuid_tree,
                                &by_path_tree,
                                file_uuid,
                            );
                            let _ = response.send(result);
                        }
                    }
                }
            })
            .expect("file index worker thread");
        tx
    }

    async fn dispatch_file_index_op<T>(
        &self,
        op: FileIndexOp,
        rx: oneshot::Receiver<Result<T, StorageError>>,
    ) -> Result<T, StorageError> {
        self.file_index_sender
            .send(op)
            .await
            .map_err(|_| StorageError::Transaction("file index worker unavailable".to_string()))?;
        rx.await.map_err(|_| {
            StorageError::Transaction("file index worker dropped response".to_string())
        })?
    }

    fn store_file_index_entries_blocking(
        entries_tree: &sled::Tree,
        by_uuid_tree: &sled::Tree,
        by_path_tree: &sled::Tree,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let mut batch_entries = sled::Batch::default();
        let mut batch_uuid = sled::Batch::default();
        let mut batch_paths = sled::Batch::default();
        for entry in entries {
            let key = Self::file_index_entry_key(entry.root_id, entry.file_uuid);
            let value = serde_cbor::to_vec(entry).map_err(|err| {
                StorageError::SerializationError(format!(
                    "failed to serialize file index entry: {}",
                    err
                ))
            })?;
            batch_entries.insert(key, value.clone());
            batch_uuid.insert(Self::uuid_key(entry.file_uuid), entry.root_id.as_bytes());
            let path_key = Self::file_index_path_key(entry.root_id, &entry.relative_path);
            batch_paths.insert(path_key, value);
        }
        entries_tree
            .apply_batch(batch_entries)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        by_uuid_tree
            .apply_batch(batch_uuid)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        by_path_tree
            .apply_batch(batch_paths)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        Ok(())
    }

    fn replace_file_index_entries_blocking(
        entries_tree: &sled::Tree,
        by_uuid_tree: &sled::Tree,
        by_path_tree: &sled::Tree,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let root_bytes = root_id.as_bytes();
        let mut batch_entries = sled::Batch::default();
        let mut batch_uuid = sled::Batch::default();
        let mut batch_paths = sled::Batch::default();
        for item in entries_tree.scan_prefix(root_bytes) {
            let (key, _) = item.map_err(|err| StorageError::Transaction(err.to_string()))?;
            if key.len() == 32 {
                batch_entries.remove(key.clone());
                batch_uuid.remove(&key[16..]);
            }
        }
        for item in by_path_tree.scan_prefix(root_bytes) {
            let (key, _) = item.map_err(|err| StorageError::Transaction(err.to_string()))?;
            batch_paths.remove(key);
        }
        for entry in entries {
            let key = Self::file_index_entry_key(entry.root_id, entry.file_uuid);
            let value = serde_cbor::to_vec(entry).map_err(|err| {
                StorageError::SerializationError(format!(
                    "failed to serialize file index entry: {}",
                    err
                ))
            })?;
            batch_entries.insert(key, value.clone());
            batch_uuid.insert(Self::uuid_key(entry.file_uuid), entry.root_id.as_bytes());
            let path_key = Self::file_index_path_key(entry.root_id, &entry.relative_path);
            batch_paths.insert(path_key, value);
        }
        entries_tree
            .apply_batch(batch_entries)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        by_uuid_tree
            .apply_batch(batch_uuid)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        by_path_tree
            .apply_batch(batch_paths)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        Ok(())
    }

    fn load_file_index_entry_blocking(
        entries_tree: &sled::Tree,
        by_uuid_tree: &sled::Tree,
        file_uuid: Uuid,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let root_bytes = match by_uuid_tree
            .get(Self::uuid_key(file_uuid))
            .map_err(|err| StorageError::Transaction(err.to_string()))?
        {
            Some(bytes) => bytes,
            None => return Ok(None),
        };
        let root_id = Uuid::from_slice(&root_bytes).map_err(|err| {
            StorageError::InvalidData(format!("invalid root uuid bytes: {}", err))
        })?;
        let key = Self::file_index_entry_key(root_id, file_uuid);
        let value = match entries_tree
            .get(key)
            .map_err(|err| StorageError::Transaction(err.to_string()))?
        {
            Some(value) => value,
            None => return Ok(None),
        };
        let entry = serde_cbor::from_slice(&value).map_err(|err| {
            StorageError::DeserializationError(format!("failed to parse file index entry: {}", err))
        })?;
        Ok(Some(entry))
    }

    fn load_file_index_entry_by_root_path_blocking(
        entries_tree: &sled::Tree,
        by_path_tree: &sled::Tree,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let path_key = Self::file_index_path_key(root_id, relative_path);
        if let Some(value) = by_path_tree
            .get(&path_key)
            .map_err(|err| StorageError::Transaction(err.to_string()))?
        {
            let entry = serde_cbor::from_slice(&value).map_err(|err| {
                StorageError::DeserializationError(format!(
                    "failed to parse file index entry: {}",
                    err
                ))
            })?;
            return Ok(Some(entry));
        }

        let target_path = Self::normalize_file_index_path(relative_path);
        let mut batch_paths = sled::Batch::default();
        let mut has_batch = false;
        let mut matched: Option<FileIndexEntry> = None;

        for item in entries_tree.scan_prefix(root_id.as_bytes()) {
            let (_, value) = item.map_err(|err| StorageError::Transaction(err.to_string()))?;
            let entry: FileIndexEntry = serde_cbor::from_slice(&value).map_err(|err| {
                StorageError::DeserializationError(format!(
                    "failed to parse file index entry: {}",
                    err
                ))
            })?;
            let path_key = Self::file_index_path_key(entry.root_id, &entry.relative_path);
            batch_paths.insert(path_key, value.clone());
            has_batch = true;
            if Self::normalize_file_index_path(&entry.relative_path) == target_path {
                matched = Some(entry);
            }
        }

        if has_batch {
            by_path_tree
                .apply_batch(batch_paths)
                .map_err(|err| StorageError::Transaction(err.to_string()))?;
        }

        Ok(matched)
    }

    fn list_file_index_entries_by_root_blocking(
        entries_tree: &sled::Tree,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, StorageError> {
        let mut entries = Vec::new();
        for item in entries_tree.scan_prefix(root_id.as_bytes()) {
            let (_, value) = item.map_err(|err| StorageError::Transaction(err.to_string()))?;
            let entry = serde_cbor::from_slice(&value).map_err(|err| {
                StorageError::DeserializationError(format!(
                    "failed to parse file index entry: {}",
                    err
                ))
            })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    fn remove_file_index_entry_blocking(
        entries_tree: &sled::Tree,
        by_uuid_tree: &sled::Tree,
        by_path_tree: &sled::Tree,
        file_uuid: Uuid,
    ) -> Result<(), StorageError> {
        let root_bytes = match by_uuid_tree
            .get(Self::uuid_key(file_uuid))
            .map_err(|err| StorageError::Transaction(err.to_string()))?
        {
            Some(bytes) => bytes,
            None => return Ok(()),
        };
        let root_id = Uuid::from_slice(&root_bytes).map_err(|err| {
            StorageError::InvalidData(format!("invalid root uuid bytes: {}", err))
        })?;
        let key = Self::file_index_entry_key(root_id, file_uuid);
        if let Some(value) = entries_tree
            .get(&key)
            .map_err(|err| StorageError::Transaction(err.to_string()))?
        {
            if let Ok(entry) = serde_cbor::from_slice::<FileIndexEntry>(&value) {
                let path_key = Self::file_index_path_key(root_id, &entry.relative_path);
                let _ = by_path_tree
                    .remove(path_key)
                    .map_err(|err| StorageError::Transaction(err.to_string()))?;
            }
        }
        entries_tree
            .remove(key)
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        by_uuid_tree
            .remove(Self::uuid_key(file_uuid))
            .map_err(|err| StorageError::Transaction(err.to_string()))?;
        Ok(())
    }

    fn legacy_file_metadata_file(&self, file_path: &str) -> PathBuf {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        file_path.hash(&mut hasher);
        let hash = hasher.finish();

        self.file_metadata_dir().join(format!("{hash:016x}.json"))
    }

    async fn persist_metadata_payload(
        &self,
        target: &Path,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError> {
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).await?;
        }

        let payload = serde_json::to_vec_pretty(metadata).map_err(|err| {
            StorageError::Serialization(format!("failed to serialize file metadata: {}", err))
        })?;

        // Write atomically via a temp file to avoid partial/corrupted snapshots when concurrent
        // writers race to persist file metadata during bulk operations.
        let temp_path = target.with_extension("json.tmp");
        fs::write(&temp_path, &payload).await?;
        fs::rename(&temp_path, target).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(md) = std::fs::metadata(target) {
                let mut permissions = md.permissions();
                permissions.set_mode(0o600);
                let _ = std::fs::set_permissions(target, permissions);
            }
        }

        Ok(())
    }

    async fn read_metadata_payload(
        &self,
        path: &Path,
    ) -> Result<Option<FileMetadataData>, StorageError> {
        let bytes = match fs::read(path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(StorageError::Io(err)),
        };

        match serde_json::from_slice::<FileMetadataData>(&bytes) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(err) => {
                // Corrupted metadata file detected - log and delete to allow regeneration
                log::warn!(
                    "Corrupted metadata file detected at {}: {}. Deleting to allow regeneration from encrypted file header.",
                    path.display(),
                    err
                );

                // Attempt to delete the corrupted file
                if let Err(delete_err) = fs::remove_file(path).await {
                    log::error!(
                        "Failed to delete corrupted metadata file {}: {}",
                        path.display(),
                        delete_err
                    );
                }

                // Return None so the system treats this as "no metadata found"
                // and regenerates it from the encrypted file header during the next scan
                Ok(None)
            }
        }
    }

    async fn write_coverage_log_file(
        &self,
        group_id: Uuid,
        log: &CoverageLogData,
    ) -> Result<(), StorageError> {
        let file_path = self.coverage_log_file(group_id);

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let payload = serde_json::to_vec_pretty(log).map_err(|err| {
            StorageError::Serialization(format!("failed to serialize coverage log: {}", err))
        })?;

        // Write atomically via a temp file to avoid partial/corrupted snapshots when concurrent
        // writers race to persist the coverage log.
        let temp_path = file_path.with_extension("json.tmp");
        fs::write(&temp_path, &payload).await?;
        fs::rename(&temp_path, &file_path).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Ok(metadata) = std::fs::metadata(&file_path) {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                let _ = std::fs::set_permissions(&file_path, permissions);
            }
        }

        Ok(())
    }

    async fn append_coverage_log_journal(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError> {
        let file_path = self.coverage_log_journal_file(group_id);
        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let mut serialized = serde_json::to_vec(delta).map_err(|err| {
            StorageError::Serialization(format!("failed to serialize coverage log delta: {}", err))
        })?;
        serialized.push(b'\n');

        let mut handle = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)
            .await?;
        handle.write_all(&serialized).await?;
        handle.flush().await?;
        Ok(())
    }

    async fn load_coverage_log_journal_since(
        &self,
        group_id: Uuid,
        since_sequence: u64,
    ) -> Result<Vec<CoverageLogDeltaData>, StorageError> {
        let file_path = self.coverage_log_journal_file(group_id);
        let bytes = match fs::read(&file_path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(StorageError::Io(err)),
        };

        let mut deltas = Vec::new();
        for line in bytes.split(|b| *b == b'\n') {
            if line.is_empty() {
                continue;
            }
            let delta: CoverageLogDeltaData = serde_json::from_slice(line).map_err(|err| {
                StorageError::DeserializationError(format!(
                    "failed to deserialize coverage log delta: {}",
                    err
                ))
            })?;
            if delta.sequence > since_sequence {
                deltas.push(delta);
            }
        }

        Ok(deltas)
    }

    async fn rewrite_coverage_log_journal(
        &self,
        group_id: Uuid,
        entries: &[CoverageLogDeltaData],
    ) -> Result<(), StorageError> {
        let file_path = self.coverage_log_journal_file(group_id);
        if entries.is_empty() {
            match fs::remove_file(&file_path).await {
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(StorageError::Io(err)),
            }
            return Ok(());
        }

        let mut payload = Vec::new();
        for entry in entries {
            let mut line = serde_json::to_vec(entry).map_err(|err| {
                StorageError::Serialization(format!(
                    "failed to serialize coverage log delta: {}",
                    err
                ))
            })?;
            payload.append(&mut line);
            payload.push(b'\n');
        }

        let temp_path =
            file_path.with_file_name(format!("coverage_log.journal.{}.tmp", Uuid::new_v4()));
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent).await?;
        }
        fs::write(&temp_path, &payload).await?;
        fs::rename(&temp_path, &file_path).await?;
        Ok(())
    }

    async fn compact_coverage_log_journal(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), StorageError> {
        let remaining = self
            .load_coverage_log_journal_since(group_id, up_to_sequence)
            .await?;
        self.rewrite_coverage_log_journal(group_id, &remaining)
            .await
    }

    async fn read_coverage_log_file(
        &self,
        group_id: Uuid,
    ) -> Result<Option<CoverageLogData>, StorageError> {
        let file_path = self.coverage_log_file(group_id);
        match fs::read(&file_path).await {
            Ok(bytes) => {
                // Try strict parse first; on trailing-data errors, salvage the first JSON value.
                let log: CoverageLogData = match serde_json::from_slice(&bytes) {
                    Ok(value) => value,
                    Err(primary_err) => {
                        let mut de = serde_json::Deserializer::from_slice(&bytes);
                        match CoverageLogData::deserialize(&mut de) {
                            Ok(value) => value,
                            Err(_) => {
                                return Err(StorageError::DeserializationError(format!(
                                    "failed to deserialize coverage log: {}",
                                    primary_err
                                )))
                            }
                        }
                    }
                };
                Ok(Some(log))
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    pub async fn list_config_keys_with_prefix(
        &self,
        prefix: &str,
    ) -> Result<Vec<String>, StorageError> {
        match fs::read_dir(&self.base_path).await {
            Ok(mut entries) => {
                let mut keys = Vec::new();
                while let Some(entry) = entries.next_entry().await.map_err(StorageError::Io)? {
                    let file_name = entry.file_name();
                    let name = match file_name.into_string() {
                        Ok(value) => value,
                        Err(_) => continue,
                    };

                    if !name.ends_with(".json") {
                        continue;
                    }

                    let key_name = &name[..name.len() - 5];
                    if key_name.starts_with(prefix) {
                        keys.push(key_name.to_string());
                    }
                }
                Ok(keys)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    fn aad_for_config(key: &str) -> Vec<u8> {
        format!("hybridcipher/localfs/{key}").into_bytes()
    }

    async fn write_config_file(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let file_path = self.config_file(key);

        if let Some(parent) = file_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let maybe_key = if Self::should_encrypt_config(key) {
            self.encryption_key()
        } else {
            None
        };

        let data = if let Some(key_bytes) = maybe_key {
            let mut key_array = [0u8; 32];
            key_array.copy_from_slice(key_bytes.as_ref());
            let aad = Self::aad_for_config(key);
            let protected = encrypt_with_ad(value.as_bytes(), key_array, &aad).map_err(|err| {
                StorageError::Encryption(format!("failed to encrypt configuration '{key}': {err}"))
            })?;
            serde_json::to_string_pretty(&protected).map_err(|err| {
                StorageError::Serialization(format!(
                    "failed to serialize encrypted configuration '{key}': {err}"
                ))
            })?
        } else {
            value.to_string()
        };

        let temp_path = file_path.with_file_name(format!(
            "{}.{}.tmp",
            file_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("config"),
            Uuid::new_v4()
        ));
        fs::write(&temp_path, data).await?;
        if let Err(err) = fs::rename(&temp_path, &file_path).await {
            if err.kind() == ErrorKind::AlreadyExists {
                let _ = fs::remove_file(&file_path).await;
                fs::rename(&temp_path, &file_path).await?;
            } else {
                return Err(StorageError::Io(err));
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            if let Ok(metadata) = std::fs::metadata(&file_path) {
                let mut permissions = metadata.permissions();
                permissions.set_mode(0o600);
                let _ = std::fs::set_permissions(&file_path, permissions);
            }
        }

        Ok(())
    }

    async fn load_and_optionally_decrypt_config(
        &self,
        key: &str,
        content: String,
    ) -> Result<(String, bool), StorageError> {
        if Self::is_global_config_key(key) {
            return Ok((content, false));
        }

        let maybe_key = self.encryption_key();

        if let Some(key_bytes) = maybe_key {
            // First attempt to parse as protected JSON; if it fails fall back to plaintext.
            match serde_json::from_str::<ProtectedData>(&content) {
                Ok(protected) if protected.magic == PROTECTED_DATA_MAGIC => {
                    let mut key_array = [0u8; 32];
                    key_array.copy_from_slice(key_bytes.as_ref());
                    let aad = Self::aad_for_config(key);
                    let decrypted =
                        decrypt_with_ad(&protected, key_array, &aad).map_err(|err| {
                            StorageError::Encryption(format!(
                                "failed to decrypt configuration '{key}': {err}"
                            ))
                        })?;
                    let value = String::from_utf8(decrypted).map_err(|err| {
                        StorageError::DeserializationError(format!(
                            "configuration '{key}' is not valid UTF-8: {err}"
                        ))
                    })?;
                    return Ok((value, true));
                }
                Ok(_) => {
                    // JSON but not protected format, treat as plaintext to preserve compatibility.
                    return Ok((content, false));
                }
                Err(_) => {
                    // Not JSON (legacy plaintext). We'll return plaintext and let caller migrate.
                }
            }
        }

        Ok((content, false))
    }

    /// Enable at-rest encryption for configuration blobs using the supplied symmetric key.
    pub fn enable_account_encryption(&self, key: [u8; 32]) {
        self.set_encryption_key_internal(key);
    }

    /// Disable encryption; primarily used during logout when sensitive key material is cleared.
    pub fn clear_account_encryption(&self) {
        self.clear_encryption_key_internal();
    }
}

impl fmt::Debug for LocalFsStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFsStorage")
            .field("base_path", &self.base_path)
            .finish()
    }
}

#[async_trait]
impl Storage for LocalFsStorage {
    async fn store_identity_key(
        &self,
        device_id: &str,
        identity_key: &[u8],
    ) -> Result<(), StorageError> {
        self.inner.store_identity_key(device_id, identity_key).await
    }

    async fn load_identity_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_identity_key(device_id).await
    }

    async fn store_epoch_state_data(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError> {
        self.inner.store_epoch_state_data(epoch_id, state).await
    }

    async fn load_epoch_state_data(
        &self,
        epoch_id: u64,
    ) -> Result<Option<EpochStateData>, StorageError> {
        self.inner.load_epoch_state_data(epoch_id).await
    }

    async fn store_epoch_state(
        &self,
        epoch_state: &crate::epoch::state::EpochState,
    ) -> Result<(), StorageError> {
        self.inner.store_epoch_state(epoch_state).await
    }

    async fn load_epoch_state(
        &self,
        epoch_id: u64,
    ) -> Result<crate::epoch::state::EpochState, StorageError> {
        self.inner.load_epoch_state(epoch_id).await
    }

    async fn list_epochs(&self) -> Result<Vec<u64>, StorageError> {
        self.inner.list_epochs().await
    }

    async fn get_current_epoch_id(&self) -> Result<u64, StorageError> {
        self.inner.get_current_epoch_id().await
    }

    async fn store_file_metadata_batch(
        &self,
        metadata_batch: &std::collections::HashMap<String, FileMetadataData>,
    ) -> Result<(), StorageError> {
        self.inner.store_file_metadata_batch(metadata_batch).await
    }

    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError> {
        self.inner.store_file(file_path, content).await
    }

    async fn get_file(&self, file_path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get_file(file_path).await
    }

    async fn get_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<crate::file::FileMetadata>, StorageError> {
        self.inner.get_file_metadata(file_path).await
    }

    async fn delete_file(&self, file_path: &str) -> Result<(), StorageError> {
        self.inner.delete_file(file_path).await?;
        let metadata_file = self.file_metadata_file(file_path);
        match fs::remove_file(&metadata_file).await {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => return Err(StorageError::Io(err)),
        }
        let legacy_file = self.legacy_file_metadata_file(file_path);
        if legacy_file != metadata_file {
            match fs::remove_file(&legacy_file).await {
                Ok(_) => {}
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(StorageError::Io(err)),
            }
        }
        Ok(())
    }

    /// Persist configuration values to `<base_path>/<key>.json` so that they are
    /// available the next time the CLI starts. Errors are mapped to
    /// `StorageError::Io`.
    async fn store_config(&self, key: &str, value: &str) -> Result<(), StorageError> {
        // first update in-memory copy so current process sees latest data
        self.inner.store_config(key, value).await?;
        self.write_config_file(key, value).await
    }

    async fn delete_config(&self, key: &str) -> Result<(), StorageError> {
        self.inner.delete_config(key).await?;
        let file_path = self.config_file(key);
        match fs::remove_file(&file_path).await {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    /// Load configuration from memory; if absent load from disk file and cache
    /// into memory so future reads are cheap.
    async fn load_config(&self, key: &str) -> Result<Option<String>, StorageError> {
        if let Some(val) = self.inner.load_config(key).await? {
            return Ok(Some(val));
        }

        let file_path = self.config_file(key);
        match fs::read(&file_path).await {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes).to_string();
                let (value, was_encrypted) =
                    self.load_and_optionally_decrypt_config(key, raw).await?;

                // Cache into memory for quick access
                self.inner.store_config(key, &value).await?;

                // If encryption is enabled and the on-disk data was plaintext, rewrite now.
                if self.encryption_key().is_some() && Self::should_encrypt_config(key) {
                    if !was_encrypted {
                        // Not JSON => legacy plaintext. Attempt migration.
                        if let Err(err) = self.write_config_file(key, &value).await {
                            log::warn!(
                                "failed to migrate configuration '{}' to encrypted storage: {}",
                                key,
                                err
                            );
                        }
                    }
                }

                Ok(Some(value))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    async fn load_config_fresh(&self, key: &str) -> Result<Option<String>, StorageError> {
        let file_path = self.config_file(key);
        match fs::read(&file_path).await {
            Ok(bytes) => {
                let raw = String::from_utf8_lossy(&bytes).to_string();
                let (value, _) = self.load_and_optionally_decrypt_config(key, raw).await?;
                // Always update the in-memory cache so subsequent reads see this value
                self.inner.store_config(key, &value).await?;
                Ok(Some(value))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    async fn list_files(&self, prefix: Option<&str>) -> Result<Vec<String>, StorageError> {
        self.inner.list_files(prefix).await
    }

    async fn store_file_index_entry(&self, entry: &FileIndexEntry) -> Result<(), StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::StoreEntry {
            entry: entry.clone(),
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn store_file_index_entries(
        &self,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::StoreEntries {
            entries: entries.to_vec(),
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn replace_file_index_entries_for_root(
        &self,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::ReplaceRoot {
            root_id,
            entries: entries.to_vec(),
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn load_file_index_entry(
        &self,
        file_uuid: Uuid,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::LoadByUuid {
            file_uuid,
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn load_file_index_entry_by_root_path(
        &self,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::LoadByRootPath {
            root_id,
            relative_path: relative_path.to_string(),
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn list_file_index_entries_by_root(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::ListByRoot { root_id, response };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn remove_file_index_entry(&self, file_uuid: Uuid) -> Result<(), StorageError> {
        let (response, rx) = oneshot::channel();
        let op = FileIndexOp::RemoveByUuid {
            file_uuid,
            response,
        };
        self.dispatch_file_index_op(op, rx).await
    }

    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError> {
        // Store in memory for fast access
        self.inner.store_file_metadata(file_path, metadata).await?;

        // Persist using deterministic path derived from SHA-256 of the canonical path
        let metadata_file = self.file_metadata_file(file_path);
        self.persist_metadata_payload(&metadata_file, metadata)
            .await?;

        // Clean up any legacy files that might exist from previous versions
        let legacy_file = self.legacy_file_metadata_file(file_path);
        if legacy_file != metadata_file {
            if let Err(err) = fs::remove_file(&legacy_file).await {
                if err.kind() != ErrorKind::NotFound {
                    log::debug!(
                        "Failed to remove legacy metadata file {}: {}",
                        legacy_file.display(),
                        err
                    );
                }
            }
        }

        Ok(())
    }

    async fn load_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<FileMetadataData>, StorageError> {
        // Try memory first for performance
        if let Some(metadata) = self.inner.load_file_metadata(file_path).await? {
            return Ok(Some(metadata));
        }

        // Fall back to disk if not in memory
        let metadata_file = self.file_metadata_file(file_path);
        if let Some(metadata) = self.read_metadata_payload(&metadata_file).await? {
            self.inner.store_file_metadata(file_path, &metadata).await?;
            return Ok(Some(metadata));
        }

        // Attempt to read legacy hashed files (pre-2025-11-xx)
        let legacy_file = self.legacy_file_metadata_file(file_path);
        if legacy_file != metadata_file {
            if let Some(metadata) = self.read_metadata_payload(&legacy_file).await? {
                // Re-store using the new deterministic layout to avoid future lookups
                self.store_file_metadata(file_path, &metadata).await?;
                return Ok(Some(metadata));
            }
        }

        Ok(None)
    }

    async fn get_stats(&self) -> Result<StorageStats, StorageError> {
        self.inner.get_stats().await
    }

    async fn maintenance(&self) -> Result<(), StorageError> {
        self.inner.maintenance().await
    }

    async fn create_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        self.inner.create_backup(backup_path, encryption_key).await
    }

    async fn restore_backup(
        &self,
        backup_path: &str,
        encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        self.inner.restore_backup(backup_path, encryption_key).await
    }

    async fn list_active_epochs(
        &self,
    ) -> Result<Vec<crate::epoch::state::EpochState>, StorageError> {
        self.inner.list_active_epochs().await
    }

    async fn store_welcome_record(
        &self,
        record: &crate::epoch::welcome::WelcomeRecord,
    ) -> Result<(), StorageError> {
        self.inner.store_welcome_record(record).await
    }

    async fn load_welcome_record(
        &self,
        epoch_id: u64,
        device_id: &str,
    ) -> Result<crate::epoch::welcome::WelcomeRecord, StorageError> {
        self.inner.load_welcome_record(epoch_id, device_id).await
    }

    async fn store_epoch_keys(
        &self,
        epoch_id: u64,
        secrets: &hybridcipher_messages::welcome::EpochSecrets,
    ) -> Result<(), StorageError> {
        self.inner.store_epoch_keys(epoch_id, secrets).await
    }

    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        log: &CoverageLogData,
    ) -> Result<(), StorageError> {
        self.inner.store_coverage_log(group_id, log).await?;
        self.write_coverage_log_file(group_id, log).await
    }

    async fn load_coverage_log(&self, group_id: Uuid) -> Result<CoverageLogData, StorageError> {
        if let Some(log) = self.read_coverage_log_file(group_id).await? {
            self.inner.store_coverage_log(group_id, &log).await?;
            return Ok(log);
        }

        self.inner.load_coverage_log(group_id).await
    }

    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError> {
        self.inner
            .append_coverage_log_delta(group_id, delta)
            .await?;
        self.append_coverage_log_journal(group_id, delta).await
    }

    async fn load_coverage_log_deltas(
        &self,
        group_id: Uuid,
        since_sequence: u64,
    ) -> Result<Vec<CoverageLogDeltaData>, StorageError> {
        let deltas = self
            .load_coverage_log_journal_since(group_id, since_sequence)
            .await?;
        if deltas.is_empty() {
            return self
                .inner
                .load_coverage_log_deltas(group_id, since_sequence)
                .await;
        }
        Ok(deltas)
    }

    async fn compact_coverage_log_deltas(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), StorageError> {
        self.inner
            .compact_coverage_log_deltas(group_id, up_to_sequence)
            .await?;
        self.compact_coverage_log_journal(group_id, up_to_sequence)
            .await
    }

    async fn coverage_log_journal_size(&self, group_id: Uuid) -> Result<Option<u64>, StorageError> {
        let file_path = self.coverage_log_journal_file(group_id);
        match fs::metadata(&file_path).await {
            Ok(meta) => Ok(Some(meta.len())),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(Some(0)),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, StorageError> {
        self.inner.begin_transaction().await
    }
}

#[cfg(test)]
mod tests {
    use super::super::AccessControlData;
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use tempfile::TempDir;

    #[tokio::test]
    async fn coverage_log_persists_across_instances() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = LocalFsStorage::new(temp_dir.path());

        let mut file_epochs = HashMap::new();
        file_epochs.insert("alpha.txt".to_string(), 7);
        file_epochs.insert("beta.txt".to_string(), 3);

        let coverage = CoverageLogData {
            root_hash: [42u8; 32],
            tree_nodes: vec![1, 2, 3, 4],
            file_epochs,
            sequence: 9,
            updated_at: Utc::now(),
            version: 2,
        };

        let gid = Uuid::new_v4();
        storage
            .store_coverage_log(gid, &coverage)
            .await
            .expect("store coverage log");

        // Re-open the storage to simulate a fresh CLI session.
        let reopened = LocalFsStorage::new(temp_dir.path());
        let loaded = reopened
            .load_coverage_log(gid)
            .await
            .expect("load persisted coverage log");

        assert_eq!(loaded.root_hash, coverage.root_hash);
        assert_eq!(loaded.tree_nodes, coverage.tree_nodes);
        assert_eq!(loaded.sequence, coverage.sequence);
        assert_eq!(loaded.version, coverage.version);
        assert_eq!(loaded.file_epochs, coverage.file_epochs);
    }

    fn sample_metadata() -> FileMetadataData {
        FileMetadataData {
            file_path: "/tmp/example.txt.encrypted".to_string(),
            file_id: Some("/tmp/example.txt.encrypted".to_string()),
            group_id: Some(Uuid::nil()),
            epoch_id: 42,
            header_version: Some(1),
            wrapped_file_key: None,
            key_wrap_nonce: None,
            key_wrap_aad_hash: None,
            content_nonce: None,
            content_chunk_size: None,
            algorithm: "chacha20poly1305".to_string(),
            file_size: 1024,
            modified_at: Utc::now(),
            integrity_hash: [7u8; 32],
            permissions: AccessControlData {
                readers: Vec::new(),
                writers: Vec::new(),
                is_public: false,
            },
            version: 1,
            chunks: Vec::new(),
            encrypted_size: 2048,
            encrypted_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn file_metadata_persists_across_instances() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = LocalFsStorage::new(temp_dir.path());
        let metadata = sample_metadata();

        storage
            .store_file_metadata(&metadata.file_path, &metadata)
            .await
            .expect("store metadata");

        let reopened = LocalFsStorage::new(temp_dir.path());
        let loaded = reopened
            .load_file_metadata(&metadata.file_path)
            .await
            .expect("load metadata")
            .expect("metadata present");

        assert_eq!(loaded.file_path, metadata.file_path);
        assert_eq!(loaded.epoch_id, metadata.epoch_id);
        assert_eq!(loaded.file_size, metadata.file_size);

        // Ensure deterministic path exists on disk
        let deterministic = reopened.file_metadata_file(&metadata.file_path);
        assert!(deterministic.exists());
    }

    #[tokio::test]
    async fn legacy_metadata_files_are_migrated() {
        let temp_dir = TempDir::new().expect("temp dir");
        let storage = LocalFsStorage::new(temp_dir.path());
        let metadata = sample_metadata();

        // Simulate legacy file layout
        let legacy_path = storage.legacy_file_metadata_file(&metadata.file_path);
        std::fs::create_dir_all(legacy_path.parent().unwrap()).expect("create dir");
        let payload =
            serde_json::to_vec_pretty(&metadata).expect("serialize legacy metadata payload");
        std::fs::write(&legacy_path, payload).expect("write legacy file");

        let reopened = LocalFsStorage::new(temp_dir.path());
        let loaded = reopened
            .load_file_metadata(&metadata.file_path)
            .await
            .expect("load metadata")
            .expect("metadata present");
        assert_eq!(loaded.epoch_id, metadata.epoch_id);

        // Legacy file should be replaced with deterministic layout
        let deterministic = reopened.file_metadata_file(&metadata.file_path);
        assert!(deterministic.exists());
    }
}
