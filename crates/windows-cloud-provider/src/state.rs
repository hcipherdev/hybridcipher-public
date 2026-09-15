use crate::{CloudObjectIdentityV2, CloudProviderError, Result};
use chrono::{DateTime, Utc};
use hybridcipher_provider_core::{ProviderContentVersion, ProviderEntry, ProviderEntryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
    time::Duration,
};
use uuid::Uuid;

const CLOUD_ROOT_STATE_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudItemState {
    pub identity: CloudObjectIdentityV2,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_version: Option<ProviderContentVersion>,
    #[serde(default)]
    pub dirty: bool,
}

impl CloudItemState {
    pub fn new(
        identity: CloudObjectIdentityV2,
        relative_path: impl Into<String>,
        content_version: Option<ProviderContentVersion>,
    ) -> Self {
        Self {
            identity,
            relative_path: relative_path.into().replace('\\', "/"),
            content_version,
            dirty: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudConflictRecord {
    pub id: Uuid,
    pub object_id: String,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<ProviderContentVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_version: Option<ProviderContentVersion>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_plaintext_path: Option<PathBuf>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloudRootPersistentState {
    pub version: u16,
    pub root_id: Uuid,
    pub generation: u64,
    #[serde(default)]
    pub items: BTreeMap<String, CloudItemState>,
    #[serde(default)]
    pub directory_ids: BTreeMap<String, Uuid>,
    #[serde(default)]
    pub conflicts: Vec<CloudConflictRecord>,
    #[serde(default)]
    pub ingestion_in_progress: usize,
    #[serde(default)]
    pub reconciliation_in_progress: bool,
}

impl CloudRootPersistentState {
    pub fn empty(root_id: Uuid) -> Self {
        Self {
            version: CLOUD_ROOT_STATE_VERSION,
            root_id,
            generation: 0,
            items: BTreeMap::new(),
            directory_ids: BTreeMap::new(),
            conflicts: Vec::new(),
            ingestion_in_progress: 0,
            reconciliation_in_progress: false,
        }
    }

    pub fn safe_to_unmount(&self, pending_mutations: usize) -> bool {
        pending_mutations == 0
            && self.conflicts.is_empty()
            && self.ingestion_in_progress == 0
            && !self.reconciliation_in_progress
    }

    pub fn has_operation_in_progress(&self) -> bool {
        self.ingestion_in_progress > 0 || self.reconciliation_in_progress
    }

    pub fn upsert_inventory_entry(
        &mut self,
        entry: &ProviderEntry,
    ) -> Result<CloudObjectIdentityV2> {
        self.upsert_inventory_entry_with_policy(entry, true)
    }

    pub fn upsert_committed_inventory_entry(
        &mut self,
        entry: &ProviderEntry,
    ) -> Result<CloudObjectIdentityV2> {
        self.upsert_inventory_entry_with_policy(entry, false)
    }

    fn upsert_inventory_entry_with_policy(
        &mut self,
        entry: &ProviderEntry,
        preserve_dirty_local_state: bool,
    ) -> Result<CloudObjectIdentityV2> {
        if entry.root_id != self.root_id {
            return Err(CloudProviderError::Callback(format!(
                "inventory entry {} belongs to the wrong root",
                entry.relative_path
            )));
        }
        let stable_directory_identity =
            entry.kind == ProviderEntryKind::Directory && entry.identity.file_id.is_some();
        let object_id = match entry.kind {
            ProviderEntryKind::File => entry.identity.file_id.clone().ok_or_else(|| {
                CloudProviderError::Callback(format!(
                    "encrypted file {} has no stable file id",
                    entry.relative_path
                ))
            })?,
            ProviderEntryKind::Directory => {
                if let Some(file_id) = entry.identity.file_id.clone() {
                    file_id
                } else {
                    self.directory_ids
                        .entry(entry.relative_path.clone())
                        .or_insert_with(Uuid::new_v4)
                        .to_string()
                }
            }
        };
        if let Some(existing) = self.items.get(&object_id) {
            if existing.identity.kind != entry.kind {
                return Err(CloudProviderError::Callback(format!(
                    "stable identity {object_id} is already used by a {:?}, not a {:?}",
                    existing.identity.kind, entry.kind
                )));
            }
        }
        if stable_directory_identity {
            self.directory_ids.remove(&entry.relative_path);
        }
        let identity = CloudObjectIdentityV2::new(self.root_id, entry.kind, object_id.clone());
        let previous = self.items.get(&object_id);
        let dirty = preserve_dirty_local_state && previous.map(|item| item.dirty).unwrap_or(false);
        let content_version = if dirty {
            previous.and_then(|item| item.content_version.clone())
        } else {
            entry.content_version()
        };
        let relative_path = if dirty {
            previous
                .map(|item| item.relative_path.as_str())
                .unwrap_or(&entry.relative_path)
        } else {
            &entry.relative_path
        };
        let mut item = CloudItemState::new(identity.clone(), relative_path, content_version);
        item.dirty = dirty;
        self.items.insert(object_id, item);
        Ok(identity)
    }

    pub fn migrate_directory_path(&mut self, old_path: &str, new_path: &str) -> Result<()> {
        let old_path = old_path.replace('\\', "/").trim_matches('/').to_string();
        let new_path = new_path.replace('\\', "/").trim_matches('/').to_string();
        if old_path.is_empty() || new_path.is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "directory migration paths must not be empty".into(),
            ));
        }
        let target_exists = self.directory_ids.contains_key(&new_path)
            || self.items.values().any(|item| {
                item.identity.kind == ProviderEntryKind::Directory && item.relative_path == new_path
            });
        if target_exists {
            return Err(CloudProviderError::InvalidPath(format!(
                "directory migration target already exists: {new_path}"
            )));
        }

        let prefix = format!("{old_path}/");
        let directory_migrations = self
            .directory_ids
            .iter()
            .filter_map(|(path, id)| {
                if path == &old_path || path.starts_with(&prefix) {
                    let suffix = path.strip_prefix(&old_path).unwrap_or_default();
                    Some((path.clone(), format!("{new_path}{suffix}"), *id))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let stable_source_exists = self.items.values().any(|item| {
            item.identity.kind == ProviderEntryKind::Directory && item.relative_path == old_path
        });
        if directory_migrations.is_empty() && !stable_source_exists {
            return Err(CloudProviderError::InvalidPath(format!(
                "directory migration source is unknown: {old_path}"
            )));
        }
        for (old, _, _) in &directory_migrations {
            self.directory_ids.remove(old);
        }
        for (_, new, id) in directory_migrations {
            self.directory_ids.insert(new, id);
        }

        for item in self.items.values_mut() {
            if item.relative_path == old_path || item.relative_path.starts_with(&prefix) {
                let suffix = item
                    .relative_path
                    .strip_prefix(&old_path)
                    .unwrap_or_default();
                item.relative_path = format!("{new_path}{suffix}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateEnvelope {
    schema_version: u16,
    generation: u64,
    checksum_hex: String,
    state: CloudRootPersistentState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum DurableInspectionSource {
    Primary,
    Backup,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DurableInspection<T> {
    pub value: T,
    pub source: DurableInspectionSource,
    pub generation: u64,
}

pub(crate) struct CloudStateStore {
    path: PathBuf,
    backup_path: PathBuf,
    root_id: Uuid,
    writer: Mutex<()>,
}

impl CloudStateStore {
    pub(crate) fn new(path: PathBuf, root_id: Uuid) -> Self {
        let backup_path = path.with_extension("json.bak");
        Self {
            path,
            backup_path,
            root_id,
            writer: Mutex::new(()),
        }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn load(&self) -> Result<CloudRootPersistentState> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| CloudProviderError::Callback("cloud state lock poisoned".into()))?;
        self.load_unlocked()
    }

    /// Reads and validates the primary and backup entirely in memory.
    ///
    /// This deliberately does not take the writer mutex and never repairs, promotes,
    /// quarantines, creates, or truncates either source.
    pub(crate) fn inspect(&self) -> Result<Option<DurableInspection<CloudRootPersistentState>>> {
        inspect_state_sources(&self.path, &self.backup_path, self.root_id)
    }

    pub(crate) fn transaction<T>(
        &self,
        update: impl FnOnce(&mut CloudRootPersistentState) -> Result<T>,
    ) -> Result<T> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| CloudProviderError::Callback("cloud state lock poisoned".into()))?;
        let mut state = self.load_unlocked()?;
        let result = update(&mut state)?;
        state.generation = state.generation.saturating_add(1);
        self.write_unlocked(&state)?;
        Ok(result)
    }

    pub(crate) fn replace_if_generation(
        &self,
        expected_generation: u64,
        mut replacement: CloudRootPersistentState,
    ) -> Result<()> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| CloudProviderError::Callback("cloud state lock poisoned".into()))?;
        let current = self.load_unlocked()?;
        if current.generation != expected_generation {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files state generation changed while reconciliation was applying: expected {expected_generation}, found {}",
                current.generation
            )));
        }
        if replacement.root_id != self.root_id || replacement.version != CLOUD_ROOT_STATE_VERSION {
            return Err(CloudProviderError::Callback(
                "Cloud Files replacement state metadata mismatch".into(),
            ));
        }
        replacement.generation = current.generation.saturating_add(1);
        self.write_unlocked(&replacement)
    }

    pub(crate) fn complete_startup_recovery(&self) -> Result<bool> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| CloudProviderError::Callback("cloud state lock poisoned".into()))?;
        let mut state = self.load_unlocked()?;
        if !state.has_operation_in_progress() {
            return Ok(false);
        }
        state.ingestion_in_progress = 0;
        state.reconciliation_in_progress = false;
        state.generation = state.generation.saturating_add(1);
        self.write_unlocked(&state)?;
        Ok(true)
    }

    pub(crate) fn require_startup_recovery(&self) -> Result<bool> {
        let _guard = self
            .writer
            .lock()
            .map_err(|_| CloudProviderError::Callback("cloud state lock poisoned".into()))?;
        let mut state = self.load_unlocked()?;
        if state.reconciliation_in_progress {
            return Ok(false);
        }
        state.reconciliation_in_progress = true;
        state.generation = state.generation.saturating_add(1);
        self.write_unlocked(&state)?;
        Ok(true)
    }

    fn load_unlocked(&self) -> Result<CloudRootPersistentState> {
        if !self.path.exists() && !self.backup_path.exists() {
            return Ok(CloudRootPersistentState::empty(self.root_id));
        }

        if self.path.exists() {
            match read_envelope(&self.path, self.root_id) {
                Ok(state) => return Ok(state),
                Err(err) => tracing::warn!(
                    "Ignoring invalid Cloud Files state generation at {}: {}",
                    self.path.display(),
                    err
                ),
            }
        }
        if self.backup_path.exists() {
            match read_envelope(&self.backup_path, self.root_id) {
                Ok(state) => {
                    quarantine_corrupt_file(&self.path)?;
                    return Ok(state);
                }
                Err(err) => tracing::warn!(
                    "Ignoring invalid Cloud Files state generation at {}: {}",
                    self.backup_path.display(),
                    err
                ),
            }
        }
        Err(CloudProviderError::Callback(format!(
            "no valid Cloud Files state generation remains for {}",
            self.root_id
        )))
    }

    fn write_unlocked(&self, state: &CloudRootPersistentState) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let state_bytes = serde_json::to_vec(state)?;
        let envelope = StateEnvelope {
            schema_version: CLOUD_ROOT_STATE_VERSION,
            generation: state.generation,
            checksum_hex: checksum_hex(&state_bytes),
            state: state.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        durable_replace(&self.path, &self.backup_path, &bytes)
    }
}

fn quarantine_corrupt_file(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cloud-state.json");
    let quarantine = path.with_file_name(format!("{file_name}.corrupt-{}", Uuid::new_v4()));
    fs::rename(path, &quarantine)?;
    let _ = fs::remove_file(quarantine);
    Ok(())
}

fn read_envelope(path: &Path, expected_root_id: Uuid) -> Result<CloudRootPersistentState> {
    parse_envelope(&fs::read(path)?, expected_root_id)
}

fn parse_envelope(data: &[u8], expected_root_id: Uuid) -> Result<CloudRootPersistentState> {
    let envelope: StateEnvelope = serde_json::from_slice(data)?;
    if envelope.schema_version != CLOUD_ROOT_STATE_VERSION
        || envelope.state.version != CLOUD_ROOT_STATE_VERSION
        || envelope.state.root_id != expected_root_id
        || envelope.generation != envelope.state.generation
    {
        return Err(CloudProviderError::Callback(
            "Cloud Files state envelope metadata mismatch".into(),
        ));
    }
    let state_bytes = serde_json::to_vec(&envelope.state)?;
    if checksum_hex(&state_bytes) != envelope.checksum_hex {
        return Err(CloudProviderError::Callback(
            "Cloud Files state checksum mismatch".into(),
        ));
    }
    Ok(envelope.state)
}

fn inspect_state_sources(
    primary_path: &Path,
    backup_path: &Path,
    expected_root_id: Uuid,
) -> Result<Option<DurableInspection<CloudRootPersistentState>>> {
    let primary_exists = primary_path.exists();
    let backup_exists = backup_path.exists();
    if !primary_exists && !backup_exists {
        return Ok(None);
    }
    let primary = fs::read(primary_path)
        .ok()
        .and_then(|bytes| parse_envelope(&bytes, expected_root_id).ok())
        .map(|value| DurableInspection {
            generation: value.generation,
            value,
            source: DurableInspectionSource::Primary,
        });
    let backup = fs::read(backup_path)
        .ok()
        .and_then(|bytes| parse_envelope(&bytes, expected_root_id).ok())
        .map(|value| DurableInspection {
            generation: value.generation,
            value,
            source: DurableInspectionSource::Backup,
        });
    match (primary, backup) {
        (Some(primary), Some(backup)) => Ok(Some(if backup.generation > primary.generation {
            backup
        } else {
            primary
        })),
        (Some(primary), None) => Ok(Some(primary)),
        (None, Some(backup)) => Ok(Some(backup)),
        (None, None) => Err(CloudProviderError::Callback(format!(
            "no valid Cloud Files state generation remains for {expected_root_id}"
        ))),
    }
}

fn checksum_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn durable_replace(path: &Path, backup_path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("cloud-state.json");
    let temp_path = parent.join(format!(".{file_name}.tmp-{}", Uuid::new_v4()));

    let result = (|| -> Result<()> {
        let mut temp = File::create(&temp_path)?;
        temp.write_all(bytes)?;
        temp.flush()?;
        temp.sync_all()?;
        // Close the replacement before the Windows atomic rename.
        drop(temp);

        if path.exists() {
            fs::copy(path, backup_path)?;
            // FlushFileBuffers requires a writable Windows handle; File::open is read-only.
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(backup_path)?
                .sync_all()?;
        }

        replace_file(&temp_path, path)?;
        if let Ok(directory) = File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> Result<()> {
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
    const MAX_REPLACE_ATTEMPTS: usize = 20;
    for attempt in 0..MAX_REPLACE_ATTEMPTS {
        let result = unsafe {
            MoveFileExW(
                PCWSTR(source.as_ptr()),
                PCWSTR(destination.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        match result {
            Ok(()) => return Ok(()),
            Err(error)
                if attempt + 1 < MAX_REPLACE_ATTEMPTS
                    && matches!(error.code().0 as u32, 0x8007_0005 | 0x8007_0020) =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("the bounded Windows replacement loop always returns")
}

pub fn versioned_cache_path(
    cache_root: &Path,
    identity: &CloudObjectIdentityV2,
    version: &ProviderContentVersion,
) -> PathBuf {
    let safe_object_id = identity
        .object_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    cache_root.join(format!("{safe_object_id}-{}.plain", version.as_str()))
}

#[cfg(test)]
mod inspection_tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn root_health_state_inspection_selects_backup_without_mutating_files() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let path = temp.path().join("state.json");
        let store = CloudStateStore::new(path.clone(), root_id);
        store.transaction(|_| Ok(())).unwrap();
        store.transaction(|_| Ok(())).unwrap();
        fs::write(&path, b"{corrupt").unwrap();

        let backup_path = path.with_extension("json.bak");
        let primary_before = fs::read(&path).unwrap();
        let backup_before = fs::read(&backup_path).unwrap();
        let primary_mtime_before = fs::metadata(&path).unwrap().modified().unwrap();
        let backup_mtime_before = fs::metadata(&backup_path).unwrap().modified().unwrap();
        let entries_before = fs::read_dir(temp.path()).unwrap().count();

        let inspected = store.inspect().unwrap().unwrap();

        assert_eq!(inspected.source, DurableInspectionSource::Backup);
        assert_eq!(inspected.generation, 1);
        assert_eq!(inspected.value.generation, 1);
        assert_eq!(fs::read(&path).unwrap(), primary_before);
        assert_eq!(fs::read(&backup_path).unwrap(), backup_before);
        assert_eq!(
            fs::metadata(&path).unwrap().modified().unwrap(),
            primary_mtime_before
        );
        assert_eq!(
            fs::metadata(&backup_path).unwrap().modified().unwrap(),
            backup_mtime_before
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), entries_before);
    }

    #[test]
    fn root_health_state_inspection_during_writes_returns_complete_generation() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let store = Arc::new(CloudStateStore::new(
            temp.path().join("state.json"),
            root_id,
        ));
        store.transaction(|_| Ok(())).unwrap();
        let writer = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for _ in 0..25 {
                    store.transaction(|_| Ok(())).unwrap();
                }
            })
        };

        for _ in 0..100 {
            let inspected = store.inspect().unwrap().unwrap();
            assert_eq!(inspected.value.root_id, root_id);
            assert_eq!(inspected.generation, inspected.value.generation);
        }
        writer.join().unwrap();
    }
}
