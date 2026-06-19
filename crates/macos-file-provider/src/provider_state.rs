use chrono::{DateTime, Utc};
use hybridcipher_provider_core::{FileIdentityV1, ProviderEntry, ProviderEntryKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use uuid::Uuid;

pub(crate) const PROVIDER_STATE_VERSION: u16 = 2;
pub(crate) const ROOT_CONTAINER_SIGNAL_IDENTIFIER: &str = "__hybridcipher_root_container__";
const PENDING_FILE_ID_PREFIX: &str = "pending:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProviderItemIdentifier {
    File { file_id: String },
    Directory { directory_id: String },
}

impl ProviderItemIdentifier {
    const PREFIX: &'static str = "hc:v2:";

    pub fn parse(identifier: &str) -> Result<Self, String> {
        let trimmed = identifier.trim();
        let without_prefix = trimmed
            .strip_prefix(Self::PREFIX)
            .ok_or_else(|| format!("unsupported provider identifier {trimmed}"))?;
        if let Some(file_id) = without_prefix.strip_prefix("file:") {
            if file_id.is_empty() {
                return Err("provider file identifier is empty".to_string());
            }
            return Ok(Self::File {
                file_id: file_id.to_string(),
            });
        }
        if let Some(directory_id) = without_prefix.strip_prefix("dir:") {
            if directory_id.is_empty() {
                return Err("provider directory identifier is empty".to_string());
            }
            return Ok(Self::Directory {
                directory_id: directory_id.to_string(),
            });
        }
        Err(format!("unsupported provider identifier {trimmed}"))
    }
}

impl fmt::Display for ProviderItemIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File { file_id } => write!(f, "{}file:{file_id}", Self::PREFIX),
            Self::Directory { directory_id } => {
                write!(f, "{}dir:{directory_id}", Self::PREFIX)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderItemSnapshot {
    pub root_id: Uuid,
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_provider_id: Option<String>,
    pub relative_path: String,
    pub kind: ProviderEntryKind,
    pub logical_size: u64,
    pub encrypted_size: u64,
    pub modified_at: DateTime<Utc>,
    pub content_version: Vec<u8>,
    pub metadata_version: Vec<u8>,
    pub identity: FileIdentityV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ProviderChangeKind {
    Upsert,
    Delete,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderChangeRecord {
    pub anchor: u64,
    pub kind: ProviderChangeKind,
    pub provider_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_provider_id: Option<String>,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ProviderItemSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderChangeJournal {
    pub version: u16,
    pub root_id: Uuid,
    pub earliest_anchor: u64,
    pub latest_anchor: u64,
    #[serde(default)]
    pub records: Vec<ProviderChangeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderChangeEnumeration {
    pub latest_anchor: u64,
    pub expired: bool,
    #[serde(default)]
    pub records: Vec<ProviderChangeRecord>,
}

impl ProviderChangeJournal {
    pub fn new(root_id: Uuid) -> Self {
        Self {
            version: PROVIDER_STATE_VERSION,
            root_id,
            earliest_anchor: 1,
            latest_anchor: 0,
            records: Vec::new(),
        }
    }

    pub fn push_upsert(&mut self, snapshot: ProviderItemSnapshot) -> u64 {
        let anchor = self.next_anchor();
        self.records.push(ProviderChangeRecord {
            anchor,
            kind: ProviderChangeKind::Upsert,
            provider_id: snapshot.provider_id.clone(),
            parent_provider_id: snapshot.parent_provider_id.clone(),
            relative_path: snapshot.relative_path.clone(),
            snapshot: Some(snapshot),
        });
        anchor
    }

    pub fn push_delete(
        &mut self,
        provider_id: String,
        parent_provider_id: Option<String>,
        relative_path: String,
    ) -> u64 {
        let anchor = self.next_anchor();
        self.records.push(ProviderChangeRecord {
            anchor,
            kind: ProviderChangeKind::Delete,
            provider_id,
            parent_provider_id,
            relative_path,
            snapshot: None,
        });
        anchor
    }

    pub fn trim_to_retention(&mut self, retention: usize) {
        if self.records.len() > retention {
            let keep_from = self.records.len() - retention;
            self.records.drain(..keep_from);
        }
        self.earliest_anchor = self.records.first().map(|record| record.anchor).unwrap_or_else(|| {
            self.latest_anchor.saturating_add(1).max(1)
        });
    }

    pub fn anchor_is_expired(&self, anchor: u64) -> bool {
        if self.records.is_empty() {
            return false;
        }
        anchor.saturating_add(1) < self.earliest_anchor
    }

    pub fn changes_since(&self, anchor: u64) -> Option<Vec<ProviderChangeRecord>> {
        if self.anchor_is_expired(anchor) {
            return None;
        }
        Some(
            self.records
                .iter()
                .filter(|record| record.anchor > anchor)
                .cloned()
                .collect(),
        )
    }

    fn next_anchor(&mut self) -> u64 {
        self.latest_anchor = self.latest_anchor.saturating_add(1);
        if self.records.is_empty() {
            self.earliest_anchor = self.latest_anchor;
        }
        self.latest_anchor
    }

    pub fn enumerate_changes(&self, anchor: u64) -> ProviderChangeEnumeration {
        match self.changes_since(anchor) {
            Some(records) => ProviderChangeEnumeration {
                latest_anchor: self.latest_anchor,
                expired: false,
                records,
            },
            None => ProviderChangeEnumeration {
                latest_anchor: self.latest_anchor,
                expired: true,
                records: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ProviderPersistentState {
    pub version: u16,
    pub root_id: Uuid,
    #[serde(default)]
    pub items: BTreeMap<String, ProviderItemSnapshot>,
    #[serde(default)]
    pub path_to_directory_id: BTreeMap<String, String>,
}

impl ProviderPersistentState {
    pub fn new(root_id: Uuid) -> Self {
        Self {
            version: PROVIDER_STATE_VERSION,
            root_id,
            items: BTreeMap::new(),
            path_to_directory_id: BTreeMap::new(),
        }
    }

    pub fn ensure_directory_path(&mut self, relative_path: String) -> String {
        if let Some(existing) = self.path_to_directory_id.get(&relative_path) {
            return existing.clone();
        }
        let directory_id = Uuid::new_v4().to_string();
        self.path_to_directory_id
            .insert(relative_path, directory_id.clone());
        directory_id
    }

    pub fn rebuild_items(
        &mut self,
        root_id: Uuid,
        _encrypted_root: &std::path::Path,
        _cache_root: &std::path::Path,
        entries: &[ProviderEntry],
    ) {
        let previous_directory_ids = self.path_to_directory_id.clone();
        let mut directory_entries = entries
            .iter()
            .filter(|entry| entry.kind == ProviderEntryKind::Directory)
            .cloned()
            .collect::<Vec<_>>();
        directory_entries.sort_by(|left, right| {
            left.relative_path
                .matches('/')
                .count()
                .cmp(&right.relative_path.matches('/').count())
                .then_with(|| left.relative_path.cmp(&right.relative_path))
        });

        self.items.clear();
        self.path_to_directory_id.clear();

        for entry in &directory_entries {
            let directory_id = previous_directory_ids
                .get(&entry.relative_path)
                .cloned()
                .unwrap_or_else(|| Uuid::new_v4().to_string());
            self.path_to_directory_id
                .insert(entry.relative_path.clone(), directory_id);
        }

        for entry in directory_entries {
            let snapshot = self.snapshot_for_entry(root_id, entry);
            self.items
                .insert(snapshot.provider_id.clone(), snapshot);
        }

        let mut file_entries = entries
            .iter()
            .filter(|entry| entry.kind == ProviderEntryKind::File)
            .cloned()
            .collect::<Vec<_>>();
        file_entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

        for entry in file_entries {
            let snapshot = self.snapshot_for_entry(root_id, entry);
            self.items
                .insert(snapshot.provider_id.clone(), snapshot);
        }
    }

    pub fn apply_directory_migration(&mut self, old_prefix: &str, new_prefix: &str) {
        let old_prefix = normalize_relative_path(old_prefix);
        let new_prefix = normalize_relative_path(new_prefix);
        let mut migrated = BTreeMap::new();
        let mut removed = Vec::new();
        for (path, directory_id) in &self.path_to_directory_id {
            if path == &old_prefix || path.starts_with(&(old_prefix.clone() + "/")) {
                let suffix = path.strip_prefix(&old_prefix).unwrap_or("");
                let migrated_path = format!("{}{}", new_prefix, suffix);
                migrated.insert(migrated_path, directory_id.clone());
                removed.push(path.clone());
            }
        }
        for path in removed {
            self.path_to_directory_id.remove(&path);
        }
        self.path_to_directory_id.extend(migrated);
    }

    pub fn snapshot(&self, provider_id: &str) -> Option<&ProviderItemSnapshot> {
        self.items.get(provider_id)
    }

    pub fn snapshot_cloned(&self, provider_id: &str) -> Option<ProviderItemSnapshot> {
        self.items.get(provider_id).cloned()
    }

    pub fn snapshot_for_relative_path(
        &self,
        root_id: Uuid,
        entry: ProviderEntry,
    ) -> Option<ProviderItemSnapshot> {
        let snapshot = self.snapshot_for_entry(root_id, entry);
        self.items
            .get(&snapshot.provider_id)
            .cloned()
            .or(Some(snapshot))
    }

    pub fn snapshot_for_entry(
        &self,
        root_id: Uuid,
        entry: ProviderEntry,
    ) -> ProviderItemSnapshot {
        let parent_relative_path = parent_relative_path(&entry.relative_path);
        let parent_provider_id = if parent_relative_path.is_empty() {
            None
        } else {
            self.path_to_directory_id
                .get(&parent_relative_path)
                .cloned()
                .map(|directory_id| ProviderItemIdentifier::Directory { directory_id }.to_string())
        };

        match entry.kind {
            ProviderEntryKind::Directory => {
                let directory_id = self
                    .path_to_directory_id
                    .get(&entry.relative_path)
                    .cloned()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                let provider_id =
                    ProviderItemIdentifier::Directory { directory_id: directory_id.clone() }
                        .to_string();
                let metadata_version = hash_metadata_version(
                    &provider_id,
                    parent_provider_id.as_deref(),
                    &entry.relative_path,
                    entry.kind,
                );
                ProviderItemSnapshot {
                    root_id,
                    provider_id,
                    parent_provider_id,
                    relative_path: entry.relative_path.clone(),
                    kind: entry.kind,
                    logical_size: entry.logical_size,
                    encrypted_size: entry.encrypted_size,
                    modified_at: entry.modified_at,
                    content_version: hash_directory_content_version(&directory_id, &entry),
                    metadata_version,
                    identity: entry.identity,
                }
            }
            ProviderEntryKind::File => {
                let stable_file_id = entry
                    .identity
                    .file_id
                    .clone()
                    .unwrap_or_else(|| pending_file_identity_component(&entry.identity));
                let provider_id =
                    ProviderItemIdentifier::File { file_id: stable_file_id.clone() }.to_string();
                let metadata_version = hash_metadata_version(
                    &provider_id,
                    parent_provider_id.as_deref(),
                    &entry.relative_path,
                    entry.kind,
                );
                ProviderItemSnapshot {
                    root_id,
                    provider_id,
                    parent_provider_id,
                    relative_path: entry.relative_path.clone(),
                    kind: entry.kind,
                    logical_size: entry.logical_size,
                    encrypted_size: entry.encrypted_size,
                    modified_at: entry.modified_at,
                    content_version: hash_file_content_version(&stable_file_id, &entry),
                    metadata_version,
                    identity: entry.identity,
                }
            }
        }
    }
}

pub(crate) fn record_state_changes(
    journal: &mut ProviderChangeJournal,
    previous_state: &ProviderPersistentState,
    next_state: &ProviderPersistentState,
    retention: usize,
) -> BTreeSet<String> {
    let mut touched_containers = BTreeSet::new();
    for (provider_id, previous_snapshot) in &previous_state.items {
        if !next_state.items.contains_key(provider_id) {
            journal.push_delete(
                provider_id.clone(),
                previous_snapshot.parent_provider_id.clone(),
                previous_snapshot.relative_path.clone(),
            );
            if let Some(parent_provider_id) = previous_snapshot.parent_provider_id.as_ref() {
                touched_containers.insert(parent_provider_id.clone());
            } else {
                touched_containers.insert(ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string());
            }
        }
    }

    for (provider_id, next_snapshot) in &next_state.items {
        match previous_state.items.get(provider_id) {
            Some(previous_snapshot) if previous_snapshot == next_snapshot => {}
            Some(previous_snapshot) => {
                journal.push_upsert(next_snapshot.clone());
                if let Some(parent_provider_id) = previous_snapshot.parent_provider_id.as_ref() {
                    touched_containers.insert(parent_provider_id.clone());
                } else {
                    touched_containers.insert(ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string());
                }
                if let Some(parent_provider_id) = next_snapshot.parent_provider_id.as_ref() {
                    touched_containers.insert(parent_provider_id.clone());
                } else {
                    touched_containers.insert(ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string());
                }
                if next_snapshot.kind == ProviderEntryKind::Directory {
                    touched_containers.insert(next_snapshot.provider_id.clone());
                }
            }
            None => {
                journal.push_upsert(next_snapshot.clone());
                if let Some(parent_provider_id) = next_snapshot.parent_provider_id.as_ref() {
                    touched_containers.insert(parent_provider_id.clone());
                } else {
                    touched_containers.insert(ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string());
                }
                if next_snapshot.kind == ProviderEntryKind::Directory {
                    touched_containers.insert(next_snapshot.provider_id.clone());
                }
            }
        }
    }

    journal.trim_to_retention(retention);
    touched_containers
}

fn pending_file_identity_component(identity: &FileIdentityV1) -> String {
    format!("{PENDING_FILE_ID_PREFIX}{}", identity.path_hash_hex)
}

fn parent_relative_path(relative_path: &str) -> String {
    if relative_path.is_empty() {
        return String::new();
    }
    let parent = std::path::Path::new(relative_path)
        .parent()
        .map(|path| normalize_relative_path(path.to_string_lossy()))
        .unwrap_or_default();
    if parent == "." {
        String::new()
    } else {
        parent
    }
}

fn relative_filename(relative_path: &str) -> String {
    std::path::Path::new(relative_path)
        .file_name()
        .map(|value| value.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn normalize_relative_path(path: impl Into<String>) -> String {
    path.into()
        .replace('\\', "/")
        .trim_start_matches('/')
        .trim_end_matches('/')
        .to_string()
}

fn hash_file_content_version(stable_file_id: &str, entry: &ProviderEntry) -> Vec<u8> {
    hash_parts(&[
        b"file-content-v1",
        stable_file_id.as_bytes(),
        &entry.logical_size.to_be_bytes(),
        &entry.encrypted_size.to_be_bytes(),
        &entry.modified_at.timestamp_millis().to_be_bytes(),
        &entry.identity.epoch_id.unwrap_or_default().to_be_bytes(),
    ])
}

fn hash_directory_content_version(directory_id: &str, entry: &ProviderEntry) -> Vec<u8> {
    hash_parts(&[
        b"dir-content-v1",
        directory_id.as_bytes(),
        &entry.modified_at.timestamp_millis().to_be_bytes(),
    ])
}

fn hash_metadata_version(
    provider_id: &str,
    parent_provider_id: Option<&str>,
    relative_path: &str,
    kind: ProviderEntryKind,
) -> Vec<u8> {
    hash_parts(&[
        b"metadata-v1",
        provider_id.as_bytes(),
        parent_provider_id.unwrap_or_default().as_bytes(),
        relative_path.as_bytes(),
        relative_filename(relative_path).as_bytes(),
        kind_label(kind).as_bytes(),
    ])
}

fn hash_parts(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}

fn kind_label(kind: ProviderEntryKind) -> &'static str {
    match kind {
        ProviderEntryKind::Directory => "directory",
        ProviderEntryKind::File => "file",
    }
}
