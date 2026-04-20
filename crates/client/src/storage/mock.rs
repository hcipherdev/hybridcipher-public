use crate::coverage::FileIndexEntry;
use crate::storage::{
    CoverageLogData, CoverageLogDeltaData, EpochStateData, FileMetadataData, Storage, StorageError,
    StorageHealth, StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use serde_json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Mock storage implementation for testing
///
/// Provides in-memory storage with all storage trait functionality
/// for comprehensive testing without external dependencies.
#[derive(Debug, Clone)]
pub struct MockStorage {
    /// In-memory data store
    data: Arc<RwLock<MockStorageData>>,
}

#[derive(Debug, Default)]
struct MockStorageData {
    identity_keys: HashMap<String, Vec<u8>>,
    epoch_states: HashMap<u64, EpochStateData>,
    file_metadata: HashMap<String, FileMetadataData>,
    file_index: HashMap<Uuid, FileIndexEntry>,
    coverage_log: HashMap<Uuid, CoverageLogData>,
    coverage_deltas: HashMap<Uuid, Vec<CoverageLogDeltaData>>,
    config: HashMap<String, String>,
    transaction_count: u64,

    /// File content storage (path -> encrypted content)
    file_content: HashMap<String, Vec<u8>>,
    /// Typed file metadata storage
    typed_file_metadata: HashMap<String, crate::file::FileMetadata>,
}

impl MockStorage {
    /// Create new mock storage instance
    pub fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(MockStorageData::default())),
        }
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

    /// Get current data size for testing
    pub async fn data_size(&self) -> usize {
        let data = self.data.read().await;
        data.identity_keys.len()
            + data.epoch_states.len()
            + data.file_metadata.len()
            + data.file_content.len()
            + data.typed_file_metadata.len()
    }

    /// Clear all data
    pub async fn clear(&self) {
        let mut data = self.data.write().await;
        *data = MockStorageData::default();
    }
}

#[async_trait]
impl Storage for MockStorage {
    async fn store_identity_key(
        &self,
        device_id: &str,
        identity_key: &[u8],
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.identity_keys
            .insert(device_id.to_string(), identity_key.to_vec());
        Ok(())
    }

    async fn load_identity_key(&self, device_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let data = self.data.read().await;
        Ok(data.identity_keys.get(device_id).cloned())
    }

    async fn store_epoch_state_data(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.epoch_states.insert(epoch_id, state.clone());
        Ok(())
    }

    async fn load_epoch_state_data(
        &self,
        epoch_id: u64,
    ) -> Result<Option<EpochStateData>, StorageError> {
        let data = self.data.read().await;
        Ok(data.epoch_states.get(&epoch_id).cloned())
    }

    async fn list_epochs(&self) -> Result<Vec<u64>, StorageError> {
        let data = self.data.read().await;
        let mut epochs: Vec<u64> = data.epoch_states.keys().copied().collect();
        epochs.sort();
        Ok(epochs)
    }

    async fn get_current_epoch_id(&self) -> Result<u64, StorageError> {
        let data = self.data.read().await;

        // Get the highest epoch ID as current
        data.epoch_states
            .keys()
            .max()
            .copied()
            .ok_or(StorageError::NotFound("No epochs found".to_string()))
    }

    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_metadata
            .insert(file_path.to_string(), metadata.clone());
        Ok(())
    }

    async fn load_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<FileMetadataData>, StorageError> {
        let data = self.data.read().await;
        Ok(data.file_metadata.get(file_path).cloned())
    }

    async fn store_file_metadata_batch(
        &self,
        metadata_batch: &HashMap<String, FileMetadataData>,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        for (path, metadata) in metadata_batch {
            data.file_metadata.insert(path.clone(), metadata.clone());
        }
        Ok(())
    }

    async fn list_files(&self, prefix: Option<&str>) -> Result<Vec<String>, StorageError> {
        let data = self.data.read().await;
        let mut files: Vec<String> = match prefix {
            Some(prefix) => data
                .file_metadata
                .keys()
                .filter(|path| path.starts_with(prefix))
                .cloned()
                .collect(),
            None => data.file_metadata.keys().cloned().collect(),
        };
        files.sort();
        Ok(files)
    }

    async fn store_file_index_entry(&self, entry: &FileIndexEntry) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_index.insert(entry.file_uuid, entry.clone());
        Ok(())
    }

    async fn store_file_index_entries(
        &self,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        for entry in entries {
            data.file_index.insert(entry.file_uuid, entry.clone());
        }
        Ok(())
    }

    async fn replace_file_index_entries_for_root(
        &self,
        root_id: Uuid,
        entries: &[FileIndexEntry],
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_index.retain(|_, entry| entry.root_id != root_id);
        for entry in entries {
            data.file_index.insert(entry.file_uuid, entry.clone());
        }
        Ok(())
    }

    async fn load_file_index_entry(
        &self,
        file_uuid: Uuid,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let data = self.data.read().await;
        Ok(data.file_index.get(&file_uuid).cloned())
    }

    async fn load_file_index_entry_by_root_path(
        &self,
        root_id: Uuid,
        relative_path: &str,
    ) -> Result<Option<FileIndexEntry>, StorageError> {
        let target = Self::normalize_file_index_path(relative_path);
        let data = self.data.read().await;
        Ok(data
            .file_index
            .values()
            .find(|entry| {
                entry.root_id == root_id
                    && Self::normalize_file_index_path(&entry.relative_path) == target
            })
            .cloned())
    }

    async fn list_file_index_entries_by_root(
        &self,
        root_id: Uuid,
    ) -> Result<Vec<FileIndexEntry>, StorageError> {
        let data = self.data.read().await;
        Ok(data
            .file_index
            .values()
            .filter(|entry| entry.root_id == root_id)
            .cloned()
            .collect())
    }

    async fn remove_file_index_entry(&self, file_uuid: Uuid) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_index.remove(&file_uuid);
        Ok(())
    }

    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        coverage_log: &CoverageLogData,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.coverage_log.insert(group_id, coverage_log.clone());
        Ok(())
    }

    async fn load_coverage_log(&self, group_id: Uuid) -> Result<CoverageLogData, StorageError> {
        let data = self.data.read().await;
        Ok(data
            .coverage_log
            .get(&group_id)
            .cloned()
            .unwrap_or_else(|| CoverageLogData {
                root_hash: [0u8; 32],
                tree_nodes: Vec::new(),
                file_epochs: HashMap::new(),
                sequence: 0,
                updated_at: chrono::Utc::now(),
                version: 1,
            }))
    }

    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.coverage_deltas
            .entry(group_id)
            .or_default()
            .push(delta.clone());
        Ok(())
    }

    async fn load_coverage_log_deltas(
        &self,
        group_id: Uuid,
        since_sequence: u64,
    ) -> Result<Vec<CoverageLogDeltaData>, StorageError> {
        let data = self.data.read().await;
        Ok(data
            .coverage_deltas
            .get(&group_id)
            .into_iter()
            .flatten()
            .filter(|delta| delta.sequence > since_sequence)
            .cloned()
            .collect())
    }

    async fn compact_coverage_log_deltas(
        &self,
        group_id: Uuid,
        up_to_sequence: u64,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        if let Some(deltas) = data.coverage_deltas.get_mut(&group_id) {
            deltas.retain(|delta| delta.sequence > up_to_sequence);
        }
        Ok(())
    }

    async fn coverage_log_journal_size(&self, group_id: Uuid) -> Result<Option<u64>, StorageError> {
        let data = self.data.read().await;
        let Some(deltas) = data.coverage_deltas.get(&group_id) else {
            return Ok(Some(0));
        };

        let mut size = 0u64;
        for delta in deltas {
            let mut line = serde_json::to_vec(delta).map_err(|err| {
                StorageError::Serialization(format!(
                    "failed to serialize coverage log delta: {}",
                    err
                ))
            })?;
            size = size.saturating_add(line.len() as u64);
            size = size.saturating_add(1); // newline
            line.clear();
        }

        Ok(Some(size))
    }

    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_content
            .insert(file_path.to_string(), content.to_vec());
        Ok(())
    }

    async fn get_file(&self, file_path: &str) -> Result<Option<Vec<u8>>, StorageError> {
        let data = self.data.read().await;
        Ok(data.file_content.get(file_path).cloned())
    }

    async fn get_file_metadata(
        &self,
        file_path: &str,
    ) -> Result<Option<crate::file::FileMetadata>, StorageError> {
        let data = self.data.read().await;
        Ok(data.typed_file_metadata.get(file_path).cloned())
    }

    async fn delete_file(&self, file_path: &str) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.file_content.remove(file_path);
        data.typed_file_metadata.remove(file_path);
        data.file_metadata.remove(file_path);
        Ok(())
    }

    async fn store_config(&self, key: &str, value: &str) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.config.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn load_config(&self, key: &str) -> Result<Option<String>, StorageError> {
        let data = self.data.read().await;
        Ok(data.config.get(key).cloned())
    }

    async fn delete_config(&self, key: &str) -> Result<(), StorageError> {
        let mut data = self.data.write().await;
        data.config.remove(key);
        Ok(())
    }

    async fn load_config_fresh(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.load_config(key).await
    }

    async fn begin_transaction(&self) -> Result<Box<dyn StorageTransaction>, StorageError> {
        let mut data = self.data.write().await;
        data.transaction_count += 1;
        drop(data);

        Ok(Box::new(MockTransaction {
            storage: self.data.clone(),
        }))
    }

    async fn get_stats(&self) -> Result<StorageStats, StorageError> {
        let data = self.data.read().await;
        Ok(StorageStats {
            total_size: 1024 * 1024, // 1 MB
            used_size: (data.identity_keys.len()
                + data.epoch_states.len()
                + data.file_metadata.len()) as u64
                * 1024,
            epoch_count: data.epoch_states.len() as u64,
            file_count: data.file_metadata.len() as u64,
            avg_latency_ms: 1.0,
            health: StorageHealth::Healthy,
            last_maintenance: chrono::Utc::now(),
        })
    }

    async fn maintenance(&self) -> Result<(), StorageError> {
        // Mock maintenance - nothing to do
        Ok(())
    }

    async fn create_backup(
        &self,
        _backup_path: &str,
        _encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        // Mock backup creation
        Ok(())
    }

    async fn restore_backup(
        &self,
        _backup_path: &str,
        _encryption_key: &[u8; 32],
    ) -> Result<(), StorageError> {
        // Mock backup restoration
        Ok(())
    }

    /// Store epoch state with direct EpochState type
    async fn store_epoch_state(
        &self,
        epoch_state: &crate::epoch::state::EpochState,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;

        // Convert EpochState to EpochStateData for storage
        let members: Vec<crate::storage::MemberData> = epoch_state
            .members
            .iter()
            .map(|(member_id, member)| {
                let member_id_array: [u8; 32] =
                    member_id.as_slice().try_into().unwrap_or([0u8; 32]); // Fallback if wrong size
                let public_key_array: [u8; 32] =
                    member.public_key.as_slice().try_into().unwrap_or([0u8; 32]); // Fallback if wrong size

                crate::storage::MemberData {
                    member_id: member_id_array,
                    public_key: public_key_array,
                    capabilities: crate::storage::CapabilityData {
                        can_read: member.capabilities.can_read,
                        can_write: member.capabilities.can_write,
                        can_invite: member.capabilities.can_invite,
                        can_rekey: member.capabilities.can_rekey,
                        can_remove: member.capabilities.can_remove,
                    },
                    joined_at: member.joined_at,
                }
            })
            .collect();

        let epoch_data = EpochStateData {
            epoch_id: epoch_state.epoch_id,
            encrypted_key: epoch_state.encryption_key.to_vec(),
            key_source: epoch_state.key_source,
            members,
            created_at: epoch_state.created_at,
            is_active: matches!(
                epoch_state.status,
                crate::epoch::state::EpochStatus::Active { .. }
            ),
            file_count: epoch_state.file_count,
            version: 1,
        };

        data.epoch_states.insert(epoch_state.epoch_id, epoch_data);
        Ok(())
    }

    /// Load epoch state with direct EpochState type
    async fn load_epoch_state(
        &self,
        epoch_id: u64,
    ) -> Result<crate::epoch::state::EpochState, StorageError> {
        let data = self.data.read().await;

        let epoch_data = data
            .epoch_states
            .get(&epoch_id)
            .ok_or_else(|| StorageError::NotFound(format!("Epoch {} not found", epoch_id)))?;

        // Convert EpochStateData back to EpochState
        let status = if epoch_data.is_active {
            crate::epoch::state::EpochStatus::Active {
                activated_at: epoch_data.created_at,
            }
        } else {
            crate::epoch::state::EpochStatus::Deprecated {
                deprecated_at: epoch_data.created_at,
                successor_epoch: epoch_id + 1,
            }
        };

        let mut members = HashMap::new();
        for member_data in &epoch_data.members {
            let member = crate::epoch::state::Member {
                member_id: member_data.member_id.to_vec(),
                public_key: member_data.public_key.to_vec(),
                status: crate::epoch::state::MemberStatus::Active,
                capabilities: crate::epoch::state::MemberCapabilities {
                    can_read: member_data.capabilities.can_read,
                    can_write: member_data.capabilities.can_write,
                    can_invite: member_data.capabilities.can_invite,
                    can_rekey: member_data.capabilities.can_rekey,
                    can_remove: member_data.capabilities.can_remove,
                    can_admin: false, // Default
                },
                joined_at: member_data.joined_at,
                updated_at: chrono::Utc::now(),
            };
            members.insert(member_data.member_id.to_vec(), member);
        }

        let encryption_key: [u8; 32] = epoch_data
            .encrypted_key
            .as_slice()
            .try_into()
            .map_err(|_| StorageError::InvalidData("Invalid encryption key length".to_string()))?;

        let epoch_state = crate::epoch::state::EpochState {
            epoch_id: epoch_data.epoch_id,
            encryption_key,
            key_source: epoch_data.key_source,
            members,
            status,
            created_at: epoch_data.created_at,
            updated_at: chrono::Utc::now(),
            file_count: epoch_data.file_count,
            metadata: Default::default(),
        };

        Ok(epoch_state)
    }

    /// List active epochs (non-deprecated)
    async fn list_active_epochs(
        &self,
    ) -> Result<Vec<crate::epoch::state::EpochState>, StorageError> {
        let data = self.data.read().await;
        let mut active_epochs = Vec::new();

        for (epoch_id, epoch_data) in &data.epoch_states {
            if epoch_data.is_active {
                if let Ok(epoch_state) = self.load_epoch_state(*epoch_id).await {
                    active_epochs.push(epoch_state);
                }
            }
        }

        active_epochs.sort_by_key(|e| e.epoch_id);
        Ok(active_epochs)
    }

    /// Store Welcome record for replay protection
    async fn store_welcome_record(
        &self,
        record: &crate::epoch::welcome::WelcomeRecord,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;

        // Store Welcome record in config with composite key
        let key = format!("welcome_{}_{}", record.epoch_id, record.recipient_device_id);
        let value = serde_json::to_string(record).map_err(|e| {
            StorageError::SerializationError(format!("Failed to serialize Welcome record: {}", e))
        })?;

        data.config.insert(key, value);
        Ok(())
    }

    /// Load Welcome record for replay protection
    async fn load_welcome_record(
        &self,
        epoch_id: u64,
        device_id: &str,
    ) -> Result<crate::epoch::welcome::WelcomeRecord, StorageError> {
        let data = self.data.read().await;

        let key = format!("welcome_{}_{}", epoch_id, device_id);
        let value = data.config.get(&key).ok_or_else(|| {
            StorageError::NotFound(format!(
                "Welcome record not found for epoch {} device {}",
                epoch_id, device_id
            ))
        })?;

        let record: crate::epoch::welcome::WelcomeRecord =
            serde_json::from_str(value).map_err(|e| {
                StorageError::DeserializationError(format!(
                    "Failed to deserialize Welcome record: {}",
                    e
                ))
            })?;

        Ok(record)
    }

    /// Store epoch keys for activation
    async fn store_epoch_keys(
        &self,
        epoch_id: u64,
        secrets: &hybridcipher_messages::welcome::EpochSecrets,
    ) -> Result<(), StorageError> {
        let mut data = self.data.write().await;

        // Store epoch secrets in config
        let key = format!("epoch_keys_{}", epoch_id);
        let value = serde_json::to_string(secrets).map_err(|e| {
            StorageError::SerializationError(format!("Failed to serialize epoch secrets: {}", e))
        })?;

        data.config.insert(key, value);
        Ok(())
    }
}

/// Mock transaction for testing atomic operations
struct MockTransaction {
    storage: Arc<RwLock<MockStorageData>>,
}

#[async_trait]
impl StorageTransaction for MockTransaction {
    async fn store_epoch_state(
        &self,
        epoch_id: u64,
        state: &EpochStateData,
    ) -> Result<(), StorageError> {
        // In a real implementation, this would be buffered until commit
        // For testing, we'll apply immediately
        let mut data = self.storage.write().await;
        data.epoch_states.insert(epoch_id, state.clone());
        Ok(())
    }

    async fn store_file_metadata(
        &self,
        file_path: &str,
        metadata: &FileMetadataData,
    ) -> Result<(), StorageError> {
        let mut data = self.storage.write().await;
        data.file_metadata
            .insert(file_path.to_string(), metadata.clone());
        Ok(())
    }

    async fn store_coverage_log(
        &self,
        group_id: Uuid,
        coverage_log: &CoverageLogData,
    ) -> Result<(), StorageError> {
        let mut data = self.storage.write().await;
        data.coverage_log.insert(group_id, coverage_log.clone());
        Ok(())
    }

    async fn append_coverage_log_delta(
        &self,
        group_id: Uuid,
        delta: &CoverageLogDeltaData,
    ) -> Result<(), StorageError> {
        let mut data = self.storage.write().await;
        data.coverage_deltas
            .entry(group_id)
            .or_default()
            .push(delta.clone());
        Ok(())
    }

    async fn store_file(&self, file_path: &str, content: &[u8]) -> Result<(), StorageError> {
        let mut data = self.storage.write().await;
        data.file_content
            .insert(file_path.to_string(), content.to_vec());
        Ok(())
    }

    async fn store_file_metadata_typed(
        &self,
        file_path: &str,
        metadata: &crate::file::FileMetadata,
    ) -> Result<(), StorageError> {
        let mut data = self.storage.write().await;
        data.typed_file_metadata
            .insert(file_path.to_string(), metadata.clone());
        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<(), StorageError> {
        // Mock commit - operations already applied
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> Result<(), StorageError> {
        // Mock rollback - would need to undo operations in real implementation
        Ok(())
    }
}

impl Default for MockStorage {
    fn default() -> Self {
        Self::new()
    }
}
