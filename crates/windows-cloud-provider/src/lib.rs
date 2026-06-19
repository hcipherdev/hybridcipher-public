use chrono::{DateTime, Utc};
use hybridcipher_provider_core::EncryptedInventory;
pub use hybridcipher_provider_core::{
    local_provider_bridge, ClientMountCrypto, LocalProviderBridge, LocalProviderClient,
    MountSafetyReason, MountSyncRuntimeStatus, ProviderBridge,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum CloudProviderError {
    #[error("Windows Cloud Files API is only supported on Windows")]
    UnsupportedPlatform,
    #[error(
        "Windows Cloud Files API host is scaffolded but native callbacks are not implemented yet"
    )]
    NativeCallbacksNotImplemented,
    #[error("invalid command line: {0}")]
    InvalidCommand(String),
    #[error("invalid provider path: {0}")]
    InvalidPath(String),
    #[error("placeholder identity for {path} is {length} bytes; Windows limit is {max} bytes")]
    IdentityTooLarge {
        path: String,
        length: usize,
        max: u32,
    },
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("provider-core error: {0}")]
    ProviderCore(#[from] hybridcipher_provider_core::ProviderCoreError),
    #[error("Cloud Files callback failed: {0}")]
    Callback(String),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[cfg(target_os = "windows")]
    #[error("Windows API error: {0}")]
    Windows(#[from] windows::core::Error),
}

pub type Result<T> = std::result::Result<T, CloudProviderError>;

fn parse_json_state_bytes<T: DeserializeOwned>(data: &[u8]) -> Result<(T, bool)> {
    match serde_json::from_slice(data) {
        Ok(value) => Ok((value, false)),
        Err(strict_error) => {
            let mut stream = serde_json::Deserializer::from_slice(data).into_iter::<T>();
            match stream.next() {
                Some(Ok(value)) => Ok((value, true)),
                Some(Err(_)) | None => Err(CloudProviderError::Serialization(strict_error)),
            }
        }
    }
}

fn write_json_file_pretty<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state.json");
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::new_v4()));
    fs::write(&temp_path, serde_json::to_vec_pretty(value)?)?;

    if path.exists() {
        fs::remove_file(path)?;
    }

    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.into());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHostConfig {
    pub user_config_dir: PathBuf,
    #[serde(default)]
    pub pipe_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudRootRegistration {
    pub root_id: Uuid,
    pub sync_root_path: PathBuf,
    pub encrypted_root: PathBuf,
    pub display_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderStatus {
    pub backend: &'static str,
    pub available: bool,
    pub native_callbacks_ready: bool,
    pub running_root_count: usize,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl CloudProviderStatus {
    pub fn scaffolded(available: bool, message: impl Into<String>) -> Self {
        Self::new(available, false, 0, Some(message.into()))
    }

    pub fn new(
        available: bool,
        native_callbacks_ready: bool,
        running_root_count: usize,
        message: Option<String>,
    ) -> Self {
        Self {
            backend: "windows-cloud-files",
            available,
            native_callbacks_ready,
            running_root_count,
            updated_at: Utc::now(),
            message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlaceholderSyncSummary {
    pub root_id: Uuid,
    pub requested_count: usize,
    pub processed_count: u32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DehydrateRootSummary {
    pub sync_root_path: PathBuf,
    pub attempted_count: usize,
    pub dehydrated_count: usize,
    pub failed_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub failures: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CloudMutationKind {
    Writeback,
    Delete,
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMutationRecord {
    pub id: Uuid,
    pub kind: CloudMutationKind,
    pub root_id: Uuid,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<hybridcipher_provider_core::FileIdentityV1>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl CloudMutationRecord {
    fn new(
        kind: CloudMutationKind,
        root_id: Uuid,
        relative_path: impl Into<String>,
        identity: Option<hybridcipher_provider_core::FileIdentityV1>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            kind,
            root_id,
            relative_path: relative_path.into(),
            target_relative_path: None,
            plaintext_path: None,
            target_plaintext_path: None,
            identity,
            attempts: 0,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudMutationJournal {
    pub root_id: Uuid,
    #[serde(default)]
    pub records: Vec<CloudMutationRecord>,
    pub updated_at: DateTime<Utc>,
}

impl CloudMutationJournal {
    fn empty(root_id: Uuid) -> Self {
        Self {
            root_id,
            records: Vec::new(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct CloudRuntimePaths {
    status_path: PathBuf,
    journal_path: PathBuf,
    cache_dir: PathBuf,
}

type BridgeFactory = Arc<dyn Fn(&CloudRootRegistration) -> Arc<dyn ProviderBridge> + Send + Sync>;

#[derive(Clone)]
pub struct CloudProviderHost {
    config: ProviderHostConfig,
    connections: Arc<Mutex<HashMap<Uuid, CloudRootConnection>>>,
    bridge_factory: Option<BridgeFactory>,
}

pub struct CloudRootConnection {
    inner: platform::ConnectedCloudRoot,
}

impl CloudRootConnection {
    pub fn root_id(&self) -> Uuid {
        self.inner.root_id()
    }

    pub fn sync_root_path(&self) -> &Path {
        self.inner.sync_root_path()
    }
}

impl CloudProviderHost {
    pub fn new(config: ProviderHostConfig) -> Self {
        Self {
            config,
            connections: Arc::new(Mutex::new(HashMap::new())),
            bridge_factory: None,
        }
    }

    pub fn with_bridge_factory(config: ProviderHostConfig, bridge_factory: BridgeFactory) -> Self {
        Self {
            config,
            connections: Arc::new(Mutex::new(HashMap::new())),
            bridge_factory: Some(bridge_factory),
        }
    }

    pub fn config(&self) -> &ProviderHostConfig {
        &self.config
    }

    pub fn status(&self) -> CloudProviderStatus {
        let mut status = platform::status();
        status.running_root_count = self.running_root_count();
        status
    }

    pub fn register_root(&self, registration: &CloudRootRegistration) -> Result<()> {
        platform::register_root(registration)?;
        self.save_registration(registration)?;
        Ok(())
    }

    pub fn unregister_root_path(&self, sync_root_path: &Path) -> Result<()> {
        platform::unregister_root(sync_root_path)
    }

    pub fn sync_placeholders(
        &self,
        registration: &CloudRootRegistration,
    ) -> Result<PlaceholderSyncSummary> {
        let entries =
            EncryptedInventory::new(registration.root_id, &registration.encrypted_root).scan()?;
        let processed_count =
            platform::create_placeholders(&registration.sync_root_path, &entries)?;
        if processed_count as usize != entries.len() {
            return Err(CloudProviderError::Callback(format!(
                "Cloud Files placeholder sync only confirmed {} of {} inventory entries",
                processed_count,
                entries.len()
            )));
        }
        Ok(PlaceholderSyncSummary {
            root_id: registration.root_id,
            requested_count: entries.len(),
            processed_count,
            updated_at: Utc::now(),
        })
    }

    pub async fn connect_root(
        &self,
        registration: &CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
    ) -> Result<CloudRootConnection> {
        let runtime_paths = self.runtime_paths(registration.root_id)?;
        self.replay_pending_mutations(registration, bridge.clone(), &runtime_paths)
            .await?;
        let entries = bridge
            .inventory(registration.root_id, &registration.encrypted_root)
            .await?;
        self.write_runtime_status(registration.root_id, &runtime_paths, None)?;
        let inner = platform::connect_root(registration, bridge, entries, runtime_paths)?;
        Ok(CloudRootConnection { inner })
    }

    pub async fn start_root_with_bridge(
        &self,
        root_id: Uuid,
        bridge: Arc<dyn ProviderBridge>,
    ) -> Result<()> {
        if self.is_root_running(root_id) {
            return Ok(());
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let connection = self.connect_root(&registration, bridge).await?;
        self.connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .insert(root_id, connection);
        Ok(())
    }

    pub async fn start_root(&self, root_id: Uuid) -> Result<()> {
        if self.is_root_running(root_id) {
            return Ok(());
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            ))
        })?;
        let Some(factory) = &self.bridge_factory else {
            return Err(CloudProviderError::Callback(
                "start-root requires an in-process ProviderBridge; use start_root_with_bridge from the CLI/Tauri host or create the host with a bridge factory".to_string(),
            ));
        };
        self.start_root_with_bridge(root_id, factory(&registration))
            .await
    }

    pub fn stop_root(&self, _root_id: Uuid) -> Result<()> {
        let removed = self
            .connections
            .lock()
            .map_err(|_| CloudProviderError::Callback("connection registry lock poisoned".into()))?
            .remove(&_root_id);
        if removed.is_some() {
            Ok(())
        } else {
            Err(CloudProviderError::Callback(format!(
                "Cloud Files root {_root_id} is not running"
            )))
        }
    }

    pub fn dehydrate_root_path(&self, sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        platform::dehydrate_root(sync_root_path)
    }

    pub async fn serve_ipc(&self) -> Result<()> {
        ipc::serve(self.clone()).await
    }

    pub fn reset_root(&self, root_id: Uuid) -> Result<()> {
        let Some(registration) = self.load_registration(root_id)? else {
            return Err(CloudProviderError::InvalidPath(format!(
                "no Cloud Files registration state found for root {root_id}"
            )));
        };
        platform::unregister_root(&registration.sync_root_path)?;
        self.remove_registration(root_id)?;
        Ok(())
    }

    pub fn runtime_status_path(&self, root_id: Uuid) -> Result<PathBuf> {
        Ok(self.runtime_paths(root_id)?.status_path)
    }

    pub fn mutation_journal_path(&self, root_id: Uuid) -> Result<PathBuf> {
        Ok(self.runtime_paths(root_id)?.journal_path)
    }

    pub fn read_runtime_status(&self, root_id: Uuid) -> Result<MountSyncRuntimeStatus> {
        let paths = self.runtime_paths(root_id)?;
        if !paths.status_path.exists() {
            return Ok(Self::status_from_journal(
                root_id,
                &self.read_journal_from_path(root_id, &paths.journal_path)?,
                None,
            ));
        }
        let data = fs::read(&paths.status_path)?;
        let (status, repaired) = parse_json_state_bytes(&data)?;
        if repaired {
            tracing::warn!(
                "Recovered Cloud Files runtime status with trailing JSON at {}; rewriting clean state",
                paths.status_path.display()
            );
            write_json_file_pretty(&paths.status_path, &status)?;
        }
        Ok(status)
    }

    pub fn unsafe_pending_mutation_count(&self, root_id: Uuid) -> Result<usize> {
        let paths = self.runtime_paths(root_id)?;
        Ok(self
            .read_journal_from_path(root_id, &paths.journal_path)?
            .records
            .len())
    }

    fn runtime_paths(&self, root_id: Uuid) -> Result<CloudRuntimePaths> {
        let user_config_dir = &self.config.user_config_dir;
        if user_config_dir.as_os_str().is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "user_config_dir is required for Cloud Files runtime state".to_string(),
            ));
        }
        let state_dir = user_config_dir.join("mount_states");
        fs::create_dir_all(&state_dir)?;
        Ok(CloudRuntimePaths {
            status_path: state_dir.join(format!("mount_sync_status_{root_id}.json")),
            journal_path: state_dir.join(format!("cloud_mutations_{root_id}.json")),
            cache_dir: state_dir.join(format!("cloud_cache_{root_id}")),
        })
    }

    fn read_journal_from_path(
        &self,
        root_id: Uuid,
        journal_path: &Path,
    ) -> Result<CloudMutationJournal> {
        if !journal_path.exists() {
            return Ok(CloudMutationJournal::empty(root_id));
        }
        let data = fs::read(journal_path)?;
        let (journal, repaired) = parse_json_state_bytes(&data)?;
        if repaired {
            tracing::warn!(
                "Recovered Cloud Files mutation journal with trailing JSON at {}; rewriting clean state",
                journal_path.display()
            );
            write_json_file_pretty(journal_path, &journal)?;
        }
        Ok(journal)
    }

    fn write_journal_to_path(
        &self,
        journal_path: &Path,
        journal: &CloudMutationJournal,
    ) -> Result<()> {
        write_json_file_pretty(journal_path, journal)
    }

    async fn replay_pending_mutations(
        &self,
        registration: &CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
        paths: &CloudRuntimePaths,
    ) -> Result<()> {
        let mut journal = self.read_journal_from_path(registration.root_id, &paths.journal_path)?;
        if journal.records.is_empty() {
            return Ok(());
        }

        let mut retained = Vec::new();
        for mut record in journal.records.into_iter() {
            let result = match record.kind {
                CloudMutationKind::Writeback => match record.plaintext_path.as_ref() {
                    None => Err(CloudProviderError::Callback(
                        "pending writeback is missing plaintext_path".to_string(),
                    )),
                    Some(path) if !path.exists() => Err(CloudProviderError::Callback(format!(
                        "pending writeback source {} no longer exists",
                        path.display()
                    ))),
                    Some(path) => bridge
                        .writeback_file(
                            registration.root_id,
                            &registration.encrypted_root,
                            &record.relative_path,
                            path,
                            record.identity.as_ref(),
                        )
                        .await
                        .map(|_| ())
                        .map_err(CloudProviderError::from),
                },
                CloudMutationKind::Delete => match record.identity.as_ref() {
                    None => Err(CloudProviderError::Callback(
                        "pending delete is missing identity".to_string(),
                    )),
                    Some(identity) => bridge
                        .delete_entry(&registration.encrypted_root, identity)
                        .await
                        .map_err(CloudProviderError::from),
                },
                CloudMutationKind::Rename => match record.identity.as_ref() {
                    None => Err(CloudProviderError::Callback(
                        "pending rename is missing identity".to_string(),
                    )),
                    Some(identity) => match record.target_relative_path.as_deref() {
                        None => Err(CloudProviderError::Callback(
                            "pending rename is missing target_relative_path".to_string(),
                        )),
                        Some(target_relative) => bridge
                            .rename_entry(
                                registration.root_id,
                                &registration.encrypted_root,
                                identity,
                                target_relative,
                                record.target_plaintext_path.as_deref(),
                            )
                            .await
                            .map(|_| ())
                            .map_err(CloudProviderError::from),
                    },
                },
            };

            if let Err(err) = result {
                record.attempts = record.attempts.saturating_add(1);
                record.last_error = Some(err.to_string());
                record.updated_at = Utc::now();
                retained.push(record);
            }
        }

        journal.records = retained;
        journal.updated_at = Utc::now();
        self.write_journal_to_path(&paths.journal_path, &journal)?;
        self.write_runtime_status(registration.root_id, paths, None)?;
        Ok(())
    }

    fn write_runtime_status(
        &self,
        root_id: Uuid,
        paths: &CloudRuntimePaths,
        last_error: Option<String>,
    ) -> Result<()> {
        let journal = self.read_journal_from_path(root_id, &paths.journal_path)?;
        let status = Self::status_from_journal(root_id, &journal, last_error);
        write_json_file_pretty(&paths.status_path, &status)
    }

    fn status_from_journal(
        _root_id: Uuid,
        journal: &CloudMutationJournal,
        last_error: Option<String>,
    ) -> MountSyncRuntimeStatus {
        let pending = journal.records.len();
        let sample_paths = journal
            .records
            .iter()
            .take(3)
            .map(|record| record.relative_path.clone())
            .collect::<Vec<_>>();
        let oldest_age_ms = journal
            .records
            .iter()
            .map(|record| {
                Utc::now()
                    .signed_duration_since(record.created_at)
                    .num_milliseconds()
                    .max(0) as u64
            })
            .max();
        let last_error = last_error.or_else(|| {
            journal
                .records
                .iter()
                .rev()
                .find_map(|record| record.last_error.clone())
        });
        let unsafe_reasons = if pending == 0 {
            Vec::new()
        } else {
            vec![MountSafetyReason::PendingWriteback {
                count: pending,
                oldest_age_ms: oldest_age_ms.unwrap_or(0),
                sample_paths: sample_paths.clone(),
                last_error: last_error.clone(),
            }]
        };

        MountSyncRuntimeStatus {
            safe_to_unmount: pending == 0,
            pending_writeback_count: pending,
            pending_writeback_oldest_age_ms: oldest_age_ms,
            pending_writeback_paths: sample_paths,
            unsafe_reasons,
            last_error,
            updated_at: Utc::now(),
            ..MountSyncRuntimeStatus::default()
        }
    }

    fn root_state_dir(&self) -> Option<PathBuf> {
        if self.config.user_config_dir.as_os_str().is_empty() {
            return None;
        }
        Some(
            self.config
                .user_config_dir
                .join("cloud-files")
                .join("roots"),
        )
    }

    fn root_state_path(&self, root_id: Uuid) -> Option<PathBuf> {
        self.root_state_dir()
            .map(|dir| dir.join(format!("{root_id}.json")))
    }

    fn save_registration(&self, registration: &CloudRootRegistration) -> Result<()> {
        let Some(path) = self.root_state_path(registration.root_id) else {
            return Ok(());
        };
        write_json_file_pretty(&path, registration)
    }

    fn load_registration(&self, root_id: Uuid) -> Result<Option<CloudRootRegistration>> {
        let Some(path) = self.root_state_path(root_id) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(&path)?;
        let (registration, repaired) = parse_json_state_bytes(&data)?;
        if repaired {
            tracing::warn!(
                "Recovered Cloud Files registration with trailing JSON at {}; rewriting clean state",
                path.display()
            );
            write_json_file_pretty(&path, &registration)?;
        }
        Ok(Some(registration))
    }

    fn remove_registration(&self, root_id: Uuid) -> Result<()> {
        let Some(path) = self.root_state_path(root_id) else {
            return Ok(());
        };
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn running_root_count(&self) -> usize {
        self.connections
            .lock()
            .map(|connections| connections.len())
            .unwrap_or_default()
    }

    fn is_root_running(&self, root_id: Uuid) -> bool {
        self.connections
            .lock()
            .map(|connections| connections.contains_key(&root_id))
            .unwrap_or(false)
    }
}

pub fn default_pipe_name() -> &'static str {
    r"\\.\pipe\hybridcipher-cloud-provider"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum ProviderIpcRequest {
    Status,
    RegisterRoot {
        registration: CloudRootRegistration,
        #[serde(default)]
        sync_placeholders: bool,
    },
    SyncPlaceholders {
        registration: CloudRootRegistration,
    },
    UnregisterRoot {
        sync_root_path: PathBuf,
    },
    ResetRoot {
        root_id: Uuid,
    },
    StartRoot {
        root_id: Uuid,
    },
    StopRoot {
        root_id: Uuid,
    },
    DehydrateRoot {
        sync_root_path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ProviderIpcResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<CloudProviderStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_summary: Option<PlaceholderSyncSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dehydrate_summary: Option<DehydrateRootSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProviderIpcResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            status: None,
            placeholder_summary: None,
            dehydrate_summary: None,
            message: None,
        }
    }

    fn error(err: impl ToString) -> Self {
        Self {
            ok: false,
            status: None,
            placeholder_summary: None,
            dehydrate_summary: None,
            message: Some(err.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_provider_core::ProviderEntryKind;

    fn test_identity(root_id: Uuid) -> hybridcipher_provider_core::FileIdentityV1 {
        hybridcipher_provider_core::FileIdentityV1 {
            version: 1,
            root_id,
            kind: ProviderEntryKind::File,
            relative_path: "docs/report.txt".to_string(),
            path_hash_hex: "abc123".to_string(),
            file_id: Some("file-1".to_string()),
            epoch_id: Some(7),
        }
    }

    #[test]
    fn mutation_journal_round_trips_and_blocks_safe_unmount() {
        let root_id = Uuid::new_v4();
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.plaintext_path = Some(PathBuf::from(r"C:\cache\report.txt"));
        record.last_error = Some("writeback retry pending".to_string());

        let mut journal = CloudMutationJournal::empty(root_id);
        journal.records.push(record);

        let encoded = serde_json::to_vec(&journal).expect("serialize journal");
        let decoded: CloudMutationJournal =
            serde_json::from_slice(&encoded).expect("deserialize journal");

        assert_eq!(decoded.root_id, root_id);
        assert_eq!(decoded.records.len(), 1);
        assert_eq!(decoded.records[0].kind, CloudMutationKind::Writeback);

        let status = CloudProviderHost::status_from_journal(root_id, &decoded, None);
        assert!(!status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 1);
        assert_eq!(status.pending_writeback_paths, vec!["docs/report.txt"]);
        assert_eq!(
            status.last_error.as_deref(),
            Some("writeback retry pending")
        );
        assert!(matches!(
            status.unsafe_reasons.first(),
            Some(MountSafetyReason::PendingWriteback { count: 1, .. })
        ));
    }

    #[test]
    fn state_parser_recovers_first_json_value_when_file_has_trailing_json() {
        let root_id = Uuid::new_v4();
        let mut first = CloudMutationJournal::empty(root_id);
        first.records.push(CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        ));
        let second = CloudMutationJournal::empty(root_id);

        let mut corrupted = serde_json::to_vec_pretty(&first).expect("serialize first");
        corrupted.extend_from_slice(&serde_json::to_vec_pretty(&second).expect("serialize second"));

        let strict_error = serde_json::from_slice::<CloudMutationJournal>(&corrupted)
            .expect_err("strict parser should reject trailing JSON");
        assert!(
            strict_error.to_string().contains("trailing characters"),
            "unexpected strict error: {strict_error}"
        );

        let (recovered, repaired) =
            parse_json_state_bytes::<CloudMutationJournal>(&corrupted).expect("recover journal");
        assert!(repaired);
        assert_eq!(recovered.root_id, root_id);
        assert_eq!(recovered.records.len(), 1);
        assert_eq!(recovered.records[0].relative_path, "docs/report.txt");
    }

    #[test]
    fn empty_mutation_journal_is_safe_to_unmount() {
        let root_id = Uuid::new_v4();
        let journal = CloudMutationJournal::empty(root_id);

        let status = CloudProviderHost::status_from_journal(root_id, &journal, None);

        assert!(status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 0);
        assert!(status.unsafe_reasons.is_empty());
    }
}

mod ipc {
    use super::{CloudProviderHost, ProviderIpcRequest, ProviderIpcResponse, Result};

    #[cfg(target_os = "windows")]
    pub async fn serve(host: CloudProviderHost) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

        let pipe_name = host
            .config()
            .pipe_name
            .clone()
            .unwrap_or_else(|| super::default_pipe_name().to_string());

        loop {
            let mut pipe = ServerOptions::new()
                .pipe_mode(PipeMode::Message)
                .create(&pipe_name)?;
            pipe.connect().await?;

            let mut request = String::new();
            {
                let mut reader = BufReader::new(&mut pipe);
                reader.read_line(&mut request).await?;
            }
            let response = handle_request(&host, request.trim()).await;
            let mut response_bytes = serde_json::to_vec(&response)?;
            response_bytes.push(b'\n');
            pipe.write_all(&response_bytes).await?;
            pipe.flush().await?;
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub async fn serve(_host: CloudProviderHost) -> Result<()> {
        Err(super::CloudProviderError::UnsupportedPlatform)
    }

    async fn handle_request(host: &CloudProviderHost, request: &str) -> ProviderIpcResponse {
        let parsed = match serde_json::from_str::<ProviderIpcRequest>(request) {
            Ok(parsed) => parsed,
            Err(err) => return ProviderIpcResponse::error(err),
        };

        match parsed {
            ProviderIpcRequest::Status => {
                let mut response = ProviderIpcResponse::ok();
                response.status = Some(host.status());
                response
            }
            ProviderIpcRequest::RegisterRoot {
                registration,
                sync_placeholders,
            } => match host.register_root(&registration) {
                Ok(()) if sync_placeholders => match host.sync_placeholders(&registration) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.placeholder_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                },
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::SyncPlaceholders { registration } => {
                match host.sync_placeholders(&registration) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.placeholder_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
            ProviderIpcRequest::UnregisterRoot { sync_root_path } => {
                match host.unregister_root_path(&sync_root_path) {
                    Ok(()) => ProviderIpcResponse::ok(),
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
            ProviderIpcRequest::ResetRoot { root_id } => match host.reset_root(root_id) {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::StartRoot { root_id } => match host.start_root(root_id).await {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::StopRoot { root_id } => match host.stop_root(root_id) {
                Ok(()) => ProviderIpcResponse::ok(),
                Err(err) => ProviderIpcResponse::error(err),
            },
            ProviderIpcRequest::DehydrateRoot { sync_root_path } => {
                match host.dehydrate_root_path(&sync_root_path) {
                    Ok(summary) => {
                        let mut response = ProviderIpcResponse::ok();
                        response.dehydrate_summary = Some(summary);
                        response
                    }
                    Err(err) => ProviderIpcResponse::error(err),
                }
            }
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    use super::{
        CloudMutationJournal, CloudMutationKind, CloudMutationRecord, CloudProviderError,
        CloudProviderHost, CloudProviderStatus, CloudRootRegistration, CloudRuntimePaths,
        DehydrateRootSummary, Result,
    };
    use chrono::Utc;
    use hybridcipher_provider_core::{
        normalize_relative_path, FileIdentityV1, ProviderBridge, ProviderEntry, ProviderEntryKind,
    };
    use std::collections::HashMap;
    use std::{
        ffi::c_void,
        ffi::OsStr,
        fs::{self, File},
        io::{Read, Seek, SeekFrom},
        mem::size_of,
        os::windows::ffi::OsStrExt,
        os::windows::fs::MetadataExt,
        path::{Component, Path, PathBuf},
        ptr::null,
        sync::{Arc, Mutex},
    };
    use uuid::Uuid;
    use windows::core::{GUID, HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        FreeLibrary, ERROR_ALREADY_EXISTS, NTSTATUS, STATUS_CLOUD_FILE_INVALID_REQUEST,
        STATUS_CLOUD_FILE_UNSUCCESSFUL, STATUS_SUCCESS, WIN32_ERROR,
    };
    use windows::Win32::Storage::CloudFilters::{
        CfCloseHandle, CfConnectSyncRoot, CfCreatePlaceholders, CfDehydratePlaceholder,
        CfDisconnectSyncRoot, CfExecute, CfOpenFileWithOplock, CfRegisterSyncRoot,
        CfUnregisterSyncRoot, CfUpdateSyncProviderStatus, CF_CALLBACK_INFO, CF_CALLBACK_PARAMETERS,
        CF_CALLBACK_REGISTRATION, CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
        CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_FETCH_DATA,
        CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS, CF_CALLBACK_TYPE_NONE,
        CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE, CF_CALLBACK_TYPE_NOTIFY_DELETE,
        CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION, CF_CALLBACK_TYPE_NOTIFY_RENAME,
        CF_CALLBACK_TYPE_VALIDATE_DATA, CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
        CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH, CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
        CF_CREATE_FLAG_NONE, CF_DEHYDRATE_FLAG_BACKGROUND, CF_FS_METADATA, CF_HARDLINK_POLICY_NONE,
        CF_HYDRATION_POLICY, CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED,
        CF_HYDRATION_POLICY_PROGRESSIVE, CF_INSYNC_POLICY_TRACK_ALL, CF_OPEN_FILE_FLAG_FOREGROUND,
        CF_OPEN_FILE_FLAG_WRITE_ACCESS, CF_OPERATION_ACK_DATA_FLAG_NONE,
        CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE, CF_OPERATION_ACK_DELETE_FLAG_NONE,
        CF_OPERATION_ACK_RENAME_FLAG_NONE, CF_OPERATION_INFO, CF_OPERATION_PARAMETERS,
        CF_OPERATION_PARAMETERS_0, CF_OPERATION_PARAMETERS_0_0, CF_OPERATION_PARAMETERS_0_2,
        CF_OPERATION_PARAMETERS_0_4, CF_OPERATION_PARAMETERS_0_5, CF_OPERATION_PARAMETERS_0_6,
        CF_OPERATION_PARAMETERS_0_7, CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE, CF_OPERATION_TYPE_ACK_DATA,
        CF_OPERATION_TYPE_ACK_DEHYDRATE, CF_OPERATION_TYPE_ACK_DELETE,
        CF_OPERATION_TYPE_ACK_RENAME, CF_OPERATION_TYPE_TRANSFER_DATA,
        CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS, CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE, CF_PLACEHOLDER_CREATE_INFO,
        CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT, CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH,
        CF_POPULATION_POLICY, CF_POPULATION_POLICY_FULL, CF_POPULATION_POLICY_MODIFIER_NONE,
        CF_PROVIDER_STATUS_IDLE, CF_PROVIDER_STATUS_POPULATE_CONTENT,
        CF_PROVIDER_STATUS_TERMINATED, CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT,
        CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT, CF_REGISTER_FLAG_UPDATE, CF_SYNC_POLICIES,
        CF_SYNC_REGISTRATION,
    };
    use windows::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO,
    };
    use windows::Win32::System::LibraryLoader::LoadLibraryW;

    const HYBRIDCIPHER_PROVIDER_ID: GUID = GUID::from_u128(0x9c9eb75e_7e0b_47f4_8f33_546c1a3a38c4);
    const WINDOWS_TICKS_PER_SECOND: i64 = 10_000_000;
    const SECONDS_FROM_1601_TO_UNIX_EPOCH: i64 = 11_644_473_600;

    pub fn status() -> CloudProviderStatus {
        match cldapi_available() {
            Ok(true) => CloudProviderStatus::new(
                true,
                true,
                0,
                Some(
                    "CldApi.dll is available; sync-root registration, placeholder creation, hydration callbacks, and local mutation callbacks are available."
                        .to_string(),
                ),
            ),
            Ok(false) => CloudProviderStatus::scaffolded(false, "CldApi.dll is not available."),
            Err(err) => {
                CloudProviderStatus::scaffolded(false, format!("Failed to probe CldApi.dll: {err}"))
            }
        }
    }

    pub fn register_root(registration: &CloudRootRegistration) -> Result<()> {
        ensure_absolute_or_create_root(&registration.sync_root_path)?;
        ensure_existing_dir(&registration.encrypted_root, "encrypted root")?;

        let sync_root_path = to_wide(registration.sync_root_path.as_os_str());
        let provider_name = to_wide(OsStr::new(&registration.display_name));
        let provider_version = to_wide(OsStr::new(env!("CARGO_PKG_VERSION")));
        let sync_root_identity = registration.root_id.as_bytes().to_vec();
        let file_identity = registration.root_id.as_bytes().to_vec();

        let sync_registration = CF_SYNC_REGISTRATION {
            StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
            ProviderName: PCWSTR(provider_name.as_ptr()),
            ProviderVersion: PCWSTR(provider_version.as_ptr()),
            SyncRootIdentity: sync_root_identity.as_ptr().cast(),
            SyncRootIdentityLength: sync_root_identity.len() as u32,
            FileIdentity: file_identity.as_ptr().cast(),
            FileIdentityLength: file_identity.len() as u32,
            ProviderId: HYBRIDCIPHER_PROVIDER_ID,
        };

        let policies = CF_SYNC_POLICIES {
            StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
            Hydration: CF_HYDRATION_POLICY {
                Primary: CF_HYDRATION_POLICY_PROGRESSIVE,
                Modifier: CF_HYDRATION_POLICY_MODIFIER_STREAMING_ALLOWED,
            },
            Population: CF_POPULATION_POLICY {
                Primary: CF_POPULATION_POLICY_FULL,
                Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
            },
            InSync: CF_INSYNC_POLICY_TRACK_ALL,
            HardLink: CF_HARDLINK_POLICY_NONE,
            PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
        };

        let flags = CF_REGISTER_FLAG_UPDATE
            | CF_REGISTER_FLAG_MARK_IN_SYNC_ON_ROOT
            | CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT;

        let result = unsafe {
            CfRegisterSyncRoot(
                PCWSTR(sync_root_path.as_ptr()),
                &sync_registration,
                &policies,
                flags,
            )
        };
        if let Err(err) = result {
            if windows_error_matches(&err, ERROR_ALREADY_EXISTS) {
                tracing::info!(
                    "Cloud Files sync root already exists at {}; reusing existing registration",
                    registration.sync_root_path.display()
                );
            } else {
                return Err(err.into());
            }
        }
        Ok(())
    }

    pub fn unregister_root(sync_root_path: &Path) -> Result<()> {
        ensure_absolute_path(sync_root_path, "sync root")?;
        let sync_root_path = to_wide(sync_root_path.as_os_str());
        unsafe {
            CfUnregisterSyncRoot(PCWSTR(sync_root_path.as_ptr()))?;
        }
        Ok(())
    }

    pub fn create_placeholders(sync_root_path: &Path, entries: &[ProviderEntry]) -> Result<u32> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        if entries.is_empty() {
            return Ok(0);
        }

        let ordered_entries = ordered_placeholder_entries(entries);
        let mut processed_total = 0u32;
        for entry in ordered_entries {
            processed_total =
                processed_total.saturating_add(create_single_placeholder(sync_root_path, entry)?);
        }
        Ok(processed_total)
    }

    fn ordered_placeholder_entries(entries: &[ProviderEntry]) -> Vec<&ProviderEntry> {
        let mut ordered = entries.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            placeholder_kind_rank(left.kind)
                .cmp(&placeholder_kind_rank(right.kind))
                .then_with(|| {
                    path_depth(&left.relative_path).cmp(&path_depth(&right.relative_path))
                })
                .then_with(|| left.relative_path.cmp(&right.relative_path))
        });
        ordered
    }

    fn placeholder_kind_rank(kind: ProviderEntryKind) -> u8 {
        match kind {
            ProviderEntryKind::Directory => 0,
            ProviderEntryKind::File => 1,
        }
    }

    fn path_depth(path: &str) -> usize {
        path.replace('\\', "/")
            .split('/')
            .filter(|component| !component.is_empty())
            .count()
    }

    fn create_single_placeholder(sync_root_path: &Path, entry: &ProviderEntry) -> Result<u32> {
        let (base_path, relative_name, full_path, display_path) =
            placeholder_location(sync_root_path, entry)?;
        let base_path_wide = to_wide(base_path.as_os_str());
        let placeholder = OwnedPlaceholder::new(entry, relative_name, full_path, display_path)?;

        for attempt in 0..2 {
            let mut processed = 0u32;
            let mut single = [placeholder.info];
            let result = unsafe {
                CfCreatePlaceholders(
                    PCWSTR(base_path_wide.as_ptr()),
                    &mut single,
                    CF_CREATE_FLAG_NONE,
                    Some(&mut processed),
                )
            };
            match result {
                Ok(()) if processed > 0 => {
                    return inspect_placeholder_results(
                        std::slice::from_ref(&placeholder),
                        &single,
                    );
                }
                Ok(()) => {
                    return Err(CloudProviderError::Callback(format!(
                        "Cloud Files did not confirm placeholder creation for {}",
                        placeholder.relative_path()
                    )));
                }
                Err(err) if windows_error_matches(&err, ERROR_ALREADY_EXISTS) => {
                    if recover_existing_placeholder(&placeholder)? && attempt == 0 {
                        continue;
                    }
                    return Ok(1);
                }
                Err(err) => return Err(err.into()),
            }
        }

        Err(CloudProviderError::Callback(format!(
            "Cloud Files did not confirm placeholder creation for {}",
            placeholder.relative_path()
        )))
    }

    fn placeholder_location(
        sync_root_path: &Path,
        entry: &ProviderEntry,
    ) -> Result<(PathBuf, Vec<u16>, PathBuf, String)> {
        let relative_path = validate_relative_path(&entry.relative_path)?;
        let relative_path_buf = PathBuf::from(&relative_path);
        let relative_name = relative_path_buf
            .file_name()
            .ok_or_else(|| {
                CloudProviderError::InvalidPath(format!(
                    "placeholder relative path is missing a file name: {}",
                    entry.relative_path
                ))
            })
            .map(to_wide)?;
        let base_path = relative_path_buf
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(|parent| sync_root_path.join(parent))
            .unwrap_or_else(|| sync_root_path.to_path_buf());
        let full_path = sync_root_path.join(&relative_path_buf);
        Ok((base_path, relative_name, full_path, relative_path))
    }

    fn recover_existing_placeholder(placeholder: &OwnedPlaceholder) -> Result<bool> {
        let metadata = fs::symlink_metadata(&placeholder.full_path)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            tracing::debug!(
                "Cloud Files placeholder already exists for {}; preserving existing entry",
                placeholder.relative_path()
            );
            return Ok(false);
        }

        if placeholder.kind == ProviderEntryKind::Directory
            && metadata.is_dir()
            && directory_is_empty(&placeholder.full_path)?
        {
            tracing::debug!(
                "Removing empty non-placeholder directory before Cloud Files placeholder recreation: {}",
                placeholder.full_path.display()
            );
            fs::remove_dir(&placeholder.full_path)?;
            return Ok(true);
        }

        Err(CloudProviderError::InvalidPath(format!(
            "Cloud Files path already exists but is not a provider placeholder: {}. Unmount and reset the Cloud Files root before retrying.",
            placeholder.full_path.display()
        )))
    }

    fn directory_is_empty(path: &Path) -> Result<bool> {
        let mut entries = fs::read_dir(path)?;
        Ok(entries.next().transpose()?.is_none())
    }

    fn inspect_placeholder_results(
        requested: &[OwnedPlaceholder],
        results: &[CF_PLACEHOLDER_CREATE_INFO],
    ) -> Result<u32> {
        let mut confirmed_count = 0u32;
        for (placeholder, result) in requested.iter().zip(results.iter()) {
            if result.Result.is_ok() {
                confirmed_count = confirmed_count.saturating_add(1);
                continue;
            }

            if hresult_matches(result.Result, ERROR_ALREADY_EXISTS) {
                tracing::debug!(
                    "Cloud Files placeholder already exists for {}; preserving existing entry",
                    placeholder.relative_path()
                );
                confirmed_count = confirmed_count.saturating_add(1);
                continue;
            }

            return Err(CloudProviderError::Callback(format!(
                "failed to create Cloud Files placeholder for {}: {}",
                placeholder.relative_path(),
                windows::core::Error::from(result.Result)
            )));
        }
        Ok(confirmed_count)
    }

    pub fn dehydrate_root(sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        ensure_existing_dir(sync_root_path, "sync root")?;
        let mut summary = DehydrateRootSummary {
            sync_root_path: sync_root_path.to_path_buf(),
            attempted_count: 0,
            dehydrated_count: 0,
            failed_count: 0,
            failures: Vec::new(),
            updated_at: chrono::Utc::now(),
        };
        dehydrate_tree(sync_root_path, &mut summary)?;
        summary.updated_at = chrono::Utc::now();
        Ok(summary)
    }

    pub fn connect_root(
        registration: &CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
        entries: Vec<ProviderEntry>,
        runtime_paths: CloudRuntimePaths,
    ) -> Result<ConnectedCloudRoot> {
        ensure_existing_dir(&registration.sync_root_path, "sync root")?;
        ensure_existing_dir(&registration.encrypted_root, "encrypted root")?;

        let sync_root_path_wide = to_wide(registration.sync_root_path.as_os_str());
        let mut context = Box::new(CallbackContext::new(
            registration.clone(),
            bridge,
            entries,
            runtime_paths,
            tokio::runtime::Handle::current(),
        ));
        let context_ptr = context.as_mut() as *mut CallbackContext as *const c_void;
        let callback_table = callback_registrations();
        let connection_key = unsafe {
            CfConnectSyncRoot(
                PCWSTR(sync_root_path_wide.as_ptr()),
                callback_table.as_ptr(),
                Some(context_ptr),
                CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH
                    | CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO
                    | CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION,
            )?
        };
        unsafe {
            let _ = CfUpdateSyncProviderStatus(connection_key, CF_PROVIDER_STATUS_IDLE);
        }
        Ok(ConnectedCloudRoot {
            root_id: registration.root_id,
            sync_root_path: registration.sync_root_path.clone(),
            connection_key,
            _callback_table: callback_table,
            _context: context,
        })
    }

    fn dehydrate_tree(path: &Path, summary: &mut DehydrateRootSummary) -> Result<()> {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                dehydrate_tree(&path, summary)?;
                continue;
            }
            if !file_type.is_file() {
                continue;
            }

            summary.attempted_count = summary.attempted_count.saturating_add(1);
            match dehydrate_file(&path) {
                Ok(()) => {
                    summary.dehydrated_count = summary.dehydrated_count.saturating_add(1);
                }
                Err(err) => {
                    summary.failed_count = summary.failed_count.saturating_add(1);
                    summary.failures.push(format!("{}: {err}", path.display()));
                }
            }
        }
        Ok(())
    }

    fn dehydrate_file(path: &Path) -> Result<()> {
        let file_path = to_wide(path.as_os_str());
        unsafe {
            let handle = CfOpenFileWithOplock(
                PCWSTR(file_path.as_ptr()),
                CF_OPEN_FILE_FLAG_WRITE_ACCESS | CF_OPEN_FILE_FLAG_FOREGROUND,
            )?;
            let result = CfDehydratePlaceholder(handle, 0, -1, CF_DEHYDRATE_FLAG_BACKGROUND, None);
            CfCloseHandle(handle);
            result?;
        }
        Ok(())
    }

    fn cldapi_available() -> windows::core::Result<bool> {
        let dll_name = OsStr::new("CldApi.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        unsafe {
            match LoadLibraryW(PCWSTR(dll_name.as_ptr())) {
                Ok(module) => {
                    let _ = FreeLibrary(module);
                    Ok(true)
                }
                Err(err) => {
                    if err.code().is_ok() {
                        Ok(false)
                    } else {
                        Err(err)
                    }
                }
            }
        }
    }

    pub struct ConnectedCloudRoot {
        root_id: uuid::Uuid,
        sync_root_path: std::path::PathBuf,
        connection_key: windows::Win32::Storage::CloudFilters::CF_CONNECTION_KEY,
        _callback_table: Vec<CF_CALLBACK_REGISTRATION>,
        _context: Box<CallbackContext>,
    }

    impl ConnectedCloudRoot {
        pub fn root_id(&self) -> uuid::Uuid {
            self.root_id
        }

        pub fn sync_root_path(&self) -> &Path {
            &self.sync_root_path
        }
    }

    impl Drop for ConnectedCloudRoot {
        fn drop(&mut self) {
            unsafe {
                let _ =
                    CfUpdateSyncProviderStatus(self.connection_key, CF_PROVIDER_STATUS_TERMINATED);
                let _ = CfDisconnectSyncRoot(self.connection_key);
            }
        }
    }

    struct CallbackContext {
        registration: CloudRootRegistration,
        bridge: Arc<dyn ProviderBridge>,
        runtime_paths: CloudRuntimePaths,
        runtime: tokio::runtime::Handle,
        inventory_by_hash: Mutex<HashMap<String, ProviderEntry>>,
    }

    impl CallbackContext {
        fn new(
            registration: CloudRootRegistration,
            bridge: Arc<dyn ProviderBridge>,
            entries: Vec<ProviderEntry>,
            runtime_paths: CloudRuntimePaths,
            runtime: tokio::runtime::Handle,
        ) -> Self {
            let inventory_by_hash = entries
                .into_iter()
                .map(|entry| (entry.identity.path_hash_hex.clone(), entry))
                .collect();
            Self {
                registration,
                bridge,
                runtime_paths,
                runtime,
                inventory_by_hash: Mutex::new(inventory_by_hash),
            }
        }

        fn entry_for_identity(&self, identity: &FileIdentityV1) -> Result<ProviderEntry> {
            let inventory = self.inventory_by_hash.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory
                .get(&identity.path_hash_hex)
                .cloned()
                .ok_or_else(|| {
                    CloudProviderError::Callback(format!(
                        "no provider inventory entry for {}",
                        identity.relative_path
                    ))
                })
        }

        fn upsert_entry(&self, entry: ProviderEntry) -> Result<()> {
            let mut inventory = self.inventory_by_hash.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory.insert(entry.identity.path_hash_hex.clone(), entry);
            Ok(())
        }

        fn remove_identity(&self, identity: &FileIdentityV1) -> Result<()> {
            let mut inventory = self.inventory_by_hash.lock().map_err(|_| {
                CloudProviderError::Callback("provider inventory lock poisoned".to_string())
            })?;
            inventory.remove(&identity.path_hash_hex);
            Ok(())
        }

        fn cache_path_for_identity(&self, identity: &FileIdentityV1) -> PathBuf {
            self.runtime_paths
                .cache_dir
                .join(format!("{}.plain", identity.path_hash_hex))
        }

        fn remove_cache_for_identity(&self, identity: &FileIdentityV1) {
            let _ = fs::remove_file(self.cache_path_for_identity(identity));
        }

        fn read_journal(&self) -> Result<CloudMutationJournal> {
            if !self.runtime_paths.journal_path.exists() {
                return Ok(CloudMutationJournal::empty(self.registration.root_id));
            }
            let data = fs::read(&self.runtime_paths.journal_path)?;
            let (journal, repaired) = super::parse_json_state_bytes(&data)?;
            if repaired {
                tracing::warn!(
                    "Recovered Cloud Files callback journal with trailing JSON at {}; rewriting clean state",
                    self.runtime_paths.journal_path.display()
                );
                super::write_json_file_pretty(&self.runtime_paths.journal_path, &journal)?;
            }
            Ok(journal)
        }

        fn write_journal(&self, journal: &CloudMutationJournal) -> Result<()> {
            super::write_json_file_pretty(&self.runtime_paths.journal_path, journal)?;
            self.write_runtime_status(None)
        }

        fn write_runtime_status(&self, last_error: Option<String>) -> Result<()> {
            let journal = self.read_journal()?;
            let status = CloudProviderHost::status_from_journal(
                self.registration.root_id,
                &journal,
                last_error,
            );
            super::write_json_file_pretty(&self.runtime_paths.status_path, &status)
        }

        fn add_pending_mutation(&self, mut record: CloudMutationRecord) -> Result<Uuid> {
            let mut journal = self.read_journal()?;
            record.updated_at = Utc::now();
            let id = record.id;
            journal.records.push(record);
            journal.updated_at = Utc::now();
            self.write_journal(&journal)?;
            Ok(id)
        }

        fn clear_pending_mutation(&self, id: Uuid) -> Result<()> {
            let mut journal = self.read_journal()?;
            journal.records.retain(|record| record.id != id);
            journal.updated_at = Utc::now();
            self.write_journal(&journal)
        }

        fn mark_pending_mutation_error(&self, id: Uuid, error: &str) -> Result<()> {
            let mut journal = self.read_journal()?;
            for record in &mut journal.records {
                if record.id == id {
                    record.attempts = record.attempts.saturating_add(1);
                    record.last_error = Some(error.to_string());
                    record.updated_at = Utc::now();
                }
            }
            journal.updated_at = Utc::now();
            self.write_journal(&journal)
        }
    }

    fn callback_registrations() -> Vec<CF_CALLBACK_REGISTRATION> {
        vec![
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_DATA,
                Callback: Some(fetch_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_VALIDATE_DATA,
                Callback: Some(validate_data_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
                Callback: Some(cancel_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS,
                Callback: Some(fetch_placeholders_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS,
                Callback: Some(cancel_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
                Callback: Some(close_completion_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,
                Callback: Some(dehydrate_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_DELETE,
                Callback: Some(delete_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NOTIFY_RENAME,
                Callback: Some(rename_callback),
            },
            CF_CALLBACK_REGISTRATION {
                Type: CF_CALLBACK_TYPE_NONE,
                Callback: None,
            },
        ]
    }

    unsafe extern "system" fn fetch_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |context, info| unsafe {
            context.handle_fetch_data(info, callback_parameters)
        });
    }

    unsafe extern "system" fn validate_data_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |_context, info| unsafe {
            let params = (*callback_parameters).Anonymous.ValidateData;
            execute_ack_data(
                info,
                STATUS_SUCCESS,
                params.RequiredFileOffset,
                params.RequiredLength,
            )
        });
    }

    unsafe extern "system" fn fetch_placeholders_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |_context, info| unsafe {
            execute_transfer_placeholders(info, STATUS_SUCCESS, 0)
        });
    }

    unsafe extern "system" fn close_completion_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |context, info| unsafe {
            context.handle_close_completion(info)
        });
    }

    unsafe extern "system" fn dehydrate_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |_context, info| unsafe {
            execute_ack_dehydrate(info, STATUS_SUCCESS)
        });
    }

    unsafe extern "system" fn delete_callback(
        callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |context, info| unsafe {
            context.handle_delete(info)
        });
    }

    unsafe extern "system" fn rename_callback(
        callback_info: *const CF_CALLBACK_INFO,
        callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
        callback_guard(callback_info, |context, info| unsafe {
            context.handle_rename(info, callback_parameters)
        });
    }

    unsafe extern "system" fn cancel_callback(
        _callback_info: *const CF_CALLBACK_INFO,
        _callback_parameters: *const CF_CALLBACK_PARAMETERS,
    ) {
    }

    fn callback_guard(
        callback_info: *const CF_CALLBACK_INFO,
        f: impl FnOnce(&CallbackContext, &CF_CALLBACK_INFO) -> Result<()>,
    ) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            if callback_info.is_null() {
                return;
            }
            let info = &*callback_info;
            let Some(context) = callback_context(info) else {
                return;
            };
            if let Err(err) = f(context, info) {
                tracing::warn!("Windows Cloud Files callback failed: {}", err);
            }
        }));
    }

    impl CallbackContext {
        unsafe fn handle_fetch_data(
            &self,
            info: &CF_CALLBACK_INFO,
            callback_parameters: *const CF_CALLBACK_PARAMETERS,
        ) -> Result<()> {
            if callback_parameters.is_null() {
                return execute_transfer_data(info, STATUS_CLOUD_FILE_INVALID_REQUEST, &[], 0);
            }
            let identity = identity_from_callback(info)?;
            if identity.kind != ProviderEntryKind::File {
                return execute_transfer_data(info, STATUS_CLOUD_FILE_INVALID_REQUEST, &[], 0);
            }
            let params = (*callback_parameters).Anonymous.FetchData;
            let offset = params.RequiredFileOffset.max(0);
            let requested_length = params.RequiredLength.max(0);
            let entry = self.entry_for_identity(&identity)?;

            let cache_path = self.cache_path_for_identity(&identity);
            if !cache_path.exists() {
                let hydrate_result = self.runtime.block_on(async {
                    self.bridge.hydrate_file_to_path(&entry, &cache_path).await
                });
                if let Err(err) = hydrate_result {
                    tracing::warn!(
                        "Cloud Files hydration failed for {}: {}",
                        entry.relative_path,
                        err
                    );
                    return execute_transfer_data(
                        info,
                        error_status(&err.to_string()),
                        &[],
                        offset,
                    );
                }
            }

            let mut file = match File::open(&cache_path) {
                Ok(file) => file,
                Err(err) => {
                    tracing::warn!(
                        "Cloud Files hydration cache open failed for {}: {}",
                        entry.relative_path,
                        err
                    );
                    return execute_transfer_data(
                        info,
                        error_status(&err.to_string()),
                        &[],
                        offset,
                    );
                }
            };
            let length = usize::try_from(requested_length).unwrap_or(0);
            let mut buffer = vec![0u8; length];
            let slice_len = if file.seek(SeekFrom::Start(offset as u64)).is_err() {
                0
            } else {
                file.read(&mut buffer).unwrap_or(0)
            };
            buffer.truncate(slice_len);
            unsafe {
                CfUpdateSyncProviderStatus(info.ConnectionKey, CF_PROVIDER_STATUS_POPULATE_CONTENT)?
            };
            let result = execute_transfer_data(info, STATUS_SUCCESS, &buffer, offset);
            unsafe { CfUpdateSyncProviderStatus(info.ConnectionKey, CF_PROVIDER_STATUS_IDLE)? };
            result
        }

        unsafe fn handle_close_completion(&self, info: &CF_CALLBACK_INFO) -> Result<()> {
            let identity = identity_from_callback(info)?;
            if identity.kind != ProviderEntryKind::File {
                return Ok(());
            }
            let Some(full_path) = normalized_path_from_callback(info) else {
                return Ok(());
            };
            if !full_path.is_file() {
                return Ok(());
            }
            let relative_path =
                relative_path_from_full_path(&self.registration.sync_root_path, &full_path)
                    .unwrap_or_else(|| identity.relative_path.clone());
            let existing_identity = identity.clone();
            let mut record = CloudMutationRecord::new(
                CloudMutationKind::Writeback,
                self.registration.root_id,
                relative_path.clone(),
                Some(existing_identity.clone()),
            );
            record.plaintext_path = Some(full_path.clone());
            let mutation_id = self.add_pending_mutation(record)?;
            let writeback_result = self.runtime.block_on(async {
                self.bridge
                    .writeback_file(
                        self.registration.root_id,
                        &self.registration.encrypted_root,
                        &relative_path,
                        &full_path,
                        Some(&existing_identity),
                    )
                    .await
            });
            let writeback = match writeback_result {
                Ok(writeback) => writeback,
                Err(err) => {
                    self.mark_pending_mutation_error(mutation_id, &err.to_string())?;
                    return Err(err.into());
                }
            };
            self.remove_identity(&identity)?;
            self.remove_cache_for_identity(&identity);
            self.upsert_entry(writeback)?;
            self.clear_pending_mutation(mutation_id)?;
            Ok(())
        }

        unsafe fn handle_delete(&self, info: &CF_CALLBACK_INFO) -> Result<()> {
            let identity = identity_from_callback(info)?;
            let mutation_id = self.add_pending_mutation(CloudMutationRecord::new(
                CloudMutationKind::Delete,
                self.registration.root_id,
                identity.relative_path.clone(),
                Some(identity.clone()),
            ))?;
            let status = match self.runtime.block_on(async {
                self.bridge
                    .delete_entry(&self.registration.encrypted_root, &identity)
                    .await
            }) {
                Ok(()) => {
                    self.remove_identity(&identity)?;
                    self.remove_cache_for_identity(&identity);
                    self.clear_pending_mutation(mutation_id)?;
                    STATUS_SUCCESS
                }
                Err(err) => {
                    self.mark_pending_mutation_error(mutation_id, &err.to_string())?;
                    tracing::warn!(
                        "Cloud Files delete failed for {}: {}",
                        identity.relative_path,
                        err
                    );
                    error_status(&err.to_string())
                }
            };
            execute_ack_delete(info, status)
        }

        unsafe fn handle_rename(
            &self,
            info: &CF_CALLBACK_INFO,
            callback_parameters: *const CF_CALLBACK_PARAMETERS,
        ) -> Result<()> {
            if callback_parameters.is_null() {
                return execute_ack_rename(info, STATUS_CLOUD_FILE_INVALID_REQUEST);
            }
            let identity = identity_from_callback(info)?;
            let params = (*callback_parameters).Anonymous.Rename;
            let target_path = pcwstr_to_path(params.TargetPath);
            let target_relative = target_path
                .as_ref()
                .and_then(|path| {
                    relative_path_from_full_path(&self.registration.sync_root_path, path)
                })
                .ok_or_else(|| {
                    CloudProviderError::Callback(format!(
                        "rename target path is outside sync root for {}",
                        identity.relative_path
                    ))
                });

            let status = match target_relative {
                Ok(target_relative) => {
                    let mut record = CloudMutationRecord::new(
                        CloudMutationKind::Rename,
                        self.registration.root_id,
                        identity.relative_path.clone(),
                        Some(identity.clone()),
                    );
                    record.target_relative_path = Some(target_relative.clone());
                    record.target_plaintext_path = target_path.clone();
                    let mutation_id = self.add_pending_mutation(record)?;
                    match self.runtime.block_on(async {
                        self.bridge
                            .rename_entry(
                                self.registration.root_id,
                                &self.registration.encrypted_root,
                                &identity,
                                &target_relative,
                                target_path.as_deref(),
                            )
                            .await
                    }) {
                        Ok(Some(entry)) => {
                            self.remove_identity(&identity)?;
                            self.remove_cache_for_identity(&identity);
                            self.upsert_entry(entry)?;
                            self.clear_pending_mutation(mutation_id)?;
                            STATUS_SUCCESS
                        }
                        Ok(None) => {
                            self.remove_identity(&identity)?;
                            self.remove_cache_for_identity(&identity);
                            self.clear_pending_mutation(mutation_id)?;
                            STATUS_SUCCESS
                        }
                        Err(err) => {
                            self.mark_pending_mutation_error(mutation_id, &err.to_string())?;
                            tracing::warn!(
                                "Cloud Files rename failed for {}: {}",
                                identity.relative_path,
                                err
                            );
                            error_status(&err.to_string())
                        }
                    }
                }
                Err(err) => {
                    tracing::warn!("Cloud Files rename target mapping failed: {}", err);
                    STATUS_CLOUD_FILE_INVALID_REQUEST
                }
            };
            execute_ack_rename(info, status)
        }
    }

    unsafe fn callback_context(info: &CF_CALLBACK_INFO) -> Option<&CallbackContext> {
        if info.CallbackContext.is_null() {
            return None;
        }
        Some(&*(info.CallbackContext as *const CallbackContext))
    }

    unsafe fn identity_from_callback(info: &CF_CALLBACK_INFO) -> Result<FileIdentityV1> {
        if info.FileIdentity.is_null() || info.FileIdentityLength == 0 {
            return Err(CloudProviderError::Callback(
                "callback did not include a file identity".to_string(),
            ));
        }
        let bytes = std::slice::from_raw_parts(
            info.FileIdentity.cast::<u8>(),
            info.FileIdentityLength as usize,
        );
        Ok(FileIdentityV1::from_bytes(bytes)?)
    }

    unsafe fn normalized_path_from_callback(info: &CF_CALLBACK_INFO) -> Option<std::path::PathBuf> {
        pcwstr_to_path(info.NormalizedPath)
    }

    unsafe fn pcwstr_to_path(value: PCWSTR) -> Option<std::path::PathBuf> {
        if value.is_null() {
            return None;
        }
        value
            .to_string()
            .ok()
            .map(strip_windows_nt_prefix)
            .map(std::path::PathBuf::from)
    }

    fn strip_windows_nt_prefix(value: String) -> String {
        value
            .strip_prefix(r"\??\")
            .or_else(|| value.strip_prefix(r"\\?\"))
            .unwrap_or(&value)
            .to_string()
    }

    fn relative_path_from_full_path(sync_root: &Path, full_path: &Path) -> Option<String> {
        full_path
            .strip_prefix(sync_root)
            .ok()
            .map(|path| normalize_relative_path(path.to_string_lossy()))
            .or_else(|| {
                let root = sync_root
                    .to_string_lossy()
                    .replace('/', "\\")
                    .to_lowercase();
                let full = full_path.to_string_lossy().replace('/', "\\");
                let full_lower = full.to_lowercase();
                full_lower.strip_prefix(&root).map(|_| {
                    normalize_relative_path(full[root.len()..].trim_start_matches('\\').to_string())
                })
            })
    }

    unsafe fn execute_transfer_data(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        bytes: &[u8],
        offset: i64,
    ) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_TRANSFER_DATA);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferData: CF_OPERATION_PARAMETERS_0_0 {
                    Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                    CompletionStatus: status,
                    Buffer: if bytes.is_empty() {
                        null()
                    } else {
                        bytes.as_ptr().cast()
                    },
                    Offset: offset,
                    Length: bytes.len() as i64,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_ack_data(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        offset: i64,
        length: i64,
    ) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DATA);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckData: CF_OPERATION_PARAMETERS_0_2 {
                    Flags: CF_OPERATION_ACK_DATA_FLAG_NONE,
                    CompletionStatus: status,
                    Offset: offset,
                    Length: length,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_transfer_placeholders(
        info: &CF_CALLBACK_INFO,
        status: NTSTATUS,
        total_count: i64,
    ) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                TransferPlaceholders: CF_OPERATION_PARAMETERS_0_4 {
                    Flags: CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_NONE,
                    CompletionStatus: status,
                    PlaceholderTotalCount: total_count,
                    PlaceholderArray: std::ptr::null_mut(),
                    PlaceholderCount: 0,
                    EntriesProcessed: 0,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_ack_dehydrate(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DEHYDRATE);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckDehydrate: CF_OPERATION_PARAMETERS_0_5 {
                    Flags: CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE,
                    CompletionStatus: status,
                    FileIdentity: info.FileIdentity,
                    FileIdentityLength: info.FileIdentityLength,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_ack_delete(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_DELETE);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckDelete: CF_OPERATION_PARAMETERS_0_7 {
                    Flags: CF_OPERATION_ACK_DELETE_FLAG_NONE,
                    CompletionStatus: status,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn execute_ack_rename(info: &CF_CALLBACK_INFO, status: NTSTATUS) -> Result<()> {
        let op_info = operation_info(info, CF_OPERATION_TYPE_ACK_RENAME);
        let mut params = CF_OPERATION_PARAMETERS {
            ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
            Anonymous: CF_OPERATION_PARAMETERS_0 {
                AckRename: CF_OPERATION_PARAMETERS_0_6 {
                    Flags: CF_OPERATION_ACK_RENAME_FLAG_NONE,
                    CompletionStatus: status,
                },
            },
        };
        unsafe { CfExecute(&op_info, &mut params)? };
        Ok(())
    }

    unsafe fn operation_info(
        info: &CF_CALLBACK_INFO,
        operation_type: windows::Win32::Storage::CloudFilters::CF_OPERATION_TYPE,
    ) -> CF_OPERATION_INFO {
        CF_OPERATION_INFO {
            StructSize: size_of::<CF_OPERATION_INFO>() as u32,
            Type: operation_type,
            ConnectionKey: info.ConnectionKey,
            TransferKey: info.TransferKey,
            CorrelationVector: info.CorrelationVector,
            SyncStatus: null(),
            RequestKey: info.RequestKey,
        }
    }

    fn error_status(_message: &str) -> NTSTATUS {
        STATUS_CLOUD_FILE_UNSUCCESSFUL
    }

    struct OwnedPlaceholder {
        relative_name: Vec<u16>,
        full_path: PathBuf,
        display_path: String,
        kind: ProviderEntryKind,
        identity: Vec<u8>,
        info: CF_PLACEHOLDER_CREATE_INFO,
    }

    impl OwnedPlaceholder {
        fn new(
            entry: &ProviderEntry,
            relative_name: Vec<u16>,
            full_path: PathBuf,
            display_path: String,
        ) -> Result<Self> {
            let identity = entry.identity.to_bytes()?;
            if identity.len() > CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH as usize {
                return Err(CloudProviderError::IdentityTooLarge {
                    path: entry.relative_path.clone(),
                    length: identity.len(),
                    max: CF_PLACEHOLDER_MAX_FILE_IDENTITY_LENGTH,
                });
            }

            let attributes = match entry.kind {
                ProviderEntryKind::Directory => FILE_ATTRIBUTE_DIRECTORY.0,
                ProviderEntryKind::File => FILE_ATTRIBUTE_ARCHIVE.0,
            };
            let modified_time = filetime_from_datetime(entry.modified_at);
            let file_size = i64::try_from(entry.logical_size).map_err(|_| {
                CloudProviderError::InvalidPath(format!(
                    "logical size for {} does not fit Windows Cloud Files metadata",
                    entry.relative_path
                ))
            })?;

            let mut placeholder = Self {
                relative_name,
                full_path,
                display_path,
                kind: entry.kind,
                identity,
                info: CF_PLACEHOLDER_CREATE_INFO::default(),
            };
            placeholder.info = CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: PCWSTR(placeholder.relative_name.as_ptr()),
                FsMetadata: CF_FS_METADATA {
                    BasicInfo: FILE_BASIC_INFO {
                        CreationTime: modified_time,
                        LastAccessTime: modified_time,
                        LastWriteTime: modified_time,
                        ChangeTime: modified_time,
                        FileAttributes: attributes,
                    },
                    FileSize: file_size,
                },
                FileIdentity: placeholder.identity.as_ptr().cast(),
                FileIdentityLength: placeholder.identity.len() as u32,
                Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
                    | CF_PLACEHOLDER_CREATE_FLAG_SUPERSEDE,
                Result: Default::default(),
                CreateUsn: 0,
            };
            Ok(placeholder)
        }

        fn relative_path(&self) -> String {
            self.display_path.clone()
        }
    }

    fn windows_error_matches(err: &windows::core::Error, code: WIN32_ERROR) -> bool {
        hresult_matches(err.code(), code)
    }

    fn hresult_matches(actual: HRESULT, code: WIN32_ERROR) -> bool {
        actual == HRESULT::from_win32(code.0)
    }

    fn ensure_absolute_or_create_root(path: &Path) -> Result<()> {
        ensure_absolute_path(path, "sync root")?;
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn ensure_existing_dir(path: &Path, label: &str) -> Result<()> {
        ensure_absolute_path(path, label)?;
        if !path.is_dir() {
            return Err(CloudProviderError::InvalidPath(format!(
                "{label} must be an existing directory: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn ensure_absolute_path(path: &Path, label: &str) -> Result<()> {
        if !path.is_absolute() {
            return Err(CloudProviderError::InvalidPath(format!(
                "{label} must be an absolute path: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn validate_relative_path(path: &str) -> Result<String> {
        if path.trim().is_empty() {
            return Err(CloudProviderError::InvalidPath(
                "placeholder relative path is empty".to_string(),
            ));
        }
        let normalized = path.replace('/', "\\");
        let candidate = Path::new(&normalized);
        if candidate.components().any(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::ParentDir
            )
        }) {
            return Err(CloudProviderError::InvalidPath(format!(
                "placeholder path must stay under the sync root: {path}"
            )));
        }
        Ok(normalized)
    }

    fn filetime_from_datetime(datetime: chrono::DateTime<chrono::Utc>) -> i64 {
        (datetime.timestamp() + SECONDS_FROM_1601_TO_UNIX_EPOCH) * WINDOWS_TICKS_PER_SECOND
            + i64::from(datetime.timestamp_subsec_nanos() / 100)
    }

    fn to_wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(target_os = "windows"))]
mod platform {
    use super::{
        CloudProviderError, CloudProviderStatus, CloudRootRegistration, CloudRuntimePaths,
        DehydrateRootSummary, Result,
    };
    use hybridcipher_provider_core::{ProviderBridge, ProviderEntry};
    use std::path::Path;
    use std::sync::Arc;
    use uuid::Uuid;

    pub struct ConnectedCloudRoot;

    impl ConnectedCloudRoot {
        pub fn root_id(&self) -> Uuid {
            Uuid::nil()
        }

        pub fn sync_root_path(&self) -> &Path {
            Path::new("")
        }
    }

    pub fn status() -> CloudProviderStatus {
        CloudProviderStatus::scaffolded(false, "Cloud Files API is only available on Windows.")
    }

    pub fn register_root(_registration: &CloudRootRegistration) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn unregister_root(_sync_root_path: &Path) -> Result<()> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn create_placeholders(_sync_root_path: &Path, _entries: &[ProviderEntry]) -> Result<u32> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn dehydrate_root(_sync_root_path: &Path) -> Result<DehydrateRootSummary> {
        Err(CloudProviderError::UnsupportedPlatform)
    }

    pub fn connect_root(
        _registration: &CloudRootRegistration,
        _bridge: Arc<dyn ProviderBridge>,
        _entries: Vec<ProviderEntry>,
        _runtime_paths: CloudRuntimePaths,
    ) -> Result<ConnectedCloudRoot> {
        Err(CloudProviderError::UnsupportedPlatform)
    }
}
