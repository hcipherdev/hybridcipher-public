use async_trait::async_trait;
use chrono::{DateTime, Utc};
use hybridcipher_mount_sync::{
    encrypted_path_for, load_mount_conflict_registry, load_mount_recovery_registry,
    parse_encrypted_header_only, ConflictKind, MountConflictRecord, MountCrypto,
    ConflictResolutionRequest, ConflictResolutionResult, MountRecoveryCopyRecord,
    MountSafetyReason, MountSyncRuntimeStatus, RecoveryCopyResolutionRequest,
    RecoveryCopyResolutionResult, SyncTracker,
};
use hybridcipher_provider_core::{
    normalize_relative_path, FileIdentityV1, ProviderBridge, ProviderCoreError, ProviderEntry,
    ProviderEntryKind,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};
use thiserror::Error;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

mod provider_state;

pub const DEFAULT_PROVIDER_IDENTIFIER: &str = "com.hybridcipher.app.HybridCipherFileProvider";

const DEFAULT_APPLE_TEAM_ID: &str = "G2L88C9692";
const FILE_PROVIDER_APP_GROUP_SUFFIX: &str = "group.com.hybridcipher.macOS";
const MACOS_UNIX_SOCKET_PATH_LIMIT: usize = 104;
const FILE_PROVIDER_CACHE_TMP_PREFIX: &str = ".hybridcipher-fp-tmp-";
const ENCRYPTED_TMP_DIR_NAME: &str = ".hybridcipher-tmp";
const PROVIDER_CHANGE_RETENTION: usize = 4_096;
#[cfg(target_os = "macos")]
const FILE_ID_XATTR: &str = "com.hybridcipher.file_id";
#[cfg(all(unix, not(target_os = "macos")))]
const FILE_ID_XATTR: &str = "user.hybridcipher.file_id";

pub use hybridcipher_provider_core::{
    local_provider_bridge, ClientMountCrypto, LocalProviderBridge, LocalProviderClient,
};
use provider_state::{
    record_state_changes, ProviderChangeEnumeration, ProviderChangeJournal, ProviderChangeRecord,
    ProviderItemIdentifier, ProviderItemSnapshot, ProviderPersistentState,
};
#[cfg(test)]
use provider_state::{ProviderChangeKind, ROOT_CONTAINER_SIGNAL_IDENTIFIER};

type DomainSignalHandler =
    dyn Fn(&str, &[String]) -> std::result::Result<(), String> + Send + Sync + 'static;

static DOMAIN_SIGNAL_HANDLER: LazyLock<Mutex<Option<Arc<DomainSignalHandler>>>> =
    LazyLock::new(|| Mutex::new(None));
#[cfg(test)]
static SIGNAL_HANDLER_TEST_GUARD: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

#[derive(Debug, Error)]
pub enum MacFileProviderError {
    #[error("macOS File Provider is only supported on macOS")]
    UnsupportedPlatform,
    #[error("invalid provider path: {0}")]
    InvalidPath(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("provider-core error: {0}")]
    ProviderCore(#[from] hybridcipher_provider_core::ProviderCoreError),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("UUID parse error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("provider operation failed: {0}")]
    Operation(String),
}

pub type Result<T> = std::result::Result<T, MacFileProviderError>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHostConfig {
    pub user_config_dir: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_identifier: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProviderDomainRegistration {
    pub root_id: Uuid,
    pub domain_identifier: String,
    pub display_name: String,
    pub encrypted_root: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_visible_url: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacFileProviderStatus {
    pub backend: String,
    pub available: bool,
    pub extension_ready: bool,
    pub running_root_count: usize,
    pub updated_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MacFileProviderRuntimeHealth {
    pub root_id: Uuid,
    pub registration_present: bool,
    pub domain_visible: bool,
    pub socket_reachable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl MacFileProviderStatus {
    pub fn new(
        available: bool,
        extension_ready: bool,
        running_root_count: usize,
        message: Option<String>,
    ) -> Self {
        Self {
            backend: "macos-file-provider".to_string(),
            available,
            extension_ready,
            running_root_count,
            updated_at: Utc::now(),
            message,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderMutationKind {
    Writeback,
    Delete,
    Rename,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderMutationRecord {
    pub id: Uuid,
    pub kind: ProviderMutationKind,
    pub root_id: Uuid,
    pub relative_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_plaintext_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<FileIdentityV1>,
    #[serde(default)]
    pub attempts: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ProviderMutationRecord {
    pub fn new(
        kind: ProviderMutationKind,
        root_id: Uuid,
        relative_path: impl Into<String>,
        identity: Option<FileIdentityV1>,
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
pub struct ProviderMutationJournal {
    pub root_id: Uuid,
    #[serde(default)]
    pub records: Vec<ProviderMutationRecord>,
    pub updated_at: DateTime<Utc>,
}

impl ProviderMutationJournal {
    pub fn empty(root_id: Uuid) -> Self {
        Self {
            root_id,
            records: Vec::new(),
            updated_at: Utc::now(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProviderRuntimePaths {
    pub status_path: PathBuf,
    pub journal_path: PathBuf,
    pub provider_state_path: PathBuf,
    pub provider_changes_path: PathBuf,
    pub socket_path: PathBuf,
    pub cache_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct MacFileProviderSyncJournalPaths {
    pending_deletions: PathBuf,
    pending_orphans: PathBuf,
    pending_writebacks: PathBuf,
    pending_refreshes: PathBuf,
    pending_open_unlinked: PathBuf,
    pending_metadata: PathBuf,
    sync_baseline: PathBuf,
    conflicts: PathBuf,
    recovery: PathBuf,
}

struct MacFileProviderCacheBridge {
    root_id: Uuid,
    domain_identifier: String,
    encrypted_root: PathBuf,
    runtime_paths: ProviderRuntimePaths,
    crypto: Arc<dyn MountCrypto>,
    tracker: AsyncMutex<SyncTracker>,
    operation_lock: AsyncMutex<()>,
    pending_directory_migrations: AsyncMutex<Vec<(String, String)>>,
}

impl MacFileProviderCacheBridge {
    fn new(
        root_id: Uuid,
        domain_identifier: String,
        encrypted_root: PathBuf,
        runtime_paths: ProviderRuntimePaths,
        user_config_dir: PathBuf,
        excluded_patterns: Vec<String>,
        crypto: Arc<dyn MountCrypto>,
    ) -> hybridcipher_provider_core::Result<Self> {
        fs::create_dir_all(&runtime_paths.cache_dir)?;
        fs::create_dir_all(&encrypted_root)?;
        match prune_redundant_decrypt_collision_conflicts(root_id, &runtime_paths) {
            Ok(pruned_conflicts) if pruned_conflicts > 0 => {
                tracing::info!(
                    "pruned {} redundant macOS File Provider conflict copies for root {}",
                    pruned_conflicts,
                    root_id
                );
            }
            Ok(_) => {}
            Err(err) => {
                tracing::warn!(
                    "failed to prune redundant macOS File Provider conflict copies for root {}: {}",
                    root_id,
                    err
                );
            }
        }
        let mut tracker = configured_cache_sync_tracker(
            root_id,
            &runtime_paths,
            &user_config_dir,
            excluded_patterns,
        );
        if seed_existing_cache_for_first_sync(&mut tracker, root_id, &runtime_paths)? {
            tracing::info!(
                "seeded existing macOS File Provider cache signatures for first sync of root {}",
                root_id
            );
        }
        Ok(Self {
            root_id,
            domain_identifier,
            encrypted_root,
            runtime_paths,
            crypto,
            tracker: AsyncMutex::new(tracker),
            operation_lock: AsyncMutex::new(()),
            pending_directory_migrations: AsyncMutex::new(Vec::new()),
        })
    }

    async fn sync_once(&self) -> hybridcipher_provider_core::Result<MountSyncRuntimeStatus> {
        let _operation = self.operation_lock.lock().await;
        self.sync_once_locked().await
    }

    async fn sync_once_locked(&self) -> hybridcipher_provider_core::Result<MountSyncRuntimeStatus> {
        fs::create_dir_all(&self.runtime_paths.cache_dir)?;
        fs::create_dir_all(&self.encrypted_root)?;
        let mut tracker = self.tracker.lock().await;
        let sync_result = tracker
            .sync(
                self.crypto.as_ref(),
                &self.encrypted_root,
                &self.runtime_paths.cache_dir,
            )
            .await;
        let mut status = tracker.runtime_status();
        if let Err(err) = sync_result {
            status.safe_to_unmount = false;
            status.last_error = Some(err.to_string());
            write_mount_sync_runtime_status(&self.runtime_paths.status_path, &status)?;
            return Err(ProviderCoreError::Crypto(err));
        }
        tracker.persist_sync_baseline()?;
        drop(tracker);
        let _ = self.reconcile_provider_state().await?;
        write_mount_sync_runtime_status(&self.runtime_paths.status_path, &status)?;
        Ok(status)
    }

    async fn has_fast_drain_work(&self) -> bool {
        self.tracker.lock().await.has_fast_drain_work()
    }

    fn ensure_root(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<()> {
        if root_id != self.root_id {
            return Err(ProviderCoreError::InvalidIdentity(format!(
                "bridge is serving root {}, not {}",
                self.root_id, root_id
            )));
        }
        if encrypted_root != self.encrypted_root {
            return Err(ProviderCoreError::InvalidIdentity(format!(
                "bridge is serving encrypted root {}, not {}",
                self.encrypted_root.display(),
                encrypted_root.display()
            )));
        }
        Ok(())
    }

    fn entry_for_relative_path(
        &self,
        relative_path: &str,
    ) -> hybridcipher_provider_core::Result<Option<ProviderEntry>> {
        let cache_path = cache_path_for_relative(&self.runtime_paths.cache_dir, relative_path)?;
        if !cache_path.exists() {
            return Ok(None);
        }
        cache_entry_for_path(
            self.root_id,
            &self.encrypted_root,
            &self.runtime_paths.cache_dir,
            &cache_path,
        )
    }

    async fn queue_directory_migration(
        &self,
        old_prefix: impl Into<String>,
        new_prefix: impl Into<String>,
    ) {
        self.pending_directory_migrations
            .lock()
            .await
            .push((old_prefix.into(), new_prefix.into()));
    }

    fn load_provider_state(&self) -> hybridcipher_provider_core::Result<ProviderPersistentState> {
        if !self.runtime_paths.provider_state_path.exists() {
            return Ok(ProviderPersistentState::new(self.root_id));
        }
        let data = fs::read(&self.runtime_paths.provider_state_path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn write_provider_state(
        &self,
        state: &ProviderPersistentState,
    ) -> hybridcipher_provider_core::Result<()> {
        if let Some(parent) = self.runtime_paths.provider_state_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.runtime_paths.provider_state_path,
            serde_json::to_vec_pretty(state)?,
        )?;
        Ok(())
    }

    fn load_provider_change_journal(
        &self,
    ) -> hybridcipher_provider_core::Result<ProviderChangeJournal> {
        if !self.runtime_paths.provider_changes_path.exists() {
            return Ok(ProviderChangeJournal::new(self.root_id));
        }
        let data = fs::read(&self.runtime_paths.provider_changes_path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    fn write_provider_change_journal(
        &self,
        journal: &ProviderChangeJournal,
    ) -> hybridcipher_provider_core::Result<()> {
        if let Some(parent) = self.runtime_paths.provider_changes_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(
            &self.runtime_paths.provider_changes_path,
            serde_json::to_vec_pretty(journal)?,
        )?;
        Ok(())
    }

    async fn reconcile_provider_state(
        &self,
    ) -> hybridcipher_provider_core::Result<(ProviderPersistentState, ProviderChangeJournal)> {
        let previous_state = self.load_provider_state()?;
        let mut next_state = previous_state.clone();
        let mut pending_directory_migrations = self.pending_directory_migrations.lock().await;
        for (old_prefix, new_prefix) in pending_directory_migrations.drain(..) {
            next_state.apply_directory_migration(&old_prefix, &new_prefix);
        }
        drop(pending_directory_migrations);

        let entries = scan_cache_inventory(
            self.root_id,
            &self.encrypted_root,
            &self.runtime_paths.cache_dir,
        )?;
        next_state.rebuild_items(
            self.root_id,
            &self.encrypted_root,
            &self.runtime_paths.cache_dir,
            &entries,
        );

        let mut journal = self.load_provider_change_journal()?;
        if !(previous_state.items.is_empty() && journal.latest_anchor == 0) {
            let touched_containers =
                record_state_changes(&mut journal, &previous_state, &next_state, PROVIDER_CHANGE_RETENTION);
            if !touched_containers.is_empty() {
                if let Err(err) = signal_provider_domain(
                    &self.domain_identifier,
                    touched_containers.into_iter().collect(),
                ) {
                    tracing::warn!(
                        "failed to signal macOS File Provider domain {}: {}",
                        self.domain_identifier,
                        err
                    );
                }
            }
        }

        self.write_provider_state(&next_state)?;
        self.write_provider_change_journal(&journal)?;
        Ok((next_state, journal))
    }

    async fn current_provider_sync_anchor(&self) -> hybridcipher_provider_core::Result<u64> {
        Ok(self.load_provider_change_journal()?.latest_anchor)
    }

    async fn enumerate_provider_changes(
        &self,
        anchor: u64,
    ) -> hybridcipher_provider_core::Result<ProviderChangeEnumeration> {
        Ok(self.load_provider_change_journal()?.enumerate_changes(anchor))
    }

    async fn provider_snapshot_for_identifier(
        &self,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        Ok(self.load_provider_state()?.snapshot_cloned(identifier))
    }
}

#[async_trait]
impl ProviderBridge for MacFileProviderCacheBridge {
    async fn inventory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<Vec<ProviderEntry>> {
        self.ensure_root(root_id, encrypted_root)?;
        // Do NOT sync here.  The background cache-sync task already keeps the
        // cache directory fresh (every 350ms / 5s).  A blocking sync on every
        // inventory call causes the File Provider extension to time out because
        // full sync takes O(seconds) per encrypted file via the crypto server.
        scan_cache_inventory(
            self.root_id,
            &self.encrypted_root,
            &self.runtime_paths.cache_dir,
        )
    }

    async fn hydrate_file(
        &self,
        entry: &ProviderEntry,
    ) -> hybridcipher_provider_core::Result<Vec<u8>> {
        if entry.kind != ProviderEntryKind::File {
            return Err(ProviderCoreError::InvalidIdentity(format!(
                "{} is not a file entry",
                entry.relative_path
            )));
        }
        let cache_path =
            cache_path_for_relative(&self.runtime_paths.cache_dir, &entry.relative_path)?;
        if !cache_path.exists() {
            // Only sync when the file is genuinely absent from cache — this is
            // a cache miss, so we must decrypt it from the encrypted store.
            self.sync_once().await?;
        }
        Ok(fs::read(cache_path)?)
    }

    async fn hydrate_file_to_path(
        &self,
        entry: &ProviderEntry,
        output_path: &Path,
    ) -> hybridcipher_provider_core::Result<()> {
        if entry.kind != ProviderEntryKind::File {
            return Err(ProviderCoreError::InvalidIdentity(format!(
                "{} is not a file entry",
                entry.relative_path
            )));
        }
        let cache_path =
            cache_path_for_relative(&self.runtime_paths.cache_dir, &entry.relative_path)?;
        if !cache_path.exists() {
            // Only sync when the file is genuinely absent from cache.
            self.sync_once().await?;
        }
        copy_file_atomically(&cache_path, output_path)?;
        Ok(())
    }

    async fn lookup_identity(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<Option<FileIdentityV1>> {
        self.ensure_root(root_id, encrypted_root)?;
        let normalized = identifier.trim_start_matches('/');
        let cache_path = cache_path_for_relative(&self.runtime_paths.cache_dir, normalized)?;
        if !cache_path.exists() {
            return Ok(None);
        }
        Ok(cache_entry_for_path(
            self.root_id,
            &self.encrypted_root,
            &self.runtime_paths.cache_dir,
            &cache_path,
        )?
        .map(|entry| entry.identity))
    }

    async fn writeback_file(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<&FileIdentityV1>,
    ) -> hybridcipher_provider_core::Result<ProviderEntry> {
        self.ensure_root(root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let cache_path = cache_path_for_relative(&self.runtime_paths.cache_dir, relative_path)?;
        copy_file_atomically(plaintext_path, &cache_path)?;
        if let Some(file_id) = existing_identity.and_then(|identity| identity.file_id.as_deref()) {
            let _ = write_file_id_xattr(&cache_path, file_id);
        }
        {
            let mut tracker = self.tracker.lock().await;
            tracker.preseed_stable(&cache_path);
        }
        self.sync_once_locked().await?;
        self.entry_for_relative_path(relative_path)?.ok_or_else(|| {
            ProviderCoreError::InvalidIdentity(format!(
                "cache entry {} was not found after writeback",
                normalize_relative_path(relative_path)
            ))
        })
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> hybridcipher_provider_core::Result<ProviderEntry> {
        self.ensure_root(root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let cache_path = cache_path_for_relative(&self.runtime_paths.cache_dir, relative_path)?;
        fs::create_dir_all(&cache_path)?;
        self.sync_once_locked().await?;
        self.entry_for_relative_path(relative_path)?.ok_or_else(|| {
            ProviderCoreError::InvalidIdentity(format!(
                "cache entry {} was not found after directory create",
                normalize_relative_path(relative_path)
            ))
        })
    }

    async fn delete_entry(
        &self,
        encrypted_root: &Path,
        identity: &FileIdentityV1,
    ) -> hybridcipher_provider_core::Result<()> {
        self.ensure_root(identity.root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let cache_path =
            cache_path_for_relative(&self.runtime_paths.cache_dir, &identity.relative_path)?;
        match identity.kind {
            ProviderEntryKind::Directory => {
                if cache_path.exists() {
                    fs::remove_dir_all(&cache_path)?;
                }
            }
            ProviderEntryKind::File => {
                if cache_path.exists() {
                    fs::remove_file(&cache_path)?;
                }
            }
        }
        self.sync_once_locked().await?;
        Ok(())
    }

    async fn rename_entry(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        source_identity: &FileIdentityV1,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> hybridcipher_provider_core::Result<Option<ProviderEntry>> {
        self.ensure_root(root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let source_path = cache_path_for_relative(
            &self.runtime_paths.cache_dir,
            &source_identity.relative_path,
        )?;
        if !source_path.exists() {
            self.sync_once_locked().await?;
        }

        let target_path =
            cache_path_for_relative(&self.runtime_paths.cache_dir, target_relative_path)?;
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent)?;
        }

        match source_identity.kind {
            ProviderEntryKind::Directory => {
                if source_path.exists() && source_path != target_path {
                    if target_path.exists() {
                        fs::remove_dir_all(&target_path)?;
                    }
                    fs::rename(&source_path, &target_path)?;
                    self.queue_directory_migration(
                        source_identity.relative_path.clone(),
                        target_relative_path.to_string(),
                    )
                    .await;
                }
            }
            ProviderEntryKind::File => {
                if source_path.exists() && source_path != target_path {
                    if target_path.exists() {
                        fs::remove_file(&target_path)?;
                    }
                    fs::rename(&source_path, &target_path)?;
                }
                if let Some(path) = target_plaintext_path {
                    copy_file_atomically(path, &target_path)?;
                }
                if let Some(file_id) = source_identity.file_id.as_deref() {
                    let _ = write_file_id_xattr(&target_path, file_id);
                }
            }
        }

        self.sync_once_locked().await?;
        Ok(self.entry_for_relative_path(target_relative_path)?)
    }
}

#[async_trait]
trait ProviderSocketBridge: Send + Sync {
    async fn list_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        container_identifier: Option<&str>,
    ) -> hybridcipher_provider_core::Result<Vec<ProviderItemSnapshot>>;

    async fn item(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>>;

    async fn hydrate(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        output_path: &Path,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>>;

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot>;

    async fn writeback(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<FileIdentityV1>,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot>;

    async fn delete(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<()>;

    async fn rename(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>>;

    async fn current_sync_anchor(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<u64>;

    async fn enumerate_changes(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        anchor: u64,
    ) -> hybridcipher_provider_core::Result<ProviderChangeEnumeration>;

    async fn resolve_conflict(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        request: ConflictResolutionRequest,
    ) -> hybridcipher_provider_core::Result<ConflictResolutionResult>;

    async fn resolve_recovery(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        request: RecoveryCopyResolutionRequest,
    ) -> hybridcipher_provider_core::Result<RecoveryCopyResolutionResult>;

    async fn signal_enumerator(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<()>;
}

#[async_trait]
impl ProviderSocketBridge for MacFileProviderCacheBridge {
    async fn list_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        container_identifier: Option<&str>,
    ) -> hybridcipher_provider_core::Result<Vec<ProviderItemSnapshot>> {
        self.ensure_root(root_id, encrypted_root)?;
        let state = self.load_provider_state()?;
        list_directory_snapshots(
            root_id,
            encrypted_root,
            &self.runtime_paths.cache_dir,
            &state,
            container_identifier,
        )
    }

    async fn item(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        self.ensure_root(root_id, encrypted_root)?;
        self.provider_snapshot_for_identifier(identifier).await
    }

    async fn hydrate(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        output_path: &Path,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        self.ensure_root(root_id, encrypted_root)?;
        let snapshot = match self.provider_snapshot_for_identifier(identifier).await? {
            Some(snapshot) => snapshot,
            None => return Ok(None),
        };
        let entry = self
            .entry_for_relative_path(&snapshot.relative_path)?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no cache entry found for provider identifier {identifier}"
                ))
            })?;
        self.hydrate_file_to_path(&entry, output_path).await?;
        Ok(Some(snapshot))
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot> {
        ProviderBridge::create_directory(self, root_id, encrypted_root, relative_path).await?;
        self.provider_snapshot_for_identifier(
            &ProviderItemIdentifier::Directory {
                directory_id: self
                    .load_provider_state()?
                    .path_to_directory_id
                    .get(&normalize_relative_path(relative_path))
                    .cloned()
                    .ok_or_else(|| {
                        ProviderCoreError::InvalidIdentity(format!(
                            "no directory identifier found for {}",
                            normalize_relative_path(relative_path)
                        ))
                    })?,
            }
            .to_string(),
        )
        .await?
        .ok_or_else(|| {
            ProviderCoreError::InvalidIdentity(format!(
                "no provider snapshot found for {}",
                normalize_relative_path(relative_path)
            ))
        })
    }

    async fn writeback(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<FileIdentityV1>,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot> {
        let resolved_identity = match existing_identity {
            Some(identity) => Some(identity),
            None => {
                let snapshot = self.provider_snapshot_for_identifier(identifier).await?;
                match snapshot {
                    Some(snapshot) => self
                        .entry_for_relative_path(&snapshot.relative_path)?
                        .map(|entry| entry.identity),
                    None => None,
                }
            }
        };
        let entry = ProviderBridge::writeback_file(
            self,
            root_id,
            encrypted_root,
            relative_path,
            plaintext_path,
            resolved_identity.as_ref(),
        )
        .await?;
        let provider_identifier = entry_provider_identifier(&entry, &self.load_provider_state()?);
        self.provider_snapshot_for_identifier(&provider_identifier)
            .await?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no provider snapshot found after writeback for {identifier}"
                ))
            })
    }

    async fn delete(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
    ) -> hybridcipher_provider_core::Result<()> {
        self.ensure_root(root_id, encrypted_root)?;
        let snapshot = self
            .provider_snapshot_for_identifier(identifier)
            .await?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no provider snapshot found for identifier {identifier}"
                ))
            })?;
        let entry = self
            .entry_for_relative_path(&snapshot.relative_path)?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no cache entry found for provider identifier {identifier}"
                ))
            })?;
        ProviderBridge::delete_entry(self, encrypted_root, &entry.identity).await
    }

    async fn rename(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        identifier: &str,
        target_relative_path: &str,
        target_plaintext_path: Option<&Path>,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        let snapshot = self
            .provider_snapshot_for_identifier(identifier)
            .await?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no provider snapshot found for identifier {identifier}"
                ))
            })?;
        let entry = self
            .entry_for_relative_path(&snapshot.relative_path)?
            .ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no cache entry found for provider identifier {identifier}"
                ))
            })?;
        ProviderBridge::rename_entry(
            self,
            root_id,
            encrypted_root,
            &entry.identity,
            target_relative_path,
            target_plaintext_path,
        )
        .await?;
        let state = self.load_provider_state()?;
        if entry.kind == ProviderEntryKind::Directory {
            if let Some(directory_id) = state
                .path_to_directory_id
                .get(&normalize_relative_path(target_relative_path))
                .cloned()
            {
                return Ok(state.snapshot_cloned(
                    &ProviderItemIdentifier::Directory { directory_id }.to_string(),
                ));
            }
        }
        if let Some(file_id) = entry.identity.file_id.clone() {
            return Ok(state.snapshot_cloned(
                &ProviderItemIdentifier::File { file_id }.to_string(),
            ));
        }
        Ok(state
            .items
            .values()
            .find(|snapshot| snapshot.relative_path == normalize_relative_path(target_relative_path))
            .cloned())
    }

    async fn current_sync_anchor(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<u64> {
        self.ensure_root(root_id, encrypted_root)?;
        self.current_provider_sync_anchor().await
    }

    async fn enumerate_changes(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        anchor: u64,
    ) -> hybridcipher_provider_core::Result<ProviderChangeEnumeration> {
        self.ensure_root(root_id, encrypted_root)?;
        self.enumerate_provider_changes(anchor).await
    }

    async fn resolve_conflict(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        request: ConflictResolutionRequest,
    ) -> hybridcipher_provider_core::Result<ConflictResolutionResult> {
        self.ensure_root(root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let mut tracker = self.tracker.lock().await;
        let result = tracker
            .resolve_conflict_action(&self.runtime_paths.cache_dir, &request)
            .map_err(ProviderCoreError::Crypto)?;
        tracker.flush_conflict_and_recovery_registries(&self.runtime_paths.cache_dir);
        drop(tracker);
        let _ = self.reconcile_provider_state().await?;
        Ok(result)
    }

    async fn resolve_recovery(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        request: RecoveryCopyResolutionRequest,
    ) -> hybridcipher_provider_core::Result<RecoveryCopyResolutionResult> {
        self.ensure_root(root_id, encrypted_root)?;
        let _operation = self.operation_lock.lock().await;
        let mut tracker = self.tracker.lock().await;
        let result = tracker
            .resolve_recovery_copy_action(&self.runtime_paths.cache_dir, &request)
            .map_err(ProviderCoreError::Crypto)?;
        tracker.flush_conflict_and_recovery_registries(&self.runtime_paths.cache_dir);
        drop(tracker);
        let _ = self.reconcile_provider_state().await?;
        Ok(result)
    }

    async fn signal_enumerator(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<()> {
        self.ensure_root(root_id, encrypted_root)?;
        signal_provider_domain(&self.domain_identifier, Vec::new())
            .map_err(|err| ProviderCoreError::InvalidIdentity(err.to_string()))
    }
}

struct GenericProviderSocketBridge {
    _root_id: Uuid,
    _encrypted_root: PathBuf,
    bridge: Arc<dyn ProviderBridge>,
}

#[async_trait]
impl ProviderSocketBridge for GenericProviderSocketBridge {
    async fn list_directory(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _container_identifier: Option<&str>,
    ) -> hybridcipher_provider_core::Result<Vec<ProviderItemSnapshot>> {
        Err(ProviderCoreError::MutationUnsupported(
            "directory-scoped listing requires cache-backed macOS File Provider runtime"
                .to_string(),
        ))
    }

    async fn item(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _identifier: &str,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        Err(ProviderCoreError::MutationUnsupported(
            "stable provider identifiers require cache-backed macOS File Provider runtime"
                .to_string(),
        ))
    }

    async fn hydrate(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _identifier: &str,
        _output_path: &Path,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        Err(ProviderCoreError::MutationUnsupported(
            "stable provider identifiers require cache-backed macOS File Provider runtime"
                .to_string(),
        ))
    }

    async fn create_directory(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        relative_path: &str,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot> {
        let entry = self
            .bridge
            .create_directory(root_id, encrypted_root, relative_path)
            .await?;
        let mut state = ProviderPersistentState::new(root_id);
        state.rebuild_items(root_id, encrypted_root, Path::new(""), &[entry.clone()]);
        Ok(state.snapshot_for_entry(root_id, entry))
    }

    async fn writeback(
        &self,
        root_id: Uuid,
        encrypted_root: &Path,
        _identifier: &str,
        relative_path: &str,
        plaintext_path: &Path,
        existing_identity: Option<FileIdentityV1>,
    ) -> hybridcipher_provider_core::Result<ProviderItemSnapshot> {
        let entry = self
            .bridge
            .writeback_file(
                root_id,
                encrypted_root,
                relative_path,
                plaintext_path,
                existing_identity.as_ref(),
            )
            .await?;
        let mut state = ProviderPersistentState::new(root_id);
        state.rebuild_items(root_id, encrypted_root, Path::new(""), &[entry.clone()]);
        Ok(state.snapshot_for_entry(root_id, entry))
    }

    async fn delete(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _identifier: &str,
    ) -> hybridcipher_provider_core::Result<()> {
        Err(ProviderCoreError::MutationUnsupported(
            "stable provider identifiers require cache-backed macOS File Provider runtime"
                .to_string(),
        ))
    }

    async fn rename(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _identifier: &str,
        _target_relative_path: &str,
        _target_plaintext_path: Option<&Path>,
    ) -> hybridcipher_provider_core::Result<Option<ProviderItemSnapshot>> {
        Err(ProviderCoreError::MutationUnsupported(
            "stable provider identifiers require cache-backed macOS File Provider runtime"
                .to_string(),
        ))
    }

    async fn current_sync_anchor(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<u64> {
        Ok(0)
    }

    async fn enumerate_changes(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _anchor: u64,
    ) -> hybridcipher_provider_core::Result<ProviderChangeEnumeration> {
        Ok(ProviderChangeEnumeration {
            latest_anchor: 0,
            expired: false,
            records: Vec::new(),
        })
    }

    async fn resolve_conflict(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _request: ConflictResolutionRequest,
    ) -> hybridcipher_provider_core::Result<ConflictResolutionResult> {
        Err(ProviderCoreError::MutationUnsupported(
            "conflict resolution requires cache-backed macOS File Provider runtime".to_string(),
        ))
    }

    async fn resolve_recovery(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
        _request: RecoveryCopyResolutionRequest,
    ) -> hybridcipher_provider_core::Result<RecoveryCopyResolutionResult> {
        Err(ProviderCoreError::MutationUnsupported(
            "recovery resolution requires cache-backed macOS File Provider runtime".to_string(),
        ))
    }

    async fn signal_enumerator(
        &self,
        _root_id: Uuid,
        _encrypted_root: &Path,
    ) -> hybridcipher_provider_core::Result<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MacFileProviderHost {
    config: ProviderHostConfig,
    running_roots: Arc<Mutex<HashMap<Uuid, FileProviderDomainRegistration>>>,
    socket_tasks: Arc<Mutex<HashMap<Uuid, Vec<tokio::task::JoinHandle<()>>>>>,
    sync_tasks: Arc<Mutex<HashMap<Uuid, tokio::task::JoinHandle<()>>>>,
}

impl MacFileProviderHost {
    pub fn new(config: ProviderHostConfig) -> Self {
        Self {
            config,
            running_roots: Arc::new(Mutex::new(HashMap::new())),
            socket_tasks: Arc::new(Mutex::new(HashMap::new())),
            sync_tasks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn config(&self) -> &ProviderHostConfig {
        &self.config
    }

    pub fn status(&self) -> MacFileProviderStatus {
        let provider_identifier = self
            .config
            .provider_identifier
            .as_deref()
            .unwrap_or(DEFAULT_PROVIDER_IDENTIFIER);
        platform_status(self.running_root_count(), provider_identifier)
    }

    pub fn check_runtime_health(&self, root_id: Uuid) -> Result<MacFileProviderRuntimeHealth> {
        let registration = self.load_registration(root_id)?;
        let mut latest_error = None;
        let mut socket_path = None;
        let mut socket_reachable = false;

        if registration.is_some() {
            let runtime_paths = self.runtime_paths(root_id)?;
            for candidate in runtime_socket_paths(root_id, &runtime_paths.socket_path) {
                match check_provider_socket(&candidate) {
                    Ok(()) => {
                        socket_path = Some(candidate);
                        socket_reachable = true;
                        latest_error = None;
                        break;
                    }
                    Err(err) => {
                        socket_path = Some(candidate);
                        latest_error = Some(err.to_string());
                    }
                }
            }
        }

        let domain_visible = registration
            .as_ref()
            .map(|registration| platform_domain_visible(&registration.domain_identifier))
            .unwrap_or(false);

        Ok(MacFileProviderRuntimeHealth {
            root_id,
            registration_present: registration.is_some(),
            domain_visible,
            socket_reachable,
            socket_path,
            latest_error: latest_error.clone(),
            last_error: latest_error,
        })
    }

    pub fn register_domain(&self, registration: &FileProviderDomainRegistration) -> Result<()> {
        self.save_registration(registration)
    }

    pub fn register_system_domain(
        &self,
        registration: &FileProviderDomainRegistration,
    ) -> Result<()> {
        platform_register_system_domain(registration)
    }

    pub fn unregister_domain(&self, root_id: Uuid) -> Result<()> {
        let registration = self.load_registration(root_id)?;
        self.cleanup_safe_runtime_artifacts(root_id)?;
        self.running_roots
            .lock()
            .map_err(|_| MacFileProviderError::Operation("running root lock poisoned".into()))?
            .remove(&root_id);
        if let Some(registration) = registration.as_ref() {
            self.unregister_system_domain(registration)?;
        }
        self.remove_registration(root_id)
    }

    pub fn unregister_domain_state(&self, root_id: Uuid) -> Result<()> {
        self.cleanup_safe_runtime_artifacts(root_id)?;
        self.running_roots
            .lock()
            .map_err(|_| MacFileProviderError::Operation("running root lock poisoned".into()))?
            .remove(&root_id);
        self.remove_registration(root_id)
    }

    pub fn unregister_system_domain(
        &self,
        registration: &FileProviderDomainRegistration,
    ) -> Result<()> {
        platform_unregister_system_domain(registration)
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
            MacFileProviderError::InvalidPath(format!(
                "no macOS File Provider registration state found for root {root_id}"
            ))
        })?;
        let runtime_paths = self.runtime_paths(root_id)?;
        self.replay_pending_mutations(&registration, bridge.clone(), &runtime_paths)
            .await?;
        self.write_runtime_status(root_id, &runtime_paths, None)?;
        let socket_bridge: Arc<dyn ProviderSocketBridge> = Arc::new(GenericProviderSocketBridge {
            _root_id: registration.root_id,
            _encrypted_root: registration.encrypted_root.clone(),
            bridge,
        });
        self.start_socket_server(registration.clone(), socket_bridge, runtime_paths.clone())
            .await?;
        self.running_roots
            .lock()
            .map_err(|_| MacFileProviderError::Operation("running root lock poisoned".into()))?
            .insert(root_id, registration);
        Ok(())
    }

    pub async fn start_root_with_crypto(
        &self,
        root_id: Uuid,
        crypto: Arc<dyn MountCrypto>,
    ) -> Result<()> {
        self.start_root_with_crypto_and_exclusions(root_id, crypto, Vec::new())
            .await
    }

    pub async fn start_root_with_crypto_and_exclusions(
        &self,
        root_id: Uuid,
        crypto: Arc<dyn MountCrypto>,
        excluded_patterns: Vec<String>,
    ) -> Result<()> {
        if self.is_root_running(root_id) {
            return Ok(());
        }
        let registration = self.load_registration(root_id)?.ok_or_else(|| {
            MacFileProviderError::InvalidPath(format!(
                "no macOS File Provider registration state found for root {root_id}"
            ))
        })?;
        let runtime_paths = self.runtime_paths(root_id)?;
        let cache_bridge = Arc::new(MacFileProviderCacheBridge::new(
            registration.root_id,
            registration.domain_identifier.clone(),
            registration.encrypted_root.clone(),
            runtime_paths.clone(),
            self.config.user_config_dir.clone(),
            excluded_patterns,
            crypto,
        )?);
        let replay_bridge: Arc<dyn ProviderBridge> = cache_bridge.clone();
        self.replay_pending_mutations(&registration, replay_bridge, &runtime_paths)
            .await?;
        cache_bridge.sync_once().await?;
        let socket_bridge: Arc<dyn ProviderSocketBridge> = cache_bridge.clone();
        self.start_socket_server(registration.clone(), socket_bridge, runtime_paths.clone())
            .await?;
        self.start_cache_sync_task(root_id, cache_bridge)?;
        self.running_roots
            .lock()
            .map_err(|_| MacFileProviderError::Operation("running root lock poisoned".into()))?
            .insert(root_id, registration);
        Ok(())
    }

    pub fn stop_root(&self, root_id: Uuid) -> Result<()> {
        let removed = self
            .running_roots
            .lock()
            .map_err(|_| MacFileProviderError::Operation("running root lock poisoned".into()))?
            .remove(&root_id);
        if removed.is_some() {
            if let Some(tasks) = self
                .socket_tasks
                .lock()
                .map_err(|_| MacFileProviderError::Operation("socket task lock poisoned".into()))?
                .remove(&root_id)
            {
                for task in tasks {
                    task.abort();
                }
            }
            if let Some(task) = self
                .sync_tasks
                .lock()
                .map_err(|_| MacFileProviderError::Operation("sync task lock poisoned".into()))?
                .remove(&root_id)
            {
                task.abort();
            }
            if let Ok(paths) = self.runtime_paths(root_id) {
                for socket_path in runtime_socket_paths(root_id, &paths.socket_path) {
                    let _ = fs::remove_file(socket_path);
                }
            }
            self.cleanup_safe_runtime_artifacts(root_id)?;
            Ok(())
        } else {
            Err(MacFileProviderError::Operation(format!(
                "macOS File Provider root {root_id} is not running"
            )))
        }
    }

    fn start_cache_sync_task(
        &self,
        root_id: Uuid,
        cache_bridge: Arc<MacFileProviderCacheBridge>,
    ) -> Result<()> {
        let task = tokio::spawn(async move {
            let mut regular = tokio::time::interval(Duration::from_secs(5));
            let mut fast = tokio::time::interval(Duration::from_millis(350));
            regular.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            fast.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

            loop {
                tokio::select! {
                    _ = regular.tick() => {
                        if let Err(err) = cache_bridge.sync_once().await {
                            tracing::warn!("macOS File Provider cache sync failed for {root_id}: {err}");
                        }
                    }
                    _ = fast.tick() => {
                        if cache_bridge.has_fast_drain_work().await {
                            if let Err(err) = cache_bridge.sync_once().await {
                                tracing::warn!("macOS File Provider fast-drain sync failed for {root_id}: {err}");
                            }
                        }
                    }
                }
            }
        });
        self.sync_tasks
            .lock()
            .map_err(|_| MacFileProviderError::Operation("sync task lock poisoned".into()))?
            .insert(root_id, task);
        Ok(())
    }

    #[cfg(unix)]
    async fn start_socket_server(
        &self,
        registration: FileProviderDomainRegistration,
        bridge: Arc<dyn ProviderSocketBridge>,
        runtime_paths: ProviderRuntimePaths,
    ) -> Result<()> {
        use tokio::net::UnixListener;

        let socket_paths = runtime_socket_paths(registration.root_id, &runtime_paths.socket_path);
        let mut tasks = Vec::new();
        for socket_path in socket_paths {
            if let Some(parent) = socket_path.parent() {
                fs::create_dir_all(parent)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
                }
            }
            if socket_path.exists() {
                fs::remove_file(&socket_path)?;
            }
            let listener = UnixListener::bind(&socket_path)?;
            let host = self.clone();
            let registration = registration.clone();
            let bridge = bridge.clone();
            let runtime_paths = runtime_paths.clone();
            let root_id = registration.root_id;
            let task_socket_path = socket_path.clone();
            let task = tokio::spawn(async move {
                loop {
                    let stream = match listener.accept().await {
                        Ok((stream, _addr)) => stream,
                        Err(err) => {
                            tracing::warn!(
                                "macOS File Provider socket accept failed for {}: {}",
                                task_socket_path.display(),
                                err
                            );
                            break;
                        }
                    };
                    let host = host.clone();
                    let registration = registration.clone();
                    let bridge = bridge.clone();
                    let runtime_paths = runtime_paths.clone();
                    tokio::spawn(async move {
                        if let Err(err) =
                            ipc::handle_stream(host, registration, bridge, runtime_paths, stream)
                                .await
                        {
                            tracing::warn!("macOS File Provider socket request failed: {}", err);
                        }
                    });
                }
            });
            tasks.push(task);
            tracing::info!(
                "macOS File Provider socket listening for root {} at {}",
                root_id,
                socket_path.display()
            );
        }

        self.socket_tasks
            .lock()
            .map_err(|_| MacFileProviderError::Operation("socket task lock poisoned".into()))?
            .insert(registration.root_id, tasks);
        Ok(())
    }

    #[cfg(not(unix))]
    async fn start_socket_server(
        &self,
        _registration: FileProviderDomainRegistration,
        _bridge: Arc<dyn ProviderSocketBridge>,
        _runtime_paths: ProviderRuntimePaths,
    ) -> Result<()> {
        Err(MacFileProviderError::UnsupportedPlatform)
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
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn runtime_paths(&self, root_id: Uuid) -> Result<ProviderRuntimePaths> {
        if self.config.user_config_dir.as_os_str().is_empty() {
            return Err(MacFileProviderError::InvalidPath(
                "user_config_dir is required for macOS File Provider runtime state".to_string(),
            ));
        }
        let state_dir = self.config.user_config_dir.join("mount_states");
        fs::create_dir_all(&state_dir)?;
        let socket_path = self
            .config
            .socket_path
            .clone()
            .unwrap_or_else(|| default_socket_path(root_id));
        Ok(ProviderRuntimePaths {
            status_path: state_dir.join(format!("mount_sync_status_{root_id}.json")),
            journal_path: state_dir.join(format!("macos_provider_mutations_{root_id}.json")),
            provider_state_path: state_dir.join(format!("macos_provider_state_{root_id}.json")),
            provider_changes_path: state_dir.join(format!("macos_provider_changes_{root_id}.json")),
            socket_path,
            cache_dir: state_dir.join(format!("macos_provider_cache_{root_id}")),
        })
    }

    pub fn read_journal_from_path(
        &self,
        root_id: Uuid,
        journal_path: &Path,
    ) -> Result<ProviderMutationJournal> {
        if !journal_path.exists() {
            return Ok(ProviderMutationJournal::empty(root_id));
        }
        let data = fs::read(journal_path)?;
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn write_journal_to_path(
        &self,
        journal_path: &Path,
        journal: &ProviderMutationJournal,
    ) -> Result<()> {
        if let Some(parent) = journal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(journal_path, serde_json::to_vec_pretty(journal)?)?;
        Ok(())
    }

    pub async fn replay_pending_mutations(
        &self,
        registration: &FileProviderDomainRegistration,
        bridge: Arc<dyn ProviderBridge>,
        paths: &ProviderRuntimePaths,
    ) -> Result<()> {
        let mut journal = self.read_journal_from_path(registration.root_id, &paths.journal_path)?;
        if journal.records.is_empty() {
            return Ok(());
        }

        let mut retained = Vec::new();
        for mut record in journal.records.into_iter() {
            let result = match record.kind {
                ProviderMutationKind::Writeback => match record.plaintext_path.as_ref() {
                    None => Err(MacFileProviderError::Operation(
                        "pending writeback is missing plaintext_path".to_string(),
                    )),
                    Some(path) if !path.exists() => Err(MacFileProviderError::Operation(format!(
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
                        .map_err(MacFileProviderError::from),
                },
                ProviderMutationKind::Delete => match record.identity.as_ref() {
                    None => Err(MacFileProviderError::Operation(
                        "pending delete is missing identity".to_string(),
                    )),
                    Some(identity) => bridge
                        .delete_entry(&registration.encrypted_root, identity)
                        .await
                        .map_err(MacFileProviderError::from),
                },
                ProviderMutationKind::Rename => match record.identity.as_ref() {
                    None => Err(MacFileProviderError::Operation(
                        "pending rename is missing identity".to_string(),
                    )),
                    Some(identity) => match record.target_relative_path.as_deref() {
                        None => Err(MacFileProviderError::Operation(
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
                            .map_err(MacFileProviderError::from),
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

    pub fn write_runtime_status(
        &self,
        root_id: Uuid,
        paths: &ProviderRuntimePaths,
        last_error: Option<String>,
    ) -> Result<()> {
        let journal = self.read_journal_from_path(root_id, &paths.journal_path)?;
        let status = Self::status_from_journal(root_id, &journal, last_error);
        if let Some(parent) = paths.status_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&paths.status_path, serde_json::to_vec_pretty(&status)?)?;
        Ok(())
    }

    pub fn status_from_journal(
        _root_id: Uuid,
        journal: &ProviderMutationJournal,
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

    fn save_registration(&self, registration: &FileProviderDomainRegistration) -> Result<()> {
        let Some(path) = self.registration_path(registration.root_id) else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_vec_pretty(registration)?)?;
        Ok(())
    }

    pub fn load_registration(
        &self,
        root_id: Uuid,
    ) -> Result<Option<FileProviderDomainRegistration>> {
        let Some(path) = self.registration_path(root_id) else {
            return Ok(None);
        };
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read(path)?;
        Ok(Some(serde_json::from_slice(&data)?))
    }

    pub fn load_registrations(&self) -> Result<Vec<FileProviderDomainRegistration>> {
        let dir = self
            .config
            .user_config_dir
            .join("macos-file-provider")
            .join("domains");
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut registrations: Vec<FileProviderDomainRegistration> = Vec::new();
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let data = fs::read(&path)?;
            registrations.push(serde_json::from_slice(&data)?);
        }
        registrations.sort_by_key(|registration| registration.root_id);
        Ok(registrations)
    }

    fn remove_registration(&self, root_id: Uuid) -> Result<()> {
        let Some(path) = self.registration_path(root_id) else {
            return Ok(());
        };
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn registration_path(&self, root_id: Uuid) -> Option<PathBuf> {
        if self.config.user_config_dir.as_os_str().is_empty() {
            return None;
        }
        Some(
            self.config
                .user_config_dir
                .join("macos-file-provider")
                .join("domains")
                .join(format!("{root_id}.json")),
        )
    }

    fn running_root_count(&self) -> usize {
        self.running_roots
            .lock()
            .map(|roots| roots.len())
            .unwrap_or_default()
    }

    fn is_root_running(&self, root_id: Uuid) -> bool {
        self.running_roots
            .lock()
            .map(|roots| roots.contains_key(&root_id))
            .unwrap_or(false)
    }

    fn cleanup_safe_runtime_artifacts(&self, root_id: Uuid) -> Result<()> {
        let paths = self.runtime_paths(root_id)?;
        if !self.runtime_artifacts_are_safe_to_remove(root_id, &paths)? {
            return Ok(());
        }
        remove_if_exists(&paths.status_path)?;
        remove_if_exists(&paths.journal_path)?;
        remove_if_exists(&paths.provider_state_path)?;
        remove_if_exists(&paths.provider_changes_path)?;

        let journals = macos_file_provider_sync_journal_paths(&paths, root_id);
        for path in [
            journals.pending_deletions,
            journals.pending_orphans,
            journals.pending_writebacks,
            journals.pending_refreshes,
            journals.pending_open_unlinked,
            journals.pending_metadata,
            journals.sync_baseline,
            journals.conflicts,
            journals.recovery,
        ] {
            remove_if_exists(&path)?;
        }

        if paths.cache_dir.exists() {
            fs::remove_dir_all(&paths.cache_dir)?;
        }
        Ok(())
    }

    fn runtime_artifacts_are_safe_to_remove(
        &self,
        root_id: Uuid,
        paths: &ProviderRuntimePaths,
    ) -> Result<bool> {
        if paths.status_path.exists() {
            return Ok(self.read_runtime_status(root_id)?.safe_to_unmount);
        }
        Ok(self
            .read_journal_from_path(root_id, &paths.journal_path)?
            .records
            .is_empty())
    }
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn configured_cache_sync_tracker(
    root_id: Uuid,
    runtime_paths: &ProviderRuntimePaths,
    user_config_dir: &Path,
    excluded_patterns: Vec<String>,
) -> SyncTracker {
    let mut tracker = SyncTracker::new();
    let mount_config = SyncTracker::load_mount_config_from_file(None);
    tracker.set_deletion_config(mount_config.deletion);
    tracker.set_sparse_skip_size_bytes(mount_config.sparse_skip_size_bytes);
    tracker.set_stream_threshold_bytes(mount_config.stream_threshold_bytes);
    tracker.set_stream_chunk_size_bytes(mount_config.stream_chunk_size_bytes);
    tracker.set_stream_stability_age_secs(mount_config.stream_stability_age_secs);
    tracker.set_excluded_patterns(excluded_patterns);
    tracker.set_retention_folder(user_config_dir);

    let journals = macos_file_provider_sync_journal_paths(runtime_paths, root_id);
    tracker.set_pending_deletion_path(journals.pending_deletions);
    tracker.set_pending_orphan_path(journals.pending_orphans);
    tracker.set_pending_writeback_path(journals.pending_writebacks);
    tracker.set_pending_refresh_path(journals.pending_refreshes);
    tracker.set_pending_open_unlinked_path(journals.pending_open_unlinked);
    tracker.set_pending_metadata_path(journals.pending_metadata);
    tracker.set_sync_baseline_path(journals.sync_baseline);
    tracker.set_conflict_registry_path(journals.conflicts);
    tracker.set_recovery_registry_path(journals.recovery);
    tracker
}

fn seed_existing_cache_for_first_sync(
    tracker: &mut SyncTracker,
    root_id: Uuid,
    runtime_paths: &ProviderRuntimePaths,
) -> hybridcipher_provider_core::Result<bool> {
    let journals = macos_file_provider_sync_journal_paths(runtime_paths, root_id);
    if journals.sync_baseline.exists() {
        return Ok(false);
    }
    if !cache_contains_user_visible_entries(&runtime_paths.cache_dir)? {
        return Ok(false);
    }

    tracker.seed_mountpoint_signatures(&runtime_paths.cache_dir)?;
    tracker.persist_sync_baseline()?;
    Ok(true)
}

fn cache_contains_user_visible_entries(cache_dir: &Path) -> io::Result<bool> {
    if !cache_dir.exists() {
        return Ok(false);
    }

    let mut stack = vec![cache_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if should_skip_cache_path(&path) {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

fn prune_redundant_decrypt_collision_conflicts(
    root_id: Uuid,
    runtime_paths: &ProviderRuntimePaths,
) -> hybridcipher_provider_core::Result<usize> {
    let journals = macos_file_provider_sync_journal_paths(runtime_paths, root_id);
    let records = load_mount_conflict_registry(&journals.conflicts)?;
    let mut pruned = 0;

    for record in records {
        if record.kind != ConflictKind::DecryptCollision || record.edited {
            continue;
        }

        let live_path = cache_path_for_relative(
            &runtime_paths.cache_dir,
            &record.live_relative_path.to_string_lossy(),
        )?;
        let conflict_path = cache_path_for_relative(
            &runtime_paths.cache_dir,
            &record.conflict_relative_path.to_string_lossy(),
        )?;
        if !live_path.is_file() || !conflict_path.is_file() {
            continue;
        }
        if files_have_same_contents(&live_path, &conflict_path)? {
            fs::remove_file(conflict_path)?;
            pruned += 1;
        }
    }

    Ok(pruned)
}

fn files_have_same_contents(left_path: &Path, right_path: &Path) -> io::Result<bool> {
    let left_metadata = fs::metadata(left_path)?;
    let right_metadata = fs::metadata(right_path)?;
    if left_metadata.len() != right_metadata.len() {
        return Ok(false);
    }

    let mut left = fs::File::open(left_path)?;
    let mut right = fs::File::open(right_path)?;
    let mut left_buffer = [0u8; 8192];
    let mut right_buffer = [0u8; 8192];

    loop {
        let left_len = left.read(&mut left_buffer)?;
        let right_len = right.read(&mut right_buffer)?;
        if left_len != right_len {
            return Ok(false);
        }
        if left_len == 0 {
            return Ok(true);
        }
        if left_buffer[..left_len] != right_buffer[..right_len] {
            return Ok(false);
        }
    }
}

fn macos_file_provider_sync_journal_paths(
    runtime_paths: &ProviderRuntimePaths,
    root_id: Uuid,
) -> MacFileProviderSyncJournalPaths {
    let state_dir = runtime_paths
        .status_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| runtime_paths.cache_dir.clone());
    let path = |name: &str| state_dir.join(format!("macos_fp_{name}_{root_id}.json"));
    MacFileProviderSyncJournalPaths {
        pending_deletions: path("pending_deletions"),
        pending_orphans: path("pending_orphans"),
        pending_writebacks: path("pending_writebacks"),
        pending_refreshes: path("pending_refreshes"),
        pending_open_unlinked: path("pending_open_unlinked"),
        pending_metadata: path("pending_metadata"),
        sync_baseline: path("sync_baseline"),
        conflicts: path("mount_conflicts"),
        recovery: path("mount_recovery"),
    }
}

fn scan_cache_inventory(
    root_id: Uuid,
    encrypted_root: &Path,
    cache_root: &Path,
) -> hybridcipher_provider_core::Result<Vec<ProviderEntry>> {
    let mut entries = Vec::new();
    if !cache_root.exists() {
        return Ok(entries);
    }
    scan_cache_dir(
        root_id,
        encrypted_root,
        cache_root,
        cache_root,
        &mut entries,
    )?;
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}

fn scan_cache_dir(
    root_id: Uuid,
    encrypted_root: &Path,
    cache_root: &Path,
    dir: &Path,
    entries: &mut Vec<ProviderEntry>,
) -> hybridcipher_provider_core::Result<()> {
    for child in fs::read_dir(dir)? {
        let child = child?;
        let path = child.path();
        if should_skip_cache_path(&path) {
            continue;
        }
        let file_type = child.file_type()?;
        if file_type.is_dir() {
            if let Some(entry) = cache_entry_for_path(root_id, encrypted_root, cache_root, &path)? {
                entries.push(entry);
            }
            scan_cache_dir(root_id, encrypted_root, cache_root, &path, entries)?;
        } else if file_type.is_file() {
            if let Some(entry) = cache_entry_for_path(root_id, encrypted_root, cache_root, &path)? {
                entries.push(entry);
            }
        }
    }
    Ok(())
}

pub(crate) fn cache_entry_for_path(
    root_id: Uuid,
    encrypted_root: &Path,
    cache_root: &Path,
    cache_path: &Path,
) -> hybridcipher_provider_core::Result<Option<ProviderEntry>> {
    let metadata = fs::metadata(cache_path)?;
    let relative_path = cache_relative_path(cache_root, cache_path)?;
    if relative_path.is_empty() {
        return Ok(None);
    }
    let modified_at = metadata_modified_at(&metadata);
    if metadata.is_dir() {
        let encrypted_directory_path = plain_path_for_relative(encrypted_root, &relative_path);
        return Ok(Some(ProviderEntry::cache_directory(
            root_id,
            relative_path,
            encrypted_directory_path,
            modified_at,
        )));
    }
    if !metadata.is_file() {
        return Ok(None);
    }

    let encrypted_path = encrypted_path_for(encrypted_root, cache_root, cache_path)
        .map_err(ProviderCoreError::Crypto)?;
    // Fast path: read only the JSON header, not the ciphertext payload.
    // The old full-file parse called read_to_end on v1 files (header_version < 2,
    // no chunk_size), which is O(file size) per file and caused 2+ minute inventory
    // times with 35 files.
    let (file_id, epoch_id, encrypted_size) = if encrypted_path.is_file() {
        parse_encrypted_header_only(&encrypted_path)
            .map(|(fid, eid, esz)| (Some(fid), Some(eid), esz))
            .unwrap_or_else(|_| {
                let esz = fs::metadata(&encrypted_path)
                    .ok()
                    .map(|m| m.len())
                    .unwrap_or(0);
                (None, None, esz)
            })
    } else {
        (None, None, 0)
    };

    Ok(Some(ProviderEntry::cache_file_with_identity(
        root_id,
        relative_path,
        encrypted_path,
        metadata.len(),
        encrypted_size,
        modified_at,
        None,
        file_id,
        epoch_id,
    )))
}

pub(crate) fn cache_path_for_relative(
    cache_root: &Path,
    relative_path: &str,
) -> hybridcipher_provider_core::Result<PathBuf> {
    let normalized = normalize_relative_path(relative_path);
    let mut path = cache_root.to_path_buf();
    for component in normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                return Err(ProviderCoreError::InvalidIdentity(format!(
                    "relative path {normalized} escapes the cache root"
                )));
            }
            value => path.push(value),
        }
    }
    Ok(path)
}

pub(crate) fn cache_relative_path(
    cache_root: &Path,
    cache_path: &Path,
) -> hybridcipher_provider_core::Result<String> {
    let relative =
        cache_path
            .strip_prefix(cache_root)
            .map_err(|_| ProviderCoreError::PathOutsideRoot {
                path: cache_path.to_path_buf(),
                root: cache_root.to_path_buf(),
            })?;
    Ok(normalize_relative_path(relative.to_string_lossy()))
}

fn plain_path_for_relative(root: &Path, relative_path: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in relative_path.split('/') {
        if !component.is_empty() {
            path.push(component);
        }
    }
    path
}

fn list_directory_snapshots(
    root_id: Uuid,
    encrypted_root: &Path,
    cache_root: &Path,
    state: &ProviderPersistentState,
    container_identifier: Option<&str>,
) -> hybridcipher_provider_core::Result<Vec<ProviderItemSnapshot>> {
    let relative_path = match container_identifier {
        None => String::new(),
        Some(identifier) => {
            let snapshot = state.snapshot(identifier).ok_or_else(|| {
                ProviderCoreError::InvalidIdentity(format!(
                    "no provider snapshot found for identifier {identifier}"
                ))
            })?;
            if snapshot.kind != ProviderEntryKind::Directory {
                return Err(ProviderCoreError::InvalidIdentity(format!(
                    "identifier {identifier} is not a directory"
                )));
            }
            snapshot.relative_path.clone()
        }
    };

    let directory_path = if relative_path.is_empty() {
        cache_root.to_path_buf()
    } else {
        cache_path_for_relative(cache_root, &relative_path)?
    };
    if !directory_path.exists() {
        return Ok(Vec::new());
    }

    let mut snapshots = Vec::new();
    for child in fs::read_dir(&directory_path)? {
        let child = child?;
        let path = child.path();
        if should_skip_cache_path(&path) {
            continue;
        }
        if let Some(entry) = cache_entry_for_path(root_id, encrypted_root, cache_root, &path)? {
            if let Some(snapshot) = state.snapshot_for_relative_path(root_id, entry) {
                snapshots.push(snapshot);
            }
        }
    }
    snapshots.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(snapshots)
}

fn entry_provider_identifier(entry: &ProviderEntry, state: &ProviderPersistentState) -> String {
    state
        .snapshot_for_entry(entry.root_id, entry.clone())
        .provider_id
}

fn metadata_modified_at(metadata: &fs::Metadata) -> DateTime<Utc> {
    metadata
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .unwrap_or_else(Utc::now)
}

fn should_skip_cache_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            name == ENCRYPTED_TMP_DIR_NAME || name.starts_with(FILE_PROVIDER_CACHE_TMP_PREFIX)
        })
        .unwrap_or(false)
}

fn copy_file_atomically(source: &Path, destination: &Path) -> io::Result<()> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("contents");
    let temp_path = parent.join(format!(
        "{FILE_PROVIDER_CACHE_TMP_PREFIX}{}-{file_name}",
        Uuid::new_v4()
    ));

    let copy_result = (|| -> io::Result<()> {
        let mut input = fs::File::open(source)?;
        let mut output = fs::File::create(&temp_path)?;
        io::copy(&mut input, &mut output)?;
        output.flush()?;
        output.sync_all()?;
        fs::rename(&temp_path, destination)?;
        if let Ok(parent_dir) = fs::File::open(parent) {
            let _ = parent_dir.sync_all();
        }
        Ok(())
    })();

    if copy_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    copy_result
}

fn write_mount_sync_runtime_status(
    status_path: &Path,
    status: &MountSyncRuntimeStatus,
) -> hybridcipher_provider_core::Result<()> {
    if let Some(parent) = status_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(status_path, serde_json::to_vec_pretty(status)?)?;
    Ok(())
}

#[cfg(unix)]
fn write_file_id_xattr(path: &Path, file_id: &str) -> io::Result<()> {
    xattr::set(path, FILE_ID_XATTR, file_id.as_bytes())
}

#[cfg(not(unix))]
fn write_file_id_xattr(_path: &Path, _file_id: &str) -> io::Result<()> {
    Ok(())
}

fn file_provider_app_group_identifier() -> String {
    if let Ok(value) = std::env::var("HYBRIDCIPHER_FILE_PROVIDER_APP_GROUP") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let team_id = option_env!("APPLE_TEAM_ID")
        .unwrap_or(DEFAULT_APPLE_TEAM_ID)
        .trim()
        .trim_end_matches('.');
    format!("{team_id}.{FILE_PROVIDER_APP_GROUP_SUFFIX}")
}

fn short_socket_filename(root_id: Uuid) -> String {
    let root_hex = root_id.simple().to_string();
    format!("{}.sock", &root_hex[..16])
}

fn app_group_socket_path(root_id: Uuid) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let path = home
        .join("Library")
        .join("Group Containers")
        .join(file_provider_app_group_identifier())
        .join("s")
        .join(short_socket_filename(root_id));

    if path.as_os_str().len() < MACOS_UNIX_SOCKET_PATH_LIMIT {
        Some(path)
    } else {
        None
    }
}

fn tmp_socket_path(root_id: Uuid) -> PathBuf {
    PathBuf::from("/tmp")
        .join("hc-fp")
        .join(short_socket_filename(root_id))
}

fn default_socket_path(root_id: Uuid) -> PathBuf {
    app_group_socket_path(root_id).unwrap_or_else(|| tmp_socket_path(root_id))
}

fn runtime_socket_paths(root_id: Uuid, primary_socket_path: &Path) -> Vec<PathBuf> {
    let mut paths = vec![primary_socket_path.to_path_buf()];
    let fallback = tmp_socket_path(root_id);
    if !paths.iter().any(|path| path == &fallback) {
        paths.push(fallback);
    }
    paths
}

#[cfg(unix)]
fn check_provider_socket(socket_path: &Path) -> Result<()> {
    use std::os::unix::net::UnixStream;

    if !socket_path.exists() {
        return Err(MacFileProviderError::Operation(format!(
            "provider socket does not exist: {}",
            socket_path.display()
        )));
    }
    let mut stream = UnixStream::connect(socket_path).map_err(|err| {
        MacFileProviderError::Operation(format!(
            "provider socket connection failed for {}: {err}",
            socket_path.display()
        ))
    })?;
    let mut request = serde_json::to_vec(&ProviderSocketRequest::Status)?;
    request.push(b'\n');
    stream.write_all(&request)?;
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let response: ProviderSocketResponse = serde_json::from_str(response.trim())?;
    if response.ok {
        Ok(())
    } else {
        Err(MacFileProviderError::Operation(
            response
                .message
                .unwrap_or_else(|| "provider socket status returned ok=false".to_string()),
        ))
    }
}

#[cfg(not(unix))]
fn check_provider_socket(_socket_path: &Path) -> Result<()> {
    Err(MacFileProviderError::UnsupportedPlatform)
}

fn providerctl_register_args(registration: &FileProviderDomainRegistration) -> Vec<String> {
    vec![
        "register".to_string(),
        "--domain-id".to_string(),
        registration.domain_identifier.clone(),
        "--display-name".to_string(),
        registration.display_name.clone(),
    ]
}

fn providerctl_unregister_args(registration: &FileProviderDomainRegistration) -> Vec<String> {
    vec![
        "unregister".to_string(),
        "--domain-id".to_string(),
        registration.domain_identifier.clone(),
    ]
}

fn providerctl_signal_args(domain_identifier: &str, container_ids: &[String]) -> Vec<String> {
    let mut args = vec![
        "signal".to_string(),
        "--domain-id".to_string(),
        domain_identifier.to_string(),
    ];
    for container_id in container_ids {
        args.push("--container-id".to_string());
        args.push(container_id.clone());
    }
    args
}

pub fn set_domain_signal_handler<F>(handler: F)
where
    F: Fn(&str, &[String]) -> std::result::Result<(), String> + Send + Sync + 'static,
{
    replace_domain_signal_handler(Some(Arc::new(handler)));
}

fn replace_domain_signal_handler(handler: Option<Arc<DomainSignalHandler>>) {
    *DOMAIN_SIGNAL_HANDLER
        .lock()
        .expect("domain signal handler lock poisoned") = handler;
}

fn current_domain_signal_handler() -> Option<Arc<DomainSignalHandler>> {
    DOMAIN_SIGNAL_HANDLER
        .lock()
        .expect("domain signal handler lock poisoned")
        .clone()
}

#[cfg(test)]
fn set_domain_signal_handler_for_tests(handler: Arc<DomainSignalHandler>) {
    replace_domain_signal_handler(Some(handler));
}

#[cfg(test)]
fn clear_domain_signal_handler_for_tests() {
    replace_domain_signal_handler(None);
}

#[cfg(test)]
fn signal_handler_test_guard() -> &'static Mutex<()> {
    &SIGNAL_HANDLER_TEST_GUARD
}

#[cfg(target_os = "macos")]
fn platform_register_system_domain(registration: &FileProviderDomainRegistration) -> Result<()> {
    run_providerctl(&providerctl_register_args(registration))
}

#[cfg(not(target_os = "macos"))]
fn platform_register_system_domain(_registration: &FileProviderDomainRegistration) -> Result<()> {
    Err(MacFileProviderError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
fn platform_unregister_system_domain(registration: &FileProviderDomainRegistration) -> Result<()> {
    run_providerctl(&providerctl_unregister_args(registration))
}

#[cfg(not(target_os = "macos"))]
fn platform_unregister_system_domain(_registration: &FileProviderDomainRegistration) -> Result<()> {
    Err(MacFileProviderError::UnsupportedPlatform)
}

#[cfg(target_os = "macos")]
fn platform_domain_visible(domain_identifier: &str) -> bool {
    std::process::Command::new("fileproviderctl")
        .arg("dump")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| {
            String::from_utf8_lossy(&output.stdout).contains(domain_identifier)
                || String::from_utf8_lossy(&output.stderr).contains(domain_identifier)
        })
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
fn platform_domain_visible(_domain_identifier: &str) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn signal_provider_domain(domain_identifier: &str, container_ids: Vec<String>) -> Result<()> {
    if let Some(handler) = current_domain_signal_handler() {
        return handler(domain_identifier, &container_ids).map_err(MacFileProviderError::Operation);
    }
    run_providerctl(&providerctl_signal_args(domain_identifier, &container_ids))
}

#[cfg(not(target_os = "macos"))]
fn signal_provider_domain(_domain_identifier: &str, _container_ids: Vec<String>) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_providerctl(args: &[String]) -> Result<()> {
    let helper = providerctl_native_path().ok_or_else(|| {
        MacFileProviderError::Operation(
            "providerctl-native is required to register macOS File Provider domains".to_string(),
        )
    })?;
    let output = std::process::Command::new(&helper)
        .args(args)
        .output()
        .map_err(MacFileProviderError::from)?;
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(MacFileProviderError::Operation(format!(
        "{} failed with status {}: {}{}{}",
        helper.display(),
        output.status,
        stdout.trim(),
        if stdout.trim().is_empty() || stderr.trim().is_empty() {
            ""
        } else {
            " "
        },
        stderr.trim()
    )))
}

#[cfg(target_os = "macos")]
fn providerctl_native_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("HYBRIDCIPHER_PROVIDERCTL_NATIVE").map(PathBuf::from) {
        if path.is_file() {
            return Some(path);
        }
    }

    if let Ok(exe) = std::env::current_exe() {
        let mut cursor = exe.as_path();
        while let Some(parent) = cursor.parent() {
            let candidate = parent
                .join("Resources")
                .join("bin")
                .join("providerctl-native");
            if candidate.is_file() {
                return Some(candidate);
            }
            let candidate = parent
                .join("Contents")
                .join("Resources")
                .join("bin")
                .join("providerctl-native");
            if candidate.is_file() {
                return Some(candidate);
            }
            cursor = parent;
        }
    }

    let candidate = PathBuf::from("/usr/local/libexec/hybridcipher/providerctl-native");
    if candidate.is_file() {
        return Some(candidate);
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub(crate) enum ProviderSocketRequest {
    Status,
    StartRoot {
        root_id: Uuid,
    },
    StopRoot {
        root_id: Uuid,
    },
    CurrentSyncAnchor {
        root_id: Uuid,
    },
    Changes {
        root_id: Uuid,
        since_anchor: u64,
    },
    Inventory {
        root_id: Uuid,
    },
    ListDirectory {
        root_id: Uuid,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        container_id: Option<String>,
    },
    Item {
        root_id: Uuid,
        identifier: String,
    },
    Hydrate {
        root_id: Uuid,
        identifier: String,
        output_path: PathBuf,
    },
    CreateDirectory {
        root_id: Uuid,
        relative_path: String,
    },
    Writeback {
        root_id: Uuid,
        identifier: String,
        relative_path: String,
        #[serde(alias = "contents_path")]
        plaintext_path: PathBuf,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        existing_identity: Option<FileIdentityV1>,
    },
    Delete {
        root_id: Uuid,
        identifier: String,
    },
    Rename {
        root_id: Uuid,
        identifier: String,
        target_relative_path: String,
        #[serde(
            default,
            alias = "contents_path",
            skip_serializing_if = "Option::is_none"
        )]
        target_plaintext_path: Option<PathBuf>,
    },
    ListConflicts {
        root_id: Uuid,
    },
    ResolveConflict {
        root_id: Uuid,
        request: serde_json::Value,
    },
    ListRecovery {
        root_id: Uuid,
    },
    ResolveRecovery {
        root_id: Uuid,
        request: serde_json::Value,
    },
    SignalEnumerator {
        root_id: Uuid,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProviderSocketResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<MacFileProviderStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<MountSyncRuntimeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<ProviderEntry>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<ProviderEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshots: Option<Vec<ProviderItemSnapshot>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<ProviderItemSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub changes: Option<Vec<ProviderChangeRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_sync_anchor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_anchor_expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflicts: Option<Vec<MountConflictRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Vec<MountRecoveryCopyRecord>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict_resolution: Option<ConflictResolutionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_resolution: Option<RecoveryCopyResolutionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl ProviderSocketResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            status: None,
            runtime_status: None,
            entries: None,
            entry: None,
            snapshots: None,
            snapshot: None,
            changes: None,
            latest_sync_anchor: None,
            sync_anchor_expired: None,
            conflicts: None,
            recovery: None,
            conflict_resolution: None,
            recovery_resolution: None,
            message: None,
        }
    }

    pub fn error(err: impl ToString) -> Self {
        Self {
            ok: false,
            status: None,
            runtime_status: None,
            entries: None,
            entry: None,
            snapshots: None,
            snapshot: None,
            changes: None,
            latest_sync_anchor: None,
            sync_anchor_expired: None,
            conflicts: None,
            recovery: None,
            conflict_resolution: None,
            recovery_resolution: None,
            message: Some(err.to_string()),
        }
    }
}

mod ipc {
    use super::{
        load_mount_conflict_registry, load_mount_recovery_registry,
        macos_file_provider_sync_journal_paths, FileProviderDomainRegistration,
        MacFileProviderHost, ProviderRuntimePaths, ProviderSocketBridge,
        ProviderSocketRequest, ProviderSocketResponse, Result,
    };
    use std::sync::Arc;
    use uuid::Uuid;

    #[cfg(unix)]
    pub async fn handle_stream(
        host: MacFileProviderHost,
        registration: FileProviderDomainRegistration,
        bridge: Arc<dyn ProviderSocketBridge>,
        runtime_paths: ProviderRuntimePaths,
        mut stream: tokio::net::UnixStream,
    ) -> Result<()> {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let mut request = String::new();
        {
            let mut reader = BufReader::new(&mut stream);
            reader.read_line(&mut request).await?;
        }
        let response =
            handle_request(&host, &registration, bridge, &runtime_paths, request.trim()).await;
        let mut response_bytes = serde_json::to_vec(&response)?;
        response_bytes.push(b'\n');
        stream.write_all(&response_bytes).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn handle_request(
        host: &MacFileProviderHost,
        registration: &FileProviderDomainRegistration,
        bridge: Arc<dyn ProviderSocketBridge>,
        runtime_paths: &ProviderRuntimePaths,
        request: &str,
    ) -> ProviderSocketResponse {
        let parsed = match serde_json::from_str::<ProviderSocketRequest>(request) {
            Ok(parsed) => parsed,
            Err(err) => return ProviderSocketResponse::error(err),
        };

        match parsed {
            ProviderSocketRequest::Status => {
                let mut response = ProviderSocketResponse::ok();
                response.status = Some(host.status());
                response.runtime_status = host.read_runtime_status(registration.root_id).ok();
                response
            }
            ProviderSocketRequest::StartRoot { root_id } => {
                root_response(root_id, registration.root_id, ProviderSocketResponse::ok())
            }
            ProviderSocketRequest::StopRoot { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match host.stop_root(root_id) {
                    Ok(()) => ProviderSocketResponse::ok(),
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::CurrentSyncAnchor { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .current_sync_anchor(root_id, &registration.encrypted_root)
                    .await
                {
                    Ok(anchor) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.latest_sync_anchor = Some(anchor);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Changes {
                root_id,
                since_anchor,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .enumerate_changes(root_id, &registration.encrypted_root, since_anchor)
                    .await
                {
                    Ok(batch) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.changes = Some(batch.records);
                        response.latest_sync_anchor = Some(batch.latest_anchor);
                        response.sync_anchor_expired = Some(batch.expired);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Inventory { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .list_directory(root_id, &registration.encrypted_root, None)
                    .await
                {
                    Ok(snapshots) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshots = Some(snapshots);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::ListDirectory {
                root_id,
                container_id,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .list_directory(
                        root_id,
                        &registration.encrypted_root,
                        container_id.as_deref(),
                    )
                    .await
                {
                    Ok(snapshots) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshots = Some(snapshots);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Item {
                root_id,
                identifier,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .item(root_id, &registration.encrypted_root, &identifier)
                    .await
                {
                    Ok(snapshot) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshot = snapshot;
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Hydrate {
                root_id,
                identifier,
                output_path,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .hydrate(
                        root_id,
                        &registration.encrypted_root,
                        &identifier,
                        &output_path,
                    )
                    .await
                {
                    Ok(Some(snapshot)) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshot = Some(snapshot);
                        response
                    }
                    Ok(None) => ProviderSocketResponse::error(format!(
                        "no provider snapshot found for identifier {identifier}"
                    )),
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Writeback {
                root_id,
                identifier,
                relative_path,
                plaintext_path,
                existing_identity,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .writeback(
                        root_id,
                        &registration.encrypted_root,
                        &identifier,
                        &relative_path,
                        &plaintext_path,
                        existing_identity,
                    )
                    .await
                {
                    Ok(snapshot) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshot = Some(snapshot);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::CreateDirectory {
                root_id,
                relative_path,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .create_directory(root_id, &registration.encrypted_root, &relative_path)
                    .await
                {
                    Ok(snapshot) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshot = Some(snapshot);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Delete {
                root_id,
                identifier,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .delete(root_id, &registration.encrypted_root, &identifier)
                    .await
                {
                    Ok(()) => ProviderSocketResponse::ok(),
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::Rename {
                root_id,
                identifier,
                target_relative_path,
                target_plaintext_path,
            } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .rename(
                        root_id,
                        &registration.encrypted_root,
                        &identifier,
                        &target_relative_path,
                        target_plaintext_path.as_deref(),
                    )
                    .await
                {
                    Ok(snapshot) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.snapshot = snapshot;
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::ListConflicts { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                let registry_path =
                    macos_file_provider_sync_journal_paths(runtime_paths, root_id).conflicts;
                match load_mount_conflict_registry(&registry_path) {
                    Ok(records) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.conflicts = Some(records);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::ResolveConflict { root_id, request } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                let request = match serde_json::from_value(request) {
                    Ok(request) => request,
                    Err(err) => return ProviderSocketResponse::error(err),
                };
                match bridge
                    .resolve_conflict(root_id, &registration.encrypted_root, request)
                    .await
                {
                    Ok(result) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.conflict_resolution = Some(result);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::ListRecovery { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                let registry_path =
                    macos_file_provider_sync_journal_paths(runtime_paths, root_id).recovery;
                match load_mount_recovery_registry(&registry_path) {
                    Ok(records) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.recovery = Some(records);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::ResolveRecovery { root_id, request } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                let request = match serde_json::from_value(request) {
                    Ok(request) => request,
                    Err(err) => return ProviderSocketResponse::error(err),
                };
                match bridge
                    .resolve_recovery(root_id, &registration.encrypted_root, request)
                    .await
                {
                    Ok(result) => {
                        let mut response = ProviderSocketResponse::ok();
                        response.recovery_resolution = Some(result);
                        response
                    }
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
            ProviderSocketRequest::SignalEnumerator { root_id } => {
                if let Err(err) = ensure_root(root_id, registration.root_id) {
                    return ProviderSocketResponse::error(err);
                }
                match bridge
                    .signal_enumerator(root_id, &registration.encrypted_root)
                    .await
                {
                    Ok(()) => ProviderSocketResponse::ok(),
                    Err(err) => ProviderSocketResponse::error(err),
                }
            }
        }
    }

    fn root_response(
        requested_root_id: Uuid,
        running_root_id: Uuid,
        response: ProviderSocketResponse,
    ) -> ProviderSocketResponse {
        match ensure_root(requested_root_id, running_root_id) {
            Ok(()) => response,
            Err(err) => ProviderSocketResponse::error(err),
        }
    }

    fn ensure_root(
        requested_root_id: Uuid,
        running_root_id: Uuid,
    ) -> std::result::Result<(), String> {
        if requested_root_id == running_root_id {
            Ok(())
        } else {
            Err(format!(
                "socket is serving root {running_root_id}, not {requested_root_id}"
            ))
        }
    }

}

#[cfg(target_os = "macos")]
fn platform_status(running_root_count: usize, provider_identifier: &str) -> MacFileProviderStatus {
    match provider_extension_ready(provider_identifier) {
        Ok(()) => MacFileProviderStatus::new(
            true,
            true,
            running_root_count,
            Some(format!(
                "macOS File Provider extension {provider_identifier} is registered."
            )),
        ),
        Err(message) => MacFileProviderStatus::new(true, false, running_root_count, Some(message)),
    }
}

#[cfg(not(target_os = "macos"))]
fn platform_status(running_root_count: usize, _provider_identifier: &str) -> MacFileProviderStatus {
    MacFileProviderStatus::new(
        false,
        false,
        running_root_count,
        Some("macOS File Provider is only available on macOS.".to_string()),
    )
}

#[cfg(target_os = "macos")]
fn provider_extension_ready(provider_identifier: &str) -> std::result::Result<(), String> {
    let output = std::process::Command::new("/usr/bin/pluginkit")
        .args(["-m", "-A", "-D", "-v", "-p", "com.apple.fileprovider-nonui"])
        .output()
        .map_err(|err| format!("failed to probe File Provider extensions: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}\n{stderr}");
    if provider_extension_ready_from_pluginkit_output(&combined, provider_identifier) {
        Ok(())
    } else {
        Err(format!(
            "HybridCipher File Provider extension {provider_identifier} is not installed or registered."
        ))
    }
}

fn provider_extension_ready_from_pluginkit_output(output: &str, provider_identifier: &str) -> bool {
    output
        .lines()
        .any(|line| line.contains(provider_identifier) || line.contains("HybridCipherFileProvider"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hybridcipher_provider_core::{FileIdentityV1, ProviderEntryKind};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use uuid::Uuid;

    struct EmptyProviderBridge;

    #[async_trait]
    impl ProviderBridge for EmptyProviderBridge {
        async fn inventory(
            &self,
            _root_id: Uuid,
            _encrypted_root: &Path,
        ) -> hybridcipher_provider_core::Result<Vec<ProviderEntry>> {
            Ok(Vec::new())
        }

        async fn hydrate_file(
            &self,
            _entry: &ProviderEntry,
        ) -> hybridcipher_provider_core::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    fn test_identity(root_id: Uuid) -> FileIdentityV1 {
        FileIdentityV1::new(
            root_id,
            ProviderEntryKind::File,
            "docs/report.txt",
            Some("file-1".to_string()),
            Some(7),
        )
    }

    #[test]
    fn mutation_journal_round_trips_and_blocks_safe_unmount() {
        let root_id = Uuid::new_v4();
        let mut record = ProviderMutationRecord::new(
            ProviderMutationKind::Writeback,
            root_id,
            "docs/report.txt",
            Some(test_identity(root_id)),
        );
        record.plaintext_path = Some("/tmp/report.txt".into());
        record.last_error = Some("writeback retry pending".to_string());

        let mut journal = ProviderMutationJournal::empty(root_id);
        journal.records.push(record);

        let encoded = serde_json::to_vec(&journal).expect("serialize journal");
        let decoded: ProviderMutationJournal =
            serde_json::from_slice(&encoded).expect("deserialize journal");

        let status = MacFileProviderHost::status_from_journal(root_id, &decoded, None);
        assert!(!status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 1);
        assert_eq!(status.pending_writeback_paths, vec!["docs/report.txt"]);
        assert!(matches!(
            status.unsafe_reasons.first(),
            Some(MountSafetyReason::PendingWriteback { count: 1, .. })
        ));
    }

    #[test]
    fn empty_mutation_journal_is_safe_to_unmount() {
        let root_id = Uuid::new_v4();
        let journal = ProviderMutationJournal::empty(root_id);

        let status = MacFileProviderHost::status_from_journal(root_id, &journal, None);

        assert!(status.safe_to_unmount);
        assert_eq!(status.pending_writeback_count, 0);
        assert!(status.unsafe_reasons.is_empty());
    }

    #[test]
    fn runtime_paths_are_scoped_by_root_id() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });

        let paths = host.runtime_paths(root_id).unwrap();

        assert!(paths
            .status_path
            .ends_with(format!("mount_sync_status_{root_id}.json")));
        assert!(paths
            .journal_path
            .ends_with(format!("macos_provider_mutations_{root_id}.json")));
        let root_hex = root_id.simple().to_string();
        assert!(paths
            .socket_path
            .ends_with(format!("{}.sock", &root_hex[..16])));
    }

    #[test]
    fn cache_sync_journal_paths_are_file_provider_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });

        let paths = host.runtime_paths(root_id).unwrap();
        let journals = macos_file_provider_sync_journal_paths(&paths, root_id);

        assert!(paths
            .status_path
            .ends_with(format!("mount_sync_status_{root_id}.json")));
        assert!(journals
            .pending_writebacks
            .ends_with(format!("macos_fp_pending_writebacks_{root_id}.json")));
        assert!(journals
            .pending_refreshes
            .ends_with(format!("macos_fp_pending_refreshes_{root_id}.json")));
        assert!(journals
            .sync_baseline
            .ends_with(format!("macos_fp_sync_baseline_{root_id}.json")));
    }

    #[test]
    fn cache_sync_tracker_applies_file_provider_exclusions() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();

        let tracker = configured_cache_sync_tracker(
            root_id,
            &paths,
            temp.path(),
            vec![
                ".obsidian".to_string(),
                ".obsidian/**".to_string(),
                ".hybridcipher-tmp/**".to_string(),
                "**/.vscode/**".to_string(),
            ],
        );

        assert!(tracker.is_path_excluded(&paths.cache_dir.join(".obsidian")));
        assert!(tracker.is_path_excluded(&paths.cache_dir.join(".obsidian/workspace.json")));
        assert!(tracker.is_path_excluded(&paths.cache_dir.join(".hybridcipher-tmp/write.tmp")));
        assert!(tracker.is_path_excluded(&paths.cache_dir.join("project/.vscode/settings.json")));
        assert!(!tracker.is_path_excluded(&paths.cache_dir.join("notes/today.md")));
    }

    #[test]
    fn cache_inventory_lists_pending_plaintext_files_with_cache_mtime() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let encrypted_root = temp.path().join("encrypted");
        let cache_root = temp.path().join("cache");
        let file_path = cache_root.join("docs").join("draft.txt");
        fs::create_dir_all(file_path.parent().unwrap()).unwrap();
        fs::write(&file_path, b"pending draft").unwrap();
        let expected_modified_at =
            DateTime::<Utc>::from(fs::metadata(&file_path).unwrap().modified().unwrap());

        let entries = scan_cache_inventory(root_id, &encrypted_root, &cache_root).unwrap();

        let file_entry = entries
            .iter()
            .find(|entry| entry.relative_path == "docs/draft.txt")
            .expect("cache file should be listed");
        assert_eq!(file_entry.kind, ProviderEntryKind::File);
        assert_eq!(file_entry.logical_size, "pending draft".len() as u64);
        assert_eq!(file_entry.encrypted_size, 0);
        assert!(file_entry.metadata.is_none());
        assert!(file_entry
            .encrypted_path
            .ends_with(PathBuf::from("docs").join("draft.txt.encrypted")));
        assert_eq!(file_entry.modified_at, expected_modified_at);

        assert!(entries.iter().any(
            |entry| entry.kind == ProviderEntryKind::Directory && entry.relative_path == "docs"
        ));
    }

    #[test]
    fn default_socket_path_stays_under_macos_sun_len_for_long_user_dirs() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let long_user_config_dir = temp
            .path()
            .join("a-very-long-home-directory-name")
            .join("users")
            .join("0123456789abcdef")
            .join("mount-state-parent-that-would-overflow-sockaddr-un");
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: long_user_config_dir,
            socket_path: None,
            provider_identifier: None,
        });

        let paths = host.runtime_paths(root_id).unwrap();
        assert!(
            paths.socket_path.as_os_str().len() < 104,
            "socket path is too long for macOS SUN_LEN: {}",
            paths.socket_path.display()
        );
    }

    #[test]
    fn default_socket_path_prefers_file_provider_app_group_container() {
        let root_id = Uuid::parse_str("00741c18-f05f-45f2-8f54-4c1c84a7bc14").unwrap();
        let path = default_socket_path(root_id);

        assert!(path.components().any(|component| {
            component.as_os_str() == std::ffi::OsStr::new("Group Containers")
        }));
        assert!(path.ends_with("s/00741c18f05f45f2.sock"));
        assert!(
            path.as_os_str().len() < 104,
            "socket path is too long for macOS SUN_LEN: {}",
            path.display()
        );
    }

    #[test]
    fn runtime_socket_paths_include_tmp_fallback_for_local_packages() {
        let root_id = Uuid::parse_str("00741c18-f05f-45f2-8f54-4c1c84a7bc14").unwrap();
        let primary = default_socket_path(root_id);

        let paths = runtime_socket_paths(root_id, &primary);

        assert!(paths.contains(&primary));
        assert!(paths.contains(&tmp_socket_path(root_id)));
        assert_eq!(paths.len(), 2);
    }

    #[test]
    fn runtime_health_reports_reachable_socket() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let socket_path = temp.path().join("provider.sock");
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: Some(socket_path.clone()),
            provider_identifier: None,
        });
        let registration = FileProviderDomainRegistration {
            root_id,
            domain_identifier: format!("com.hybridcipher.root.{root_id}"),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: temp.path().join("encrypted"),
            user_visible_url: Some(temp.path().join("visible")),
        };
        host.register_domain(&registration).unwrap();

        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            stream.read_to_string(&mut request).unwrap();
            assert!(request.contains("\"command\":\"status\""));
            stream.write_all(br#"{"ok":true}"#).unwrap();
            stream.write_all(b"\n").unwrap();
        });

        let health = host.check_runtime_health(root_id).unwrap();

        handle.join().unwrap();
        assert!(health.registration_present);
        assert!(health.socket_reachable);
        assert!(health.last_error.is_none(), "{:?}", health.last_error);
    }

    #[test]
    fn runtime_health_reports_stale_socket_file() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let socket_path = temp.path().join("provider.sock");
        fs::write(&socket_path, b"stale").unwrap();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: Some(socket_path),
            provider_identifier: None,
        });
        let registration = FileProviderDomainRegistration {
            root_id,
            domain_identifier: format!("com.hybridcipher.root.{root_id}"),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: temp.path().join("encrypted"),
            user_visible_url: Some(temp.path().join("visible")),
        };
        host.register_domain(&registration).unwrap();

        let health = host.check_runtime_health(root_id).unwrap();

        assert!(health.registration_present);
        assert!(!health.socket_reachable);
        assert!(health.last_error.unwrap().contains("socket"));
    }

    #[tokio::test]
    async fn generic_socket_bridge_conflict_recovery_errors_are_not_placeholders() {
        let bridge = GenericProviderSocketBridge {
            _root_id: Uuid::new_v4(),
            _encrypted_root: PathBuf::from("/tmp/encrypted"),
            bridge: Arc::new(EmptyProviderBridge),
        };
        let root_id = Uuid::new_v4();
        let conflict_request = ConflictResolutionRequest {
            request_id: Uuid::new_v4(),
            conflict_id: Uuid::new_v4(),
            action: hybridcipher_mount_sync::ConflictResolutionAction::KeepMountedFile,
            merged_text: None,
            destination_path: None,
            requested_at: Utc::now(),
        };
        let recovery_request = RecoveryCopyResolutionRequest {
            request_id: Uuid::new_v4(),
            recovery_relative_path: PathBuf::from("docs/report.txt.recovered"),
            action: hybridcipher_mount_sync::RecoveryCopyResolutionAction::ArchiveAndDismiss,
            destination_path: None,
            requested_at: Utc::now(),
        };

        let conflict_error = bridge
            .resolve_conflict(root_id, Path::new("/tmp/encrypted"), conflict_request)
            .await
            .unwrap_err()
            .to_string();
        let recovery_error = bridge
            .resolve_recovery(root_id, Path::new("/tmp/encrypted"), recovery_request)
            .await
            .unwrap_err()
            .to_string();

        assert!(!conflict_error.contains("not implemented yet"));
        assert!(!recovery_error.contains("not implemented yet"));
        assert!(conflict_error.contains("cache-backed macOS File Provider runtime"));
        assert!(recovery_error.contains("cache-backed macOS File Provider runtime"));
    }

    #[test]
    fn first_sync_seeds_existing_cache_when_file_provider_baseline_is_missing() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("existing.txt"), b"cached plaintext").unwrap();
        let mut tracker = configured_cache_sync_tracker(root_id, &paths, temp.path(), Vec::new());

        let seeded = seed_existing_cache_for_first_sync(&mut tracker, root_id, &paths).unwrap();

        assert!(seeded);
        assert!(macos_file_provider_sync_journal_paths(&paths, root_id)
            .sync_baseline
            .exists());
    }

    #[test]
    fn first_sync_does_not_seed_cache_when_file_provider_baseline_exists() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("existing.txt"), b"cached plaintext").unwrap();
        let mut tracker = configured_cache_sync_tracker(root_id, &paths, temp.path(), Vec::new());
        tracker.persist_sync_baseline().unwrap();

        let seeded = seed_existing_cache_for_first_sync(&mut tracker, root_id, &paths).unwrap();

        assert!(!seeded);
    }

    #[test]
    fn redundant_decrypt_collision_conflict_is_pruned_before_cache_seed() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("document.txt"), b"same").unwrap();
        fs::write(
            paths
                .cache_dir
                .join("document.txt.conflict-20260609_211325"),
            b"same",
        )
        .unwrap();
        let journals = macos_file_provider_sync_journal_paths(&paths, root_id);
        let records = vec![MountConflictRecord {
            id: Uuid::new_v4(),
            kind: ConflictKind::DecryptCollision,
            live_relative_path: PathBuf::from("document.txt"),
            conflict_relative_path: PathBuf::from("document.txt.conflict-20260609_211325"),
            created_at: Utc::now(),
            edited: false,
            live_exists: true,
            text_merge_supported: true,
            live_size_bytes: Some(4),
            conflict_size_bytes: 4,
        }];
        fs::write(&journals.conflicts, serde_json::to_vec(&records).unwrap()).unwrap();

        let pruned = prune_redundant_decrypt_collision_conflicts(root_id, &paths).unwrap();

        assert_eq!(pruned, 1);
        assert!(!paths
            .cache_dir
            .join("document.txt.conflict-20260609_211325")
            .exists());
        assert!(paths.cache_dir.join("document.txt").exists());
    }

    #[test]
    fn edited_decrypt_collision_conflict_is_not_pruned() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("document.txt"), b"same").unwrap();
        fs::write(
            paths
                .cache_dir
                .join("document.txt.conflict-20260609_211325"),
            b"same",
        )
        .unwrap();
        let journals = macos_file_provider_sync_journal_paths(&paths, root_id);
        let records = vec![MountConflictRecord {
            id: Uuid::new_v4(),
            kind: ConflictKind::DecryptCollision,
            live_relative_path: PathBuf::from("document.txt"),
            conflict_relative_path: PathBuf::from("document.txt.conflict-20260609_211325"),
            created_at: Utc::now(),
            edited: true,
            live_exists: true,
            text_merge_supported: true,
            live_size_bytes: Some(4),
            conflict_size_bytes: 4,
        }];
        fs::write(&journals.conflicts, serde_json::to_vec(&records).unwrap()).unwrap();

        let pruned = prune_redundant_decrypt_collision_conflicts(root_id, &paths).unwrap();

        assert_eq!(pruned, 0);
        assert!(paths
            .cache_dir
            .join("document.txt.conflict-20260609_211325")
            .exists());
    }

    #[test]
    fn pluginkit_probe_requires_hybridcipher_extension_identifier() {
        let output = "plugin com.dropbox.FileProvider(1.0) path=/Applications/Dropbox.app";
        assert!(!provider_extension_ready_from_pluginkit_output(
            output,
            DEFAULT_PROVIDER_IDENTIFIER
        ));

        let output = "plugin com.hybridcipher.app.HybridCipherFileProvider(1.0) path=/Applications/HybridCipher.app/Contents/PlugIns/HybridCipherFileProvider.appex";
        assert!(provider_extension_ready_from_pluginkit_output(
            output,
            DEFAULT_PROVIDER_IDENTIFIER
        ));
    }

    #[test]
    fn providerctl_register_args_include_domain_identifier_and_display_name() {
        let registration = FileProviderDomainRegistration {
            root_id: Uuid::nil(),
            domain_identifier: "com.hybridcipher.root.test".to_string(),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: "/tmp/encrypted".into(),
            user_visible_url: None,
        };

        let args = providerctl_register_args(&registration);

        assert_eq!(
            args,
            vec![
                "register",
                "--domain-id",
                "com.hybridcipher.root.test",
                "--display-name",
                "HybridCipher Test",
            ]
        );
    }

    #[test]
    fn providerctl_signal_args_include_container_identifiers() {
        let args = providerctl_signal_args(
            "com.hybridcipher.root.test",
            &[
                "hc:v2:dir:projects".to_string(),
                "hc:v2:file:file-123".to_string(),
            ],
        );

        assert_eq!(
            args,
            vec![
                "signal",
                "--domain-id",
                "com.hybridcipher.root.test",
                "--container-id",
                "hc:v2:dir:projects",
                "--container-id",
                "hc:v2:file:file-123",
            ]
        );
    }

    #[test]
    fn registration_persists_domain_state() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let registration = FileProviderDomainRegistration {
            root_id,
            domain_identifier: format!("com.hybridcipher.root.{root_id}"),
            display_name: "HybridCipher Test".to_string(),
            encrypted_root: temp.path().join("encrypted"),
            user_visible_url: Some(temp.path().join("visible")),
        };

        host.register_domain(&registration).unwrap();
        let reloaded = host.load_registration(root_id).unwrap().unwrap();

        assert_eq!(reloaded.root_id, root_id);
        assert_eq!(reloaded.domain_identifier, registration.domain_identifier);
        assert_eq!(reloaded.user_visible_url, registration.user_visible_url);
    }

    #[test]
    fn safe_stop_removes_plaintext_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("document.txt"), b"cached plaintext").unwrap();
        write_mount_sync_runtime_status(
            &paths.status_path,
            &MountSyncRuntimeStatus {
                safe_to_unmount: true,
                ..MountSyncRuntimeStatus::default()
            },
        )
        .unwrap();
        host.running_roots
            .lock()
            .unwrap()
            .insert(
                root_id,
                FileProviderDomainRegistration {
                    root_id,
                    domain_identifier: format!("com.hybridcipher.root.{root_id}"),
                    display_name: "HybridCipher Test".to_string(),
                    encrypted_root: temp.path().join("encrypted"),
                    user_visible_url: Some(temp.path().join("visible")),
                },
            );

        host.stop_root(root_id).unwrap();

        assert!(
            !paths.cache_dir.exists(),
            "safe stop should remove the plaintext cache directory"
        );
    }

    #[test]
    fn unsafe_stop_preserves_plaintext_cache() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let host = MacFileProviderHost::new(ProviderHostConfig {
            user_config_dir: temp.path().to_path_buf(),
            socket_path: None,
            provider_identifier: None,
        });
        let paths = host.runtime_paths(root_id).unwrap();
        fs::create_dir_all(&paths.cache_dir).unwrap();
        fs::write(paths.cache_dir.join("document.txt"), b"cached plaintext").unwrap();
        write_mount_sync_runtime_status(
            &paths.status_path,
            &MountSyncRuntimeStatus {
                safe_to_unmount: false,
                pending_writeback_count: 1,
                ..MountSyncRuntimeStatus::default()
            },
        )
        .unwrap();
        host.running_roots
            .lock()
            .unwrap()
            .insert(
                root_id,
                FileProviderDomainRegistration {
                    root_id,
                    domain_identifier: format!("com.hybridcipher.root.{root_id}"),
                    display_name: "HybridCipher Test".to_string(),
                    encrypted_root: temp.path().join("encrypted"),
                    user_visible_url: Some(temp.path().join("visible")),
                },
            );

        host.stop_root(root_id).unwrap();

        assert!(
            paths.cache_dir.exists(),
            "unsafe stop should preserve the plaintext cache directory"
        );
    }

    #[test]
    fn socket_request_uses_kebab_case_commands() {
        let request = ProviderSocketRequest::Inventory {
            root_id: Uuid::nil(),
        };

        let encoded = serde_json::to_string(&request).unwrap();

        assert!(encoded.contains("\"command\":\"inventory\""));
        assert!(encoded.contains("root_id"));
    }

    #[test]
    fn provider_identifier_round_trips_file_and_directory_ids() {
        let file_identifier = ProviderItemIdentifier::File {
            file_id: "file-123".to_string(),
        };
        let directory_identifier = ProviderItemIdentifier::Directory {
            directory_id: "dir-456".to_string(),
        };

        assert_eq!(
            ProviderItemIdentifier::parse(&file_identifier.to_string()).unwrap(),
            file_identifier
        );
        assert_eq!(
            ProviderItemIdentifier::parse(&directory_identifier.to_string()).unwrap(),
            directory_identifier
        );
    }

    #[test]
    fn change_journal_tracks_latest_anchor_and_expiration_window() {
        let root_id = Uuid::new_v4();
        let mut journal = ProviderChangeJournal::new(root_id);
        let snapshot = ProviderItemSnapshot {
            root_id,
            provider_id: "hc:v2:file:file-123".to_string(),
            parent_provider_id: Some("hc:v2:dir:dir-1".to_string()),
            relative_path: "docs/report.txt".to_string(),
            kind: ProviderEntryKind::File,
            logical_size: 12,
            encrypted_size: 34,
            modified_at: Utc::now(),
            content_version: vec![1, 2, 3],
            metadata_version: vec![4, 5, 6],
            identity: test_identity(root_id),
        };

        journal.push_upsert(snapshot.clone());
        journal.push_delete(
            snapshot.provider_id.clone(),
            snapshot.parent_provider_id.clone(),
            snapshot.relative_path.clone(),
        );
        journal.trim_to_retention(1);

        assert_eq!(journal.latest_anchor, 2);
        assert_eq!(journal.earliest_anchor, 2);
        assert_eq!(journal.records.len(), 1);
        assert!(journal.anchor_is_expired(0));
        assert!(!journal.anchor_is_expired(1));
        assert_eq!(
            journal
                .changes_since(1)
                .unwrap()
                .into_iter()
                .map(|record| record.anchor)
                .collect::<Vec<_>>(),
            vec![2]
        );
    }

    #[test]
    fn directory_listing_returns_only_direct_children() {
        let temp = tempfile::tempdir().unwrap();
        let root_id = Uuid::new_v4();
        let encrypted_root = temp.path().join("encrypted");
        let cache_root = temp.path().join("cache");
        fs::create_dir_all(cache_root.join("docs").join("nested")).unwrap();
        fs::write(cache_root.join("docs").join("report.txt"), b"report").unwrap();
        fs::write(
            cache_root.join("docs").join("nested").join("notes.txt"),
            b"notes",
        )
        .unwrap();

        let mut state = ProviderPersistentState::new(root_id);
        let docs_dir_id = state.ensure_directory_path("docs".to_string());
        state.ensure_directory_path("docs/nested".to_string());
        state.rebuild_items(
            root_id,
            &encrypted_root,
            &cache_root,
            &scan_cache_inventory(root_id, &encrypted_root, &cache_root).unwrap(),
        );

        let items = list_directory_snapshots(
            root_id,
            &encrypted_root,
            &cache_root,
            &state,
            Some(&ProviderItemIdentifier::Directory {
                directory_id: docs_dir_id,
            }
            .to_string()),
        )
        .unwrap();

        let relative_paths = items
            .into_iter()
            .map(|item| item.relative_path)
            .collect::<Vec<_>>();
        assert_eq!(relative_paths, vec!["docs/nested", "docs/report.txt"]);
    }

    #[test]
    fn file_rename_emits_single_upsert_without_delete() {
        let root_id = Uuid::new_v4();
        let encrypted_root = PathBuf::from("/tmp/encrypted");
        let cache_root = PathBuf::from("/tmp/cache");
        let old_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/report.txt",
            encrypted_root.join("docs/report.txt.encrypted"),
            7,
            9,
            Utc::now(),
            None,
            Some("file-1".to_string()),
            Some(7),
        );
        let new_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/final.txt",
            encrypted_root.join("docs/final.txt.encrypted"),
            7,
            9,
            Utc::now(),
            None,
            Some("file-1".to_string()),
            Some(7),
        );

        let mut previous = ProviderPersistentState::new(root_id);
        previous.rebuild_items(root_id, &encrypted_root, &cache_root, &[old_entry]);
        let mut next = previous.clone();
        next.rebuild_items(root_id, &encrypted_root, &cache_root, &[new_entry]);

        let mut journal = ProviderChangeJournal::new(root_id);
        let _ = record_state_changes(&mut journal, &previous, &next, 32);

        assert_eq!(journal.records.len(), 1);
        assert_eq!(journal.records[0].kind, ProviderChangeKind::Upsert);
        assert_eq!(journal.records[0].provider_id, "hc:v2:file:file-1");
        assert_eq!(journal.records[0].relative_path, "docs/final.txt");
    }

    #[test]
    fn local_directory_rename_preserves_directory_identifiers() {
        let root_id = Uuid::new_v4();
        let encrypted_root = PathBuf::from("/tmp/encrypted");
        let cache_root = PathBuf::from("/tmp/cache");
        let docs_entry = ProviderEntry::cache_directory(
            root_id,
            "docs",
            encrypted_root.join("docs"),
            Utc::now(),
        );
        let nested_entry = ProviderEntry::cache_directory(
            root_id,
            "docs/nested",
            encrypted_root.join("docs/nested"),
            Utc::now(),
        );
        let file_entry = ProviderEntry::cache_file_with_identity(
            root_id,
            "docs/nested/report.txt",
            encrypted_root.join("docs/nested/report.txt.encrypted"),
            6,
            8,
            Utc::now(),
            None,
            Some("file-1".to_string()),
            Some(7),
        );

        let mut previous = ProviderPersistentState::new(root_id);
        previous.rebuild_items(
            root_id,
            &encrypted_root,
            &cache_root,
            &[docs_entry.clone(), nested_entry.clone(), file_entry.clone()],
        );
        let old_docs_provider_id = previous
            .items
            .values()
            .find(|snapshot| snapshot.relative_path == "docs")
            .unwrap()
            .provider_id
            .clone();
        let old_nested_provider_id = previous
            .items
            .values()
            .find(|snapshot| snapshot.relative_path == "docs/nested")
            .unwrap()
            .provider_id
            .clone();

        let mut next = previous.clone();
        next.apply_directory_migration("docs", "projects");
        next.rebuild_items(
            root_id,
            &encrypted_root,
            &cache_root,
            &[
                ProviderEntry::cache_directory(
                    root_id,
                    "projects",
                    encrypted_root.join("projects"),
                    Utc::now(),
                ),
                ProviderEntry::cache_directory(
                    root_id,
                    "projects/nested",
                    encrypted_root.join("projects/nested"),
                    Utc::now(),
                ),
                ProviderEntry::cache_file_with_identity(
                    root_id,
                    "projects/nested/report.txt",
                    encrypted_root.join("projects/nested/report.txt.encrypted"),
                    6,
                    8,
                    Utc::now(),
                    None,
                    Some("file-1".to_string()),
                    Some(7),
                ),
            ],
        );

        let new_docs_provider_id = next
            .items
            .values()
            .find(|snapshot| snapshot.relative_path == "projects")
            .unwrap()
            .provider_id
            .clone();
        let new_nested_provider_id = next
            .items
            .values()
            .find(|snapshot| snapshot.relative_path == "projects/nested")
            .unwrap()
            .provider_id
            .clone();

        let mut journal = ProviderChangeJournal::new(root_id);
        let _ = record_state_changes(&mut journal, &previous, &next, 32);

        assert_eq!(old_docs_provider_id, new_docs_provider_id);
        assert_eq!(old_nested_provider_id, new_nested_provider_id);
        assert!(journal
            .records
            .iter()
            .all(|record| record.kind == ProviderChangeKind::Upsert));
    }

    #[test]
    fn root_level_changes_touch_the_root_container_signal() {
        let root_id = Uuid::new_v4();
        let encrypted_root = PathBuf::from("/tmp/encrypted");
        let cache_root = PathBuf::from("/tmp/cache");
        let previous = ProviderPersistentState::new(root_id);
        let mut next = ProviderPersistentState::new(root_id);
        next.rebuild_items(
            root_id,
            &encrypted_root,
            &cache_root,
            &[ProviderEntry::cache_directory(
                root_id,
                "docs",
                encrypted_root.join("docs"),
                Utc::now(),
            )],
        );

        let mut journal = ProviderChangeJournal::new(root_id);
        let touched = record_state_changes(&mut journal, &previous, &next, 32);

        assert!(touched.contains(ROOT_CONTAINER_SIGNAL_IDENTIFIER));
    }

    #[test]
    fn installed_signal_handler_overrides_external_helper() {
        let _guard = signal_handler_test_guard().lock().unwrap();
        clear_domain_signal_handler_for_tests();

        let calls = Arc::new(Mutex::new(Vec::<(String, Vec<String>)>::new()));
        let captured_calls = calls.clone();
        set_domain_signal_handler_for_tests(Arc::new(move |domain_identifier, container_ids| {
            captured_calls.lock().unwrap().push((
                domain_identifier.to_string(),
                container_ids.to_vec(),
            ));
            Ok(())
        }));

        signal_provider_domain(
            "com.hybridcipher.root.test",
            vec![
                ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string(),
                "hc:v2:file:file-123".to_string(),
            ],
        )
        .expect("signal succeeds with installed handler");

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "com.hybridcipher.root.test");
        assert_eq!(
            calls[0].1,
            vec![
                ROOT_CONTAINER_SIGNAL_IDENTIFIER.to_string(),
                "hc:v2:file:file-123".to_string(),
            ]
        );

        clear_domain_signal_handler_for_tests();
    }
}
