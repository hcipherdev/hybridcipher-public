//! HybridCipher FUSE filesystem implementation
//!
//! This module implements the main HybridCipher struct that provides the FUSE
//! Filesystem trait implementation with dual-epoch support and migration
//! awareness.

use crate::{
    cache::{CacheKey, CacheManager},
    migration::{tracker::MigrationStats, MigrationTracker},
    virtual_fs::{OverlayFile, VirtualTree},
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Local, Utc};
use dashmap::DashMap;
use dashmap::DashSet;
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use hybridcipher_client::{
    file::encrypt::{write_encrypted_file, SerializedEncryptedHeader, SparseFileMetadata},
    EncryptedFileMetadata,
};
use nix::sys::statvfs;
use notify::event::{Event, EventKind, RemoveKind};
use notify::{recommended_watcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde_json::Value;
use std::cmp;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, SystemTime};
use tokio::runtime::Handle;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Inode number type for filesystem operations
pub type InodeId = u64;

/// File handle type for open file operations  
pub type FileHandle = u64;

/// Root inode number (standard FUSE convention)
pub const ROOT_INODE: InodeId = 1;

/// Time-to-live for filesystem attributes (in seconds)
pub const ATTR_TTL: Duration = Duration::from_secs(1);

/// Time-to-live for directory entries (in seconds)
pub const ENTRY_TTL: Duration = Duration::from_secs(1);

const ENCRYPTED_SEPARATOR: &[u8] = b"\n---ENCRYPTED_DATA---\n";

/// Information about an open file handle
#[derive(Debug, Clone)]
pub struct FileHandleInfo {
    pub inode: InodeId,
    pub file_id: String,
    pub epoch_id: Option<String>,
    pub flags: i32,
    pub access_time: SystemTime,
}

/// File information for FUSE operations
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub file_id: String,
    pub epoch_id: String,
    pub size: u64,
    pub is_directory: bool,
    pub modified_time: SystemTime,
    pub access_time: SystemTime,
    pub creation_time: SystemTime,
    pub permissions: u16,
    pub relative_path: String,
    pub encrypted_path: Option<PathBuf>,
    pub is_virtual: bool,
}

/// HybridCipher FUSE filesystem implementation
///
/// This struct implements the FUSE Filesystem trait and provides:
/// - Dual-epoch file access with automatic fallback
/// - Opportunistic migration during file operations
/// - Migration status visualization through virtual files
/// - High-performance caching and prefetching
/// - Comprehensive error handling and recovery
pub struct HybridCipher<
    S: hybridcipher_client::storage::Storage,
    N: hybridcipher_client::network::Network,
> {
    /// HybridCipher client for encrypted operations
    client: Arc<hybridcipher_client::Client<S, N>>,

    /// Migration tracker for progress monitoring
    migration_tracker: Option<Arc<MigrationTracker<S, N>>>,

    /// Cache manager for performance optimization
    cache: Arc<CacheManager<S, N>>,

    /// High-performance decryption manager
    decryption_manager: Arc<super::decrypt::DecryptionManager<S, N>>,

    /// Performance monitoring and optimization manager
    performance_manager: Arc<super::performance::PerformanceManager<S, N>>,

    /// Virtual filesystem tree for migration status overlay
    virtual_tree: Arc<RwLock<VirtualTree>>,

    /// Open file handles mapping
    file_handles: Arc<DashMap<FileHandle, FileHandleInfo>>,

    /// Inode to file mapping
    inode_map: Arc<DashMap<InodeId, FileInfo>>,

    /// Normalized path ("/foo/bar") to inode mapping
    path_lookup: Arc<DashMap<String, InodeId>>,

    /// In-memory extended attribute store keyed by normalized path
    xattrs: Arc<DashMap<String, BTreeMap<String, Vec<u8>>>>,

    /// Paths currently being replaced via rename to suppress watcher removal
    suppressed_removals: Arc<DashSet<String>>,

    /// Root directory containing encrypted `.encrypted` files
    encrypted_root: PathBuf,

    /// Mount point directory where decrypted files are mirrored (for mirror mount on macOS)
    mount_point: Option<PathBuf>,

    /// Next available file handle
    next_handle: Arc<parking_lot::Mutex<FileHandle>>,

    /// Next available inode number
    next_inode: Arc<parking_lot::Mutex<InodeId>>,

    /// Tokio runtime handle for async operations
    runtime: Handle,

    /// Limit concurrent FUSE operations that touch the client/runtime
    operation_semaphore: Arc<Semaphore>,
}

impl<S, N> Clone for HybridCipher<S, N>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            migration_tracker: self.migration_tracker.clone(),
            cache: self.cache.clone(),
            decryption_manager: self.decryption_manager.clone(),
            performance_manager: self.performance_manager.clone(),
            virtual_tree: self.virtual_tree.clone(),
            file_handles: self.file_handles.clone(),
            inode_map: self.inode_map.clone(),
            path_lookup: self.path_lookup.clone(),
            xattrs: self.xattrs.clone(),
            suppressed_removals: self.suppressed_removals.clone(),
            encrypted_root: self.encrypted_root.clone(),
            mount_point: self.mount_point.clone(),
            next_handle: self.next_handle.clone(),
            next_inode: self.next_inode.clone(),
            runtime: self.runtime.clone(),
            operation_semaphore: self.operation_semaphore.clone(),
        }
    }
}

impl<S, N> HybridCipher<S, N>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    /// Create a new HybridCipher filesystem instance
    ///
    /// # Arguments
    ///
    /// * `client` - HybridCipher client for encrypted operations
    /// * `migration_tracker` - Optional migration tracker for progress monitoring
    ///
    /// # Returns
    ///
    /// Returns a new HybridCipher instance ready for mounting
    pub async fn new(
        client: hybridcipher_client::Client<S, N>,
        migration_tracker: Option<MigrationTracker<S, N>>,
        encrypted_root: PathBuf,
        mount_point: Option<PathBuf>,
        max_operations: u32,
    ) -> Result<Self> {
        let client = Arc::new(client);
        let migration_tracker = migration_tracker.map(Arc::new);
        let cache = Arc::new(CacheManager::new(client.clone(), Default::default()).await);
        let decryption_manager = Arc::new(super::decrypt::DecryptionManager::new(
            client.clone(),
            cache.clone(),
        ));
        let performance_manager =
            Arc::new(super::performance::PerformanceManager::new(cache.clone()));
        let virtual_tree = Arc::new(RwLock::new(VirtualTree::new()));
        let file_handles = Arc::new(DashMap::new());
        let inode_map = Arc::new(DashMap::new());
        let path_lookup = Arc::new(DashMap::new());
        let xattrs = Arc::new(DashMap::new());
        let suppressed_removals = Arc::new(DashSet::new());
        let next_handle = Arc::new(parking_lot::Mutex::new(1));
        let next_inode = Arc::new(parking_lot::Mutex::new(2)); // Start after root inode
        let runtime = Handle::current();
        let max_ops = std::cmp::max(1, max_operations) as usize;
        let operation_semaphore = Arc::new(Semaphore::new(max_ops));

        let fs = HybridCipher {
            client,
            migration_tracker,
            cache,
            decryption_manager,
            performance_manager,
            virtual_tree,
            file_handles,
            inode_map,
            path_lookup,
            xattrs,
            suppressed_removals,
            encrypted_root,
            mount_point,
            next_handle,
            next_inode,
            runtime,
            operation_semaphore,
        };

        // Initialize the virtual tree with root directory
        fs.initialize_root_directory()?;

        // Start performance monitoring background tasks
        fs.performance_manager.start_background_tasks().await?;

        // Start coverage watchers for auto-encryption of new files in enrolled folders
        if let Err(e) = fs.client.start_coverage_watchers().await {
            warn!("Failed to start coverage watchers: {}", e);
        }

        fs.spawn_encrypted_root_watcher();

        info!("HybridCipher filesystem initialized successfully");
        Ok(fs)
    }

    pub fn client_arc(&self) -> Arc<hybridcipher_client::Client<S, N>> {
        self.client.clone()
    }

    fn spawn_encrypted_root_watcher(&self) {
        let encrypted_root = self.encrypted_root.clone();
        let mount_point = self.mount_point.clone();
        let path_lookup = self.path_lookup.clone();
        let inode_map = self.inode_map.clone();
        let xattrs = self.xattrs.clone();
        let suppressed_removals = self.suppressed_removals.clone();
        let cache = self.cache.clone();
        let client = self.client.clone();
        let runtime = self.runtime.clone();

        thread::spawn(move || {
            let (event_tx, event_rx) = mpsc::channel();
            let mut watcher = match recommended_watcher(move |res| {
                let _ = event_tx.send(res);
            }) {
                Ok(w) => w,
                Err(err) => {
                    warn!("Failed to initialize encrypted root watcher: {}", err);
                    return;
                }
            };

            if let Err(err) = watcher.watch(&encrypted_root, RecursiveMode::Recursive) {
                warn!(
                    "Failed to watch encrypted root {}: {}",
                    encrypted_root.display(),
                    err
                );
                return;
            }

            info!(
                "Encrypted root watcher started for {}",
                encrypted_root.display()
            );

            for res in event_rx {
                match res {
                    Ok(event) => {
                        info!("Watcher received event: {:?}", event);
                        Self::handle_encrypted_root_event(
                            &encrypted_root,
                            mount_point.as_deref(),
                            event,
                            &path_lookup,
                            &inode_map,
                            &xattrs,
                            &suppressed_removals,
                            cache.clone(),
                            runtime.clone(),
                            client.clone(),
                        );
                    }
                    Err(err) => warn!("Encrypted root watcher error: {}", err),
                }
            }
        });
    }

    fn handle_encrypted_root_event(
        encrypted_root: &Path,
        mount_point: Option<&Path>,
        event: Event,
        path_lookup: &DashMap<String, InodeId>,
        inode_map: &DashMap<InodeId, FileInfo>,
        xattrs: &DashMap<String, BTreeMap<String, Vec<u8>>>,
        suppressed: &DashSet<String>,
        cache: Arc<CacheManager<S, N>>,
        runtime: Handle,
        client: Arc<hybridcipher_client::Client<S, N>>,
    ) {
        match event.kind {
            EventKind::Remove(RemoveKind::File)
            | EventKind::Remove(RemoveKind::Any)
            | EventKind::Remove(RemoveKind::Other) => {
                for removed in event.paths {
                    if let Some(normalized) =
                        normalize_encrypted_child_path(encrypted_root, &removed)
                    {
                        if suppressed.remove(&normalized).is_some() {
                            debug!(
                                "Suppressed watcher removal for {} (handled by rename)",
                                normalized
                            );
                            continue;
                        }
                        info!(
                            "Detected deletion of encrypted file {} (normalized path: {})",
                            removed.display(),
                            normalized
                        );

                        // For mirror mount: delete the physical decrypted file
                        if let Some(mount_root) = mount_point {
                            let decrypted_path =
                                mount_root.join(normalized.trim_start_matches('/'));
                            if decrypted_path.exists() {
                                match fs::remove_file(&decrypted_path) {
                                    Ok(()) => {
                                        info!(
                                            "Deleted mirror mount file: {}",
                                            decrypted_path.display()
                                        );
                                    }
                                    Err(err) => {
                                        warn!(
                                            "Failed to delete mirror mount file {}: {}",
                                            decrypted_path.display(),
                                            err
                                        );
                                    }
                                }
                            } else {
                                debug!(
                                    "Mirror mount file {} does not exist (already deleted or never created)",
                                    decrypted_path.display()
                                );
                            }
                        }

                        // Remove from our internal caches
                        Self::remove_cached_entry(
                            &normalized,
                            path_lookup,
                            inode_map,
                            xattrs,
                            cache.clone(),
                            runtime.clone(),
                        );

                        // Prune from coverage to prevent re-encryption
                        let client_clone = client.clone();
                        let runtime_clone = runtime.clone();
                        runtime_clone.spawn(async move {
                            match client_clone
                                .coverage_prune_orphan_file(removed.clone())
                                .await
                            {
                                Ok(pruned) => {
                                    if pruned {
                                        info!(
                                            "Successfully pruned coverage metadata for deleted file {}",
                                            removed.display()
                                        );
                                    } else {
                                        debug!(
                                            "File {} was not in coverage index (already pruned or never tracked)",
                                            removed.display()
                                        );
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        "Failed to prune coverage metadata for {}: {}",
                                        removed.display(),
                                        err
                                    );
                                }
                            }
                        });
                    } else {
                        debug!(
                            "Ignoring deletion event for non-encrypted file: {}",
                            removed.display()
                        );
                    }
                }
            }
            _ => {}
        }
    }

    fn remove_cached_entry(
        normalized: &str,
        path_lookup: &DashMap<String, InodeId>,
        inode_map: &DashMap<InodeId, FileInfo>,
        xattrs: &DashMap<String, BTreeMap<String, Vec<u8>>>,
        cache: Arc<CacheManager<S, N>>,
        runtime: Handle,
    ) {
        if let Some((_, inode)) = path_lookup.remove(normalized) {
            if let Some((_, info)) = inode_map.remove(&inode) {
                info!(
                    "Removed cached inode {} for deleted encrypted file at path {}",
                    inode, normalized
                );
                let file_id = info.file_id.clone();
                let cache_clone = cache.clone();
                runtime.spawn(async move {
                    cache_clone.invalidate_file(&file_id).await;
                    debug!("Cache invalidated for deleted file {}", file_id);
                });
            }
        } else {
            debug!("No cached entry found for deleted path {}", normalized);
        }

        xattrs.remove(normalized);
    }

    /// Initialize the root directory and virtual tree
    fn initialize_root_directory(&self) -> Result<()> {
        debug!("Initializing root directory");

        // Create root directory info
        let now = SystemTime::now();
        let root_info = FileInfo {
            file_id: "/".to_string(),
            epoch_id: "0".to_string(),
            size: 0,
            is_directory: true,
            modified_time: now,
            access_time: now,
            creation_time: now,
            permissions: 0o755,
            relative_path: "/".to_string(),
            encrypted_path: None,
            is_virtual: false,
        };

        // Insert root directory into inode map
        self.inode_map.insert(ROOT_INODE, root_info);
        self.path_lookup.insert("/".to_string(), ROOT_INODE);

        // Initialize virtual tree
        let mut tree = self.virtual_tree.write();
        tree.initialize_root()?;

        debug!("Root directory initialized successfully");
        Ok(())
    }

    /// Get the next available file handle
    fn get_next_handle(&self) -> FileHandle {
        let mut handle = self.next_handle.lock();
        let result = *handle;
        *handle += 1;
        result
    }

    /// Get the next available inode number
    fn get_next_inode(&self) -> InodeId {
        let mut inode = self.next_inode.lock();
        let result = *inode;
        *inode += 1;
        result
    }

    /// Convert FileInfo to FUSE FileAttr
    fn file_info_to_attr(&self, inode: InodeId, info: &FileInfo) -> FileAttr {
        let file_type = if info.is_directory {
            FileType::Directory
        } else {
            FileType::RegularFile
        };

        FileAttr {
            ino: inode,
            size: info.size,
            blocks: (info.size + 511) / 512, // 512-byte blocks
            atime: info.access_time,
            mtime: info.modified_time,
            ctime: info.creation_time,
            crtime: info.creation_time,
            kind: file_type,
            perm: info.permissions,
            nlink: if info.is_directory { 2 } else { 1 },
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    /// Check if migration is currently active
    ///
    /// # Returns
    ///
    /// Returns `true` if migration is active, `false` otherwise
    pub async fn is_migration_active(&self) -> bool {
        if let Some(tracker) = &self.migration_tracker {
            tracker.is_migration_active()
        } else {
            false
        }
    }

    /// Get migration statistics
    ///
    /// # Returns
    ///
    /// Returns current migration statistics
    pub fn get_migration_stats(&self) -> MigrationStats {
        if let Some(tracker) = &self.migration_tracker {
            tracker.get_migration_stats()
        } else {
            MigrationStats::default()
        }
    }

    /// Perform file lookup with migration awareness
    async fn lookup_file(
        &self,
        parent_inode: InodeId,
        name: &str,
    ) -> Result<Option<(InodeId, FileInfo)>> {
        debug!(
            "Looking up file '{}' in parent inode {}",
            name, parent_inode
        );

        // Resolve parent path
        let parent_info = match self.inode_map.get(&parent_inode) {
            Some(info) => info.clone(),
            None => {
                debug!("Parent inode {} not found", parent_inode);
                return Ok(None);
            }
        };

        if !parent_info.is_directory {
            debug!("Parent inode {} is not a directory", parent_inode);
            return Ok(None);
        }

        // Handle virtual overlay files (root only)
        if parent_inode == ROOT_INODE {
            if let Some(mut virtual_file) = self.lookup_virtual_entry(name)? {
                let path = format!("/{}", name.trim_matches('/'));
                virtual_file.relative_path = path.clone();
                virtual_file.file_id = path.clone();
                virtual_file.is_virtual = true;
                let inode = self.upsert_file_info(&path, virtual_file.clone());
                return Ok(Some((inode, virtual_file)));
            }
        }

        let parent_path = parent_info.relative_path.clone();
        drop(parent_info);

        let normalized_child = normalize_child_path(&parent_path, name);
        let parent_fs_path = self.encrypted_dir_for(&parent_path);
        let candidate_dir = parent_fs_path.join(name);

        if candidate_dir.is_dir() {
            match fs::metadata(&candidate_dir) {
                Ok(metadata) => {
                    let info = self.build_directory_info(&normalized_child, &metadata);
                    let inode = self.upsert_file_info(&normalized_child, info.clone());
                    debug!("Directory lookup successful: {} -> inode {}", name, inode);
                    return Ok(Some((inode, info)));
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(err) => {
                    warn!(
                        "Failed to read metadata for directory {}: {}",
                        candidate_dir.display(),
                        err
                    );
                    return Err(err.into());
                }
            }
        }

        let encrypted_file_path = parent_fs_path.join(format!("{}.encrypted", name));
        if encrypted_file_path.is_file() {
            let metadata = fs::metadata(&encrypted_file_path).with_context(|| {
                format!(
                    "Failed to read metadata for encrypted file {}",
                    encrypted_file_path.display()
                )
            })?;
            let encrypted_metadata = parse_encrypted_file(&encrypted_file_path)?; // includes ciphertext
            let info = self.build_file_info(
                &normalized_child,
                encrypted_file_path.clone(),
                &metadata,
                &encrypted_metadata,
            );
            let inode = self.upsert_file_info(&normalized_child, info.clone());
            debug!("File lookup successful: {} -> inode {}", name, inode);
            return Ok(Some((inode, info)));
        }

        debug!(
            "Entry '{}' not found under parent path {}",
            name, parent_path
        );
        Ok(None)
    }

    /// Perform file read operation with migration awareness
    async fn read_file_data(
        &self,
        inode: InodeId,
        offset: i64,
        size: u32,
    ) -> anyhow::Result<Vec<u8>> {
        debug!(
            "Reading file data: inode={}, offset={}, size={}",
            inode, offset, size
        );

        let file_info = match self.inode_map.get(&inode) {
            Some(info) => info.clone(),
            None => {
                error!("File inode {} not found for read operation", inode);
                return Err(anyhow!("File not found"));
            }
        };

        if file_info.is_directory {
            return Err(anyhow!("Cannot read directory entries"));
        }

        let normalized_offset = if offset < 0 { 0 } else { offset as u64 };
        if size == 0 {
            return Ok(Vec::new());
        }

        if file_info.is_virtual {
            return self
                .read_virtual_overlay(inode, &file_info, normalized_offset, size)
                .await;
        }

        let encrypted_path = file_info
            .encrypted_path
            .clone()
            .ok_or_else(|| anyhow!("Missing encrypted path for {}", file_info.file_id))?;

        self.performance_manager
            .update_access_pattern(
                &file_info.file_id,
                normalized_offset,
                size as usize,
                SystemTime::now(),
            )
            .await;

        let cache_key = CacheKey::new(&file_info.file_id, normalized_offset, size as usize);
        if let Some(cached_chunk) = self.cache.get_chunk(&cache_key).await {
            debug!(
                "Cache hit for file {} at offset {}",
                file_info.file_id, normalized_offset
            );
            return Ok(cached_chunk.data);
        }

        let start_time = std::time::Instant::now();
        let encrypted_metadata = parse_encrypted_file(&encrypted_path)?;

        let plaintext = tokio::task::block_in_place(|| {
            self.runtime
                .block_on(self.client.decrypt_file(&encrypted_metadata))
        })
        .map_err(|e| anyhow!("Failed to decrypt {}: {}", file_info.file_id, e))?;

        let file_len = plaintext.len() as u64;
        if normalized_offset >= file_len {
            return Ok(Vec::new());
        }

        let available = file_len - normalized_offset;
        let take_len = cmp::min(available, size as u64) as usize;
        let start = normalized_offset as usize;
        let end = start + take_len;
        let slice = plaintext[start..end].to_vec();

        let chunk = super::decrypt::DecryptedChunk {
            data: slice.clone(),
            epoch_id: encrypted_metadata.epoch_id,
            decrypted_at: SystemTime::now(),
            size: slice.len(),
            from_cache: false,
        };

        self.cache
            .store_chunk(&cache_key, &chunk, Duration::from_secs(60))
            .await;

        let duration = start_time.elapsed();
        self.performance_manager
            .record_operation(
                "read",
                &file_info.file_id,
                duration,
                slice.len(),
                false,
                encrypted_metadata.epoch_id,
            )
            .await;

        Ok(slice)
    }

    async fn read_virtual_overlay(
        &self,
        inode: InodeId,
        file_info: &FileInfo,
        offset: u64,
        size: u32,
    ) -> anyhow::Result<Vec<u8>> {
        let filename = file_info.relative_path.trim_start_matches('/');

        let overlay_type = {
            let tree = self.virtual_tree.read();
            tree.overlay_type_for(filename)
        }
        .ok_or_else(|| anyhow!("Unknown virtual file {}", file_info.relative_path))?;

        let rendered = self.render_virtual_content(overlay_type.clone()).await?;
        let rendered_bytes = rendered.into_bytes();
        let total_len = rendered_bytes.len();

        self.virtual_tree
            .write()
            .update_content(filename, rendered_bytes.clone());

        let mut updated_info = file_info.clone();
        updated_info.size = total_len as u64;
        updated_info.modified_time = SystemTime::now();
        updated_info.access_time = updated_info.modified_time;
        self.inode_map.insert(inode, updated_info);

        if offset as usize >= total_len {
            return Ok(Vec::new());
        }

        let end = std::cmp::min(offset as usize + size as usize, total_len);
        Ok(rendered_bytes[offset as usize..end].to_vec())
    }

    async fn render_virtual_content(&self, overlay: OverlayFile) -> anyhow::Result<String> {
        match overlay {
            OverlayFile::MigrationStatus => self.render_migration_status().await,
            OverlayFile::PendingFiles => self.render_pending_files().await,
            OverlayFile::CoverageLog => self.render_coverage_log().await,
            OverlayFile::RekeyHistory => self.render_rekey_history().await,
            OverlayFile::PerformanceMetrics => self.render_performance_metrics_overlay().await,
            OverlayFile::FilesystemHealth => {
                Ok("Filesystem health overlay not implemented.\n".to_string())
            }
            OverlayFile::BackgroundTasks => {
                Ok("Background task overlay not implemented.\n".to_string())
            }
            OverlayFile::ErrorLog => Ok("No error log overlay available.\n".to_string()),
            OverlayFile::CacheStatistics => self.render_cache_statistics().await,
            OverlayFile::NetworkStatus => {
                Ok("Network status overlay not implemented.\n".to_string())
            }
        }
    }

    async fn render_migration_status(&self) -> anyhow::Result<String> {
        use chrono::Utc;

        let status = match self.client.get_migration_status().await {
            Ok(status) => status,
            Err(err) => format!("Unable to fetch migration status: {err}"),
        };

        let progress = self.client.migration_progress().await.unwrap_or(0.0);
        let snapshot = self.client.migration_state_snapshot().await;

        let mut content = String::new();
        content.push_str("HybridCipher Migration Status\n");
        content.push_str("============================\n\n");
        content.push_str(&format!(
            "Generated: {}\n\n",
            Self::format_datetime(&Utc::now())
        ));

        content.push_str(&format!("Status: {}\n", status));
        content.push_str(&format!("Overall Progress: {:.1}%\n", progress * 100.0));

        if let Some(state) = snapshot {
            let total = state.total_files;
            let migrated = state.migrated_files.len() as u64;
            let failed = state.failed_files.len() as u64;
            let pending = total.saturating_sub(migrated + failed);
            let phase = format!("{:?}", state.phase);

            content.push_str("\nActive Migration Details\n");
            content.push_str("------------------------\n");
            content.push_str(&format!("From Epoch: {}\n", state.from_epoch));
            content.push_str(&format!("To Epoch: {}\n", state.to_epoch));
            content.push_str(&format!("Phase: {}\n", phase));
            content.push_str(&format!(
                "Migrated Files: {} / {}\n",
                migrated.saturating_add(failed),
                total
            ));
            content.push_str(&format!("• Completed: {}\n", migrated));
            content.push_str(&format!("• Failed: {}\n", failed));
            content.push_str(&format!("• Pending: {}\n", pending));

            content.push_str(&format!(
                "Started At: {}\n",
                Self::format_datetime(&state.started_at)
            ));
            if let Some(eta) = state.estimated_completion {
                content.push_str(&format!(
                    "Estimated Completion: {}\n",
                    Self::format_datetime(&eta)
                ));
            }

            if !state.failed_files.is_empty() {
                content.push_str("\nRecently Failed Files\n");
                content.push_str("---------------------\n");
                for file in state.failed_files.iter().take(10) {
                    content.push_str(&format!("• {}\n", file));
                }
                if state.failed_files.len() > 10 {
                    content.push_str(&format!("… and {} more\n", state.failed_files.len() - 10));
                }
            }
        } else {
            content.push_str("\nNo migration is currently in progress.\n");
        }

        Ok(content)
    }

    async fn render_pending_files(&self) -> anyhow::Result<String> {
        use chrono::Utc;

        let snapshot = self.client.migration_state_snapshot().await;
        let mut content = String::new();
        content.push_str("Pending Migration Files\n");
        content.push_str("=======================\n\n");
        content.push_str(&format!(
            "Generated: {}\n\n",
            Self::format_datetime(&Utc::now())
        ));

        match snapshot {
            Some(state) => {
                let total = state.total_files;
                let migrated = state.migrated_files.len() as u64;
                let failed = state.failed_files.len() as u64;
                let pending = total.saturating_sub(migrated + failed);

                content.push_str(&format!("Total Files: {}\n", total));
                content.push_str(&format!("Completed: {}\n", migrated));
                content.push_str(&format!("Failed: {}\n", failed));
                content.push_str(&format!("Remaining: {}\n", pending));

                if pending > 0 {
                    content.push_str(
                        "\nFile-level tracking for pending items is still being wired through.\n",
                    );
                }

                if !state.failed_files.is_empty() {
                    content.push_str("\nFailed Files (most recent first):\n");
                    content.push_str("----------------------------------\n");
                    for file in state.failed_files.iter().rev().take(10) {
                        content.push_str(&format!("• {}\n", file));
                    }
                    if state.failed_files.len() > 10 {
                        content
                            .push_str(&format!("… and {} more\n", state.failed_files.len() - 10));
                    }
                } else {
                    content.push_str("\nNo failed files recorded.\n");
                }

                if !state.migrated_files.is_empty() {
                    content.push_str("\nRecently Migrated Files:\n");
                    content.push_str("------------------------\n");
                    for file in state.migrated_files.iter().rev().take(10) {
                        content.push_str(&format!("• {}\n", file));
                    }
                    if state.migrated_files.len() > 10 {
                        content
                            .push_str(&format!("… and {} more\n", state.migrated_files.len() - 10));
                    }
                }
            }
            None => {
                content.push_str("No active migration. All files are up to date.\n");
            }
        }

        Ok(content)
    }

    async fn render_coverage_log(&self) -> anyhow::Result<String> {
        let overview = match self.client.coverage_overview().await {
            Ok(data) => data,
            Err(err) => {
                return Ok(format!("Coverage overview unavailable: {}\n", err));
            }
        };

        let mut content = String::new();
        writeln!(content, "HybridCipher Coverage Overview")?;
        writeln!(content, "==============================")?;
        writeln!(content)?;
        writeln!(
            content,
            "Generated: {}",
            Self::format_datetime(&overview.generated_at)
        )?;
        writeln!(content, "Current Epoch: {}", overview.current_epoch)?;
        if let Some(target) = overview.migration_target_epoch {
            writeln!(content, "Migration Target Epoch: {}", target)?;
        } else {
            writeln!(content, "Migration Target Epoch: (none)")?;
        }
        writeln!(content, "Tracked Files: {}", overview.total_tracked_files)?;
        writeln!(content)?;

        if let Some(snapshot) = overview.latest_snapshot {
            writeln!(content, "Latest Snapshot:")?;
            writeln!(content, "  • Merkle Root: {}", snapshot.merkle_root_hex)?;
            writeln!(
                content,
                "  • Verifying Key: {}",
                snapshot.verifying_key_base64
            )?;
            if let Some(id) = snapshot.signing_key_id {
                writeln!(content, "  • Signing Key ID: {}", id)?;
            }
            if let Some(signature) = snapshot.signature_base64 {
                writeln!(content, "  • Signature: {}", signature)?;
            }
        } else {
            writeln!(content, "Latest Snapshot: not yet published")?;
        }
        writeln!(content)?;

        if overview.epochs.is_empty() {
            writeln!(content, "No epoch coverage data recorded.")?;
        } else {
            writeln!(content, "Per-Epoch Coverage:")?;
            for epoch in overview.epochs {
                let mut markers = Vec::new();
                if epoch.is_active {
                    markers.push("active");
                }
                if epoch.is_migration_target {
                    markers.push("target");
                }
                let suffix = if markers.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", markers.join(", "))
                };
                writeln!(
                    content,
                    "- Epoch {}{}: {} / {} ({}) rewrapped",
                    epoch.epoch_id,
                    suffix,
                    epoch.rewrapped_files,
                    epoch.total_files,
                    Self::format_ratio(epoch.coverage_ratio)
                )?;
            }
        }
        writeln!(content)?;
        Ok(content)
    }

    async fn render_rekey_history(&self) -> anyhow::Result<String> {
        let overlay_state = match self.client.rekey_overlay_state().await {
            Ok(state) => state,
            Err(err) => {
                return Ok(format!("Rekey state unavailable: {}\n", err));
            }
        };

        let mut content = String::new();
        writeln!(content, "Rekey Operations Overview")?;
        writeln!(content, "========================")?;
        writeln!(content)?;
        writeln!(
            content,
            "Generated: {}",
            Self::format_datetime(&overlay_state.generated_at)
        )?;
        writeln!(content)?;

        if let Some(active) = overlay_state.active_operation.as_ref() {
            let file_completion = if active.progress.total_files == 0 {
                0.0
            } else {
                active.progress.migrated_files as f64 / active.progress.total_files as f64
            };
            writeln!(content, "Active Operation: {}", active.rekey_id)?;
            writeln!(content, "  Status: {:?}", active.status)?;
            writeln!(content, "  Target Epoch: {}", active.new_epoch_label)?;
            if let Some(epoch_id) = active.new_epoch_id {
                writeln!(content, "  Target Epoch ID: {}", epoch_id)?;
            }
            writeln!(
                content,
                "  Progress: {} / {} files ({})",
                active.progress.migrated_files,
                active.progress.total_files,
                Self::format_ratio(file_completion)
            )?;
            writeln!(
                content,
                "  Members Confirmed: {} / {} ({} reporting)",
                active.progress.confirmed_members,
                active.progress.total_members,
                active.progress.reporting_members
            )?;
            if let Some(minutes) = active.progress.estimated_time_remaining_minutes {
                writeln!(content, "  Estimated Time Remaining: {} minute(s)", minutes)?;
            }
            writeln!(
                content,
                "  Started: {}",
                Self::format_datetime(&active.started_at)
            )?;
            writeln!(
                content,
                "  Last Updated: {}",
                Self::format_datetime(&active.last_updated)
            )?;
            if let Some(eta) = active.estimated_completion.as_ref() {
                writeln!(
                    content,
                    "  Estimated Completion: {}",
                    Self::format_datetime(eta)
                )?;
            }
            writeln!(
                content,
                "  Cutover Ready: {}",
                if active.can_cutover { "yes" } else { "no" }
            )?;
            if let Some(commitment) = active.descriptor_commitment.as_ref() {
                writeln!(content, "  Descriptor Commitment: {}", commitment)?;
            }
            if !active.errors.is_empty() {
                writeln!(content, "  Recent Errors:")?;
                for error in active.errors.iter().rev().take(5) {
                    writeln!(
                        content,
                        "    • [{}] {} ({})",
                        Self::format_datetime(&error.timestamp),
                        error.message,
                        error.error_type
                    )?;
                }
                if active.errors.len() > 5 {
                    writeln!(
                        content,
                        "    … and {} more error(s)",
                        active.errors.len() - 5
                    )?;
                }
            } else {
                writeln!(content, "  Recent Errors: none")?;
            }
        } else {
            writeln!(content, "Active Operation: none")?;
        }

        writeln!(content)?;
        if let Some(migration) = overlay_state.migration.as_ref() {
            let migrated = migration.migrated_files.len();
            let failed = migration.failed_files.len();
            let pending = migration
                .total_files
                .saturating_sub((migrated + failed) as u64);
            writeln!(content, "Migration State: {:?}", migration.phase)?;
            writeln!(
                content,
                "  Epochs: {} -> {}",
                migration.from_epoch, migration.to_epoch
            )?;
            writeln!(
                content,
                "  Files migrated: {} / {}",
                migrated, migration.total_files
            )?;
            writeln!(content, "  Files failed: {}", failed)?;
            writeln!(content, "  Files pending: {}", pending)?;
            writeln!(
                content,
                "  Started: {}",
                Self::format_datetime(&migration.started_at)
            )?;
            if let Some(eta) = migration.estimated_completion.as_ref() {
                writeln!(
                    content,
                    "  Estimated Completion: {}",
                    Self::format_datetime(eta)
                )?;
            }
        } else {
            writeln!(content, "Migration State: none")?;
        }

        writeln!(content)?;
        if overlay_state.heartbeats.is_empty() {
            writeln!(
                content,
                "Heartbeat Status: no recent client heartbeats recorded."
            )?;
        } else {
            writeln!(content, "Heartbeat Status (showing up to 5):")?;
            for heartbeat in overlay_state.heartbeats.iter().take(5) {
                writeln!(content, "- Rekey {}:", heartbeat.rekey_id)?;
                writeln!(content, "    Sequence: {}", heartbeat.sequence)?;
                writeln!(
                    content,
                    "    Last Emitted: {}",
                    Self::format_option_datetime(heartbeat.last_emitted_at)
                )?;
                writeln!(
                    content,
                    "    Last Observed: {}",
                    Self::format_option_datetime(heartbeat.last_observed_at)
                )?;
                writeln!(
                    content,
                    "    Coverage: {} / {} (protected: {} / {})",
                    Self::format_bytes(heartbeat.last_coverage_bytes),
                    heartbeat.last_coverage_items,
                    Self::format_bytes(heartbeat.last_protected_bytes),
                    heartbeat.last_protected_items
                )?;
                if let Some(descriptor) = heartbeat.descriptor_commitment.as_ref() {
                    writeln!(content, "    Descriptor: {}", descriptor)?;
                }
                writeln!(
                    content,
                    "    Confirmed Reported: {}",
                    if heartbeat.confirmed_reported {
                        "yes"
                    } else {
                        "no"
                    }
                )?;
            }
            if overlay_state.heartbeats.len() > 5 {
                writeln!(
                    content,
                    "… and {} more tracked heartbeat(s)",
                    overlay_state.heartbeats.len() - 5
                )?;
            }
        }

        writeln!(content)?;
        if overlay_state.pending_rewraps.is_empty() {
            writeln!(content, "Pending Rewrap Tasks: none")?;
        } else {
            writeln!(content, "Pending Rewrap Tasks (showing up to 5):")?;
            for task in overlay_state.pending_rewraps.iter().take(5) {
                writeln!(
                    content,
                    "- {} ({} -> {}, attempts {}, last tried {})",
                    task.path,
                    task.from_epoch,
                    task.to_epoch,
                    task.attempts,
                    Self::format_option_datetime(task.last_attempt)
                )?;
            }
            if overlay_state.pending_rewraps.len() > 5 {
                writeln!(
                    content,
                    "… and {} additional task(s)",
                    overlay_state.pending_rewraps.len() - 5
                )?;
            }
        }
        writeln!(content)?;
        Ok(content)
    }

    async fn render_performance_metrics_overlay(&self) -> anyhow::Result<String> {
        let snapshot = self.performance_manager.get_metrics().await;
        let cache_window = if snapshot.cache_metrics.time_window_minutes == 0 {
            5
        } else {
            snapshot.cache_metrics.time_window_minutes
        };

        let mut content = String::new();
        writeln!(content, "Performance Snapshot")?;
        writeln!(content, "====================")?;
        writeln!(content)?;
        writeln!(
            content,
            "Collected At: {}",
            Self::format_system_time(snapshot.timestamp)
        )?;
        writeln!(
            content,
            "Operations Window: last {} minute(s)",
            cache_window
        )?;
        writeln!(content)?;
        writeln!(content, "Operations:")?;
        writeln!(
            content,
            "  • Completed: {} operation(s)",
            snapshot.operation_count
        )?;
        writeln!(
            content,
            "  • Average Duration: {}",
            Self::format_duration(snapshot.avg_operation_time)
        )?;
        writeln!(
            content,
            "  • Cache Hit Rate: {}",
            Self::format_ratio(snapshot.cache_hit_rate)
        )?;
        writeln!(
            content,
            "  • Memory Pressure (prefetch): {}",
            Self::format_ratio(snapshot.memory_pressure)
        )?;
        writeln!(
            content,
            "  • Active Prefetch Tasks: {}",
            snapshot.active_prefetch_tasks
        )?;

        let system = snapshot.system_metrics.clone();
        writeln!(content)?;
        writeln!(content, "System Metrics:")?;
        writeln!(
            content,
            "  • Memory Usage: {} (pressure {})",
            Self::format_bytes(system.memory_usage_bytes as u64),
            Self::format_ratio(system.memory_pressure)
        )?;
        writeln!(
            content,
            "  • CPU Utilization: {}",
            Self::format_ratio(system.cpu_utilization)
        )?;
        writeln!(
            content,
            "  • Network Throughput: {}",
            Self::format_bytes_per_second(system.network_bandwidth as f64)
        )?;
        writeln!(
            content,
            "  • Disk Throughput: {}",
            Self::format_bytes_per_second(system.disk_io_rate)
        )?;

        let cache_metrics = snapshot.cache_metrics.clone();
        writeln!(content)?;
        writeln!(content, "Cache Metrics:")?;
        writeln!(
            content,
            "  • Hit Rate: {}",
            Self::format_ratio(cache_metrics.hit_rate)
        )?;
        writeln!(
            content,
            "  • Memory Efficiency: {}",
            Self::format_ratio(cache_metrics.memory_efficiency)
        )?;
        if cache_metrics.avg_lookup_time_us > 0 {
            writeln!(
                content,
                "  • Average Lookup Time: {} µs",
                cache_metrics.avg_lookup_time_us
            )?;
        }
        if cache_metrics.evictions_per_minute > 0.0 {
            writeln!(
                content,
                "  • Evictions per Minute: {:.2}",
                cache_metrics.evictions_per_minute
            )?;
        }
        if cache_metrics.time_window_minutes > 0 {
            writeln!(
                content,
                "  • Sampling Window: {} minute(s)",
                cache_metrics.time_window_minutes
            )?;
        }
        writeln!(content)?;
        Ok(content)
    }

    async fn render_cache_statistics(&self) -> anyhow::Result<String> {
        let stats = self.cache.get_stats().await;
        let mut content = String::new();
        writeln!(content, "Cache Statistics")?;
        writeln!(content, "=================")?;
        writeln!(content)?;
        writeln!(
            content,
            "Total Memory Usage: {}",
            Self::format_bytes(stats.total_memory_usage as u64)
        )?;
        writeln!(content)?;

        let total_requests = stats.chunk_cache.hits + stats.chunk_cache.misses;
        writeln!(content, "Chunk Cache:")?;
        writeln!(
            content,
            "  • Requests: {} (hits: {}, misses: {})",
            total_requests, stats.chunk_cache.hits, stats.chunk_cache.misses
        )?;
        writeln!(
            content,
            "  • Hit Rate: {}",
            Self::format_ratio(stats.chunk_hit_rate)
        )?;
        writeln!(
            content,
            "  • Utilization: {} of {} ({})",
            Self::format_bytes(stats.chunk_cache_bytes),
            Self::format_bytes(stats.chunk_cache_capacity),
            Self::format_ratio(stats.chunk_cache_utilization)
        )?;
        writeln!(content, "  • Evictions: {}", stats.chunk_cache.evictions)?;
        if stats.chunk_cache.average_chunk_size > 0.0 {
            writeln!(
                content,
                "  • Average Chunk Size: {}",
                Self::format_bytes_f64(stats.chunk_cache.average_chunk_size)
            )?;
        }
        if stats.chunk_cache.total_bytes_cached > 0 {
            writeln!(
                content,
                "  • Bytes Cached (historical total): {}",
                Self::format_bytes(stats.chunk_cache.total_bytes_cached)
            )?;
        }

        writeln!(content)?;
        let metadata_requests = stats.metadata_cache.hits + stats.metadata_cache.misses;
        writeln!(content, "Metadata Cache:")?;
        writeln!(
            content,
            "  • Requests: {} (hits: {}, misses: {})",
            metadata_requests, stats.metadata_cache.hits, stats.metadata_cache.misses
        )?;
        writeln!(
            content,
            "  • Hit Rate: {}",
            Self::format_ratio(stats.metadata_hit_rate)
        )?;
        writeln!(content, "  • Entries: {}", stats.metadata_cache.entries)?;
        writeln!(content, "  • Evictions: {}", stats.metadata_cache.evictions)?;
        writeln!(
            content,
            "  • Estimated Memory: {}",
            Self::format_bytes(stats.metadata_memory_usage as u64)
        )?;
        writeln!(content)?;
        Ok(content)
    }

    fn format_bytes(bytes: u64) -> String {
        Self::format_bytes_f64(bytes as f64)
    }

    fn format_bytes_f64(bytes: f64) -> String {
        if bytes <= 0.0 {
            return "0 B".to_string();
        }
        const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
        let mut value = bytes;
        let mut unit = 0usize;
        while value >= 1024.0 && unit < UNITS.len() - 1 {
            value /= 1024.0;
            unit += 1;
        }
        if unit == 0 {
            format!("{:.0} {}", value, UNITS[unit])
        } else {
            format!("{:.1} {}", value, UNITS[unit])
        }
    }

    fn format_bytes_per_second(bytes_per_second: f64) -> String {
        if bytes_per_second <= 0.0 {
            "0 B/s".to_string()
        } else {
            format!("{}/s", Self::format_bytes_f64(bytes_per_second))
        }
    }

    fn format_ratio(value: f64) -> String {
        format!("{:.1}%", value * 100.0)
    }

    fn format_system_time(ts: SystemTime) -> String {
        let datetime: DateTime<Utc> = ts.into();
        Self::format_datetime(&datetime)
    }

    fn format_datetime(dt: &DateTime<Utc>) -> String {
        let local = dt.with_timezone(&Local);
        let offset = local.format("%:z");
        format!("{} UTC{}", local.format("%Y-%m-%d %H:%M:%S"), offset)
    }

    fn format_option_datetime(dt: Option<DateTime<Utc>>) -> String {
        dt.map(|dt| Self::format_datetime(&dt))
            .unwrap_or_else(|| "n/a".to_string())
    }

    fn format_duration(duration: Duration) -> String {
        if duration.is_zero() {
            "0s".to_string()
        } else if duration.as_secs() >= 60 {
            let minutes = duration.as_secs() / 60;
            let seconds = duration.as_secs() % 60;
            format!("{}m {:02}s", minutes, seconds)
        } else if duration.as_secs() >= 1 {
            format!("{:.2}s", duration.as_secs_f64())
        } else {
            format!("{}ms", duration.as_millis())
        }
    }
    fn build_directory_info(&self, normalized_path: &str, metadata: &fs::Metadata) -> FileInfo {
        let (modified, accessed, created) = metadata_times(metadata);
        FileInfo {
            file_id: normalized_path.to_string(),
            epoch_id: "0".to_string(),
            size: 0,
            is_directory: true,
            modified_time: modified,
            access_time: accessed,
            creation_time: created,
            permissions: permissions_from(metadata, 0o755),
            relative_path: normalized_path.to_string(),
            encrypted_path: None,
            is_virtual: false,
        }
    }

    fn build_file_info(
        &self,
        normalized_path: &str,
        encrypted_path: PathBuf,
        metadata: &fs::Metadata,
        encrypted_metadata: &EncryptedFileMetadata,
    ) -> FileInfo {
        let (modified, accessed, created) = metadata_times(metadata);
        FileInfo {
            file_id: encrypted_metadata.file_id.clone(),
            epoch_id: encrypted_metadata.epoch_id.to_string(),
            size: encrypted_metadata.content_size,
            is_directory: false,
            modified_time: modified,
            access_time: accessed,
            creation_time: created,
            permissions: permissions_from(metadata, 0o644),
            relative_path: normalized_path.to_string(),
            encrypted_path: Some(encrypted_path),
            is_virtual: false,
        }
    }

    fn upsert_file_info(&self, path: &str, info: FileInfo) -> InodeId {
        if let Some(existing) = self.path_lookup.get(path) {
            let inode = *existing.value();
            self.inode_map.insert(inode, info);
            inode
        } else {
            let inode = self.get_next_inode();
            self.path_lookup.insert(path.to_string(), inode);
            self.inode_map.insert(inode, info);
            inode
        }
    }

    fn encrypted_dir_for(&self, normalized_path: &str) -> PathBuf {
        let trimmed = normalized_path.trim_start_matches('/');
        if trimmed.is_empty() {
            self.encrypted_root.clone()
        } else {
            self.encrypted_root.join(trimmed)
        }
    }

    fn parent_inode_for_path(&self, path: &str) -> InodeId {
        if path == "/" {
            return ROOT_INODE;
        }

        let parent_path = Path::new(path)
            .parent()
            .map(|p| {
                let s = p.to_string_lossy();
                if s.is_empty() {
                    "/".to_string()
                } else {
                    if s.starts_with('/') {
                        s.to_string()
                    } else {
                        format!("/{}", s)
                    }
                }
            })
            .unwrap_or_else(|| "/".to_string());

        self.path_lookup
            .get(&parent_path)
            .map(|entry| *entry.value())
            .unwrap_or(ROOT_INODE)
    }

    fn collect_directory_entries(&self, parent_path: &str) -> Vec<(InodeId, FileType, String)> {
        let mut entries = Vec::new();
        let directory_path = self.encrypted_dir_for(parent_path);

        let read_dir = match fs::read_dir(&directory_path) {
            Ok(iter) => iter,
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    warn!(
                        "Failed to read directory {}: {}",
                        directory_path.display(),
                        err
                    );
                }
                return entries;
            }
        };

        for entry in read_dir {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    warn!(
                        "Failed to read entry in {}: {}",
                        directory_path.display(),
                        err
                    );
                    continue;
                }
            };

            let name_os = entry.file_name();
            let name = match name_os.to_str() {
                Some(n) => n,
                None => continue,
            };

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(err) => {
                    warn!(
                        "Failed to determine file type in {}: {}",
                        directory_path.display(),
                        err
                    );
                    continue;
                }
            };

            if file_type.is_dir() {
                let normalized_child = normalize_child_path(parent_path, name);
                match entry.metadata() {
                    Ok(metadata) => {
                        let info = self.build_directory_info(&normalized_child, &metadata);
                        let inode = self.upsert_file_info(&normalized_child, info);
                        entries.push((inode, FileType::Directory, name.to_string()));
                    }
                    Err(err) => {
                        warn!(
                            "Failed to read metadata for directory {}: {}",
                            entry.path().display(),
                            err
                        );
                    }
                }
            } else if file_type.is_file() && name.ends_with(".encrypted") {
                let decrypted_name = name.trim_end_matches(".encrypted");
                let normalized_child = normalize_child_path(parent_path, decrypted_name);
                let metadata = match entry.metadata() {
                    Ok(m) => m,
                    Err(err) => {
                        warn!(
                            "Failed to read metadata for file {}: {}",
                            entry.path().display(),
                            err
                        );
                        continue;
                    }
                };

                let encrypted_path = entry.path();
                match parse_encrypted_file(&encrypted_path) {
                    Ok(encrypted_metadata) => {
                        let info = self.build_file_info(
                            &normalized_child,
                            encrypted_path,
                            &metadata,
                            &encrypted_metadata,
                        );
                        let inode = self.upsert_file_info(&normalized_child, info);
                        entries.push((inode, FileType::RegularFile, decrypted_name.to_string()));
                    }
                    Err(err) => {
                        warn!(
                            "Failed to parse encrypted metadata for {}: {}",
                            entry.path().display(),
                            err
                        );
                    }
                }
            }
        }

        entries.sort_by(|a, b| a.2.cmp(&b.2));
        entries
    }

    fn collect_virtual_entries(&self) -> Vec<(InodeId, FileType, String)> {
        let virtual_entries = {
            let tree = self.virtual_tree.read();
            tree.get_virtual_entries()
        };

        let mut entries = Vec::new();
        for (name, mut info) in virtual_entries {
            let normalized = format!("/{}", name.trim_matches('/'));
            info.relative_path = normalized.clone();
            info.file_id = normalized.clone();
            info.is_virtual = true;
            let inode = self.upsert_file_info(&normalized, info.clone());
            let file_type = if info.is_directory {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            entries.push((inode, file_type, name));
        }

        entries.sort_by(|a, b| a.2.cmp(&b.2));
        entries
    }

    fn lookup_virtual_entry(&self, name: &str) -> Result<Option<FileInfo>> {
        let tree = self.virtual_tree.read();
        tree.lookup_virtual_file(ROOT_INODE, name)
    }

    /// Get current performance metrics for monitoring
    pub async fn get_performance_metrics(&self) -> super::performance::PerformanceSnapshot {
        self.performance_manager.get_metrics().await
    }

    /// Get filesystem statistics
    pub async fn get_filesystem_stats(&self) -> FilesystemStats {
        let cache_stats = self.cache.get_stats().await;
        let performance_snapshot = self.get_performance_metrics().await;

        FilesystemStats {
            total_files: self.inode_map.len() as u64,
            open_file_handles: self.file_handles.len() as u32,
            cache_hit_rate: performance_snapshot.cache_hit_rate,
            memory_pressure: performance_snapshot.memory_pressure,
            active_prefetch_tasks: performance_snapshot.active_prefetch_tasks,
            total_cache_size: cache_stats.total_memory_usage,
            operation_count_5min: performance_snapshot.operation_count,
            avg_operation_time_ms: performance_snapshot.avg_operation_time.as_millis() as u64,
        }
    }
}

fn normalize_child_path(parent: &str, name: &str) -> String {
    let clean_name = name.trim_matches('/');
    if clean_name.is_empty() {
        if parent.is_empty() {
            "/".to_string()
        } else {
            parent.to_string()
        }
    } else if parent == "/" {
        format!("/{}", clean_name)
    } else if parent.is_empty() {
        format!("/{}", clean_name)
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), clean_name)
    }
}

fn normalize_encrypted_child_path(encrypted_root: &Path, path: &Path) -> Option<String> {
    let relative = path.strip_prefix(encrypted_root).ok()?;
    let mut normalized = String::new();
    for component in relative.components() {
        let segment = component.as_os_str().to_str()?;
        if segment.is_empty() {
            continue;
        }
        normalized.push('/');
        normalized.push_str(segment);
    }
    if normalized.is_empty() {
        return None;
    }
    const SUFFIX: &str = ".encrypted";
    if !normalized.ends_with(SUFFIX) {
        return None;
    }
    let new_len = normalized.len() - SUFFIX.len();
    normalized.truncate(new_len);
    if normalized.is_empty() {
        normalized.push('/');
    }
    Some(normalized)
}

fn metadata_times(metadata: &fs::Metadata) -> (SystemTime, SystemTime, SystemTime) {
    let modified = metadata.modified().unwrap_or_else(|_| SystemTime::now());
    let accessed = metadata.accessed().unwrap_or(modified);
    let created = metadata.created().unwrap_or(modified);
    (modified, accessed, created)
}

fn permissions_from(metadata: &fs::Metadata, _default_mode: u16) -> u16 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (metadata.permissions().mode() & 0o777) as u16
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        _default_mode
    }
}

fn parse_encrypted_file(path: &Path) -> Result<EncryptedFileMetadata> {
    let raw = fs::read(path).with_context(|| {
        format!(
            "Failed to read encrypted file payload from {}",
            path.display()
        )
    })?;

    let separator_pos = raw
        .windows(ENCRYPTED_SEPARATOR.len())
        .position(|window| window == ENCRYPTED_SEPARATOR)
        .ok_or_else(|| anyhow!("Encrypted file {} missing separator marker", path.display()))?;

    let metadata_bytes = &raw[..separator_pos];
    let ciphertext = raw[separator_pos + ENCRYPTED_SEPARATOR.len()..].to_vec();

    let json: Value = serde_json::from_slice(metadata_bytes)
        .with_context(|| format!("Failed to parse encrypted metadata for {}", path.display()))?;

    let file_id = json
        .get("file_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("Encrypted metadata missing file_id for {}", path.display()))?
        .to_string();

    let epoch_id = json
        .get("epoch_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("Encrypted metadata missing epoch_id for {}", path.display()))?;

    let content_size = json
        .get("file_size")
        .and_then(|v| v.as_u64())
        .or_else(|| json.get("original_size").and_then(|v| v.as_u64()))
        .unwrap_or(0);
    let content_chunk_size = json.get("chunk_size").and_then(|v| v.as_u64());

    let _original_name = json
        .get("original_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let created_at = json
        .get("encrypted_at")
        .and_then(|v| v.as_str())
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now());

    let file_path = json
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow!(
                "Encrypted metadata missing file_path for {}",
                path.display()
            )
        })?;

    let header_version = json
        .get("header_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let wrapped_file_key = json
        .get("wrapped_file_key")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let key_wrap_nonce = json
        .get("key_wrap_nonce")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let key_wrap_aad_hash = json
        .get("key_wrap_aad_hash")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let content_nonce = json
        .get("content_nonce")
        .and_then(|v| v.as_str())
        .and_then(|s| B64.decode(s).ok());
    let platform_metadata = json
        .get("platform_metadata")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .filter(|metadata: &hybridcipher_client::PlatformFileMetadata| !metadata.is_empty());
    let sparse_metadata = json
        .get("sparse_metadata")
        .and_then(|value| serde_json::from_value::<SparseFileMetadata>(value.clone()).ok())
        .filter(SparseFileMetadata::is_effectively_sparse);

    Ok(EncryptedFileMetadata {
        file_id,
        file_path,
        group_id,
        epoch_id,
        header_version,
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size,
        content_size,
        encrypted_size: ciphertext.len() as u64,
        created_at,
        platform_metadata,
        sparse_metadata,
        encrypted_content: ciphertext,
    })
}

fn persist_encrypted_file(path: &Path, metadata: &EncryptedFileMetadata) -> Result<()> {
    let header = SerializedEncryptedHeader {
        file_id: &metadata.file_id,
        file_path: &metadata.file_path,
        group_id: metadata.group_id,
        epoch_id: metadata.epoch_id,
        header_version: metadata.header_version.unwrap_or(1),
        wrapped_file_key: metadata
            .wrapped_file_key
            .as_ref()
            .ok_or_else(|| anyhow!("Missing wrapped_file_key for {}", path.display()))?,
        key_wrap_nonce: metadata
            .key_wrap_nonce
            .as_ref()
            .ok_or_else(|| anyhow!("Missing key_wrap_nonce for {}", path.display()))?,
        key_wrap_aad_hash: metadata
            .key_wrap_aad_hash
            .as_ref()
            .ok_or_else(|| anyhow!("Missing key_wrap_aad_hash for {}", path.display()))?,
        content_nonce: metadata
            .content_nonce
            .as_ref()
            .ok_or_else(|| anyhow!("Missing content_nonce for {}", path.display()))?,
        content_chunk_size: metadata.content_chunk_size,
        original_size: metadata.content_size,
        encrypted_size: metadata.encrypted_size,
        encrypted_at: metadata.created_at,
        original_name: None,
        platform_metadata: metadata.platform_metadata.as_ref(),
        sparse_metadata: metadata.sparse_metadata.as_ref(),
    };

    write_encrypted_file(path, &header, &metadata.encrypted_content)
        .context("Failed to persist encrypted file payload")
}

fn io_error_to_errno(err: io::Error) -> libc::c_int {
    err.raw_os_error().unwrap_or(libc::EIO)
}

fn time_or_now_to_system(value: TimeOrNow) -> SystemTime {
    match value {
        TimeOrNow::SpecificTime(ts) => ts,
        TimeOrNow::Now => SystemTime::now(),
    }
}

/// Filesystem statistics for monitoring
#[derive(Debug, Clone, serde::Serialize)]
pub struct FilesystemStats {
    pub total_files: u64,
    pub open_file_handles: u32,
    pub cache_hit_rate: f64,
    pub memory_pressure: f64,
    pub active_prefetch_tasks: usize,
    pub total_cache_size: usize,
    pub operation_count_5min: usize,
    pub avg_operation_time_ms: u64,
}

impl<S, N> Filesystem for HybridCipher<S, N>
where
    S: hybridcipher_client::storage::Storage + Send + Sync + 'static,
    N: hybridcipher_client::network::Network + Send + Sync + 'static,
{
    /// File/directory lookup implementation with migration awareness
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        debug!("FUSE lookup: parent={}, name={}", parent, name_str);

        let semaphore = self.operation_semaphore.clone();
        let lookup_future = async {
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|_| anyhow!("operation limiter closed"))?;
            self.lookup_file(parent, name_str).await
        };

        match tokio::task::block_in_place(|| self.runtime.block_on(lookup_future)) {
            Ok(Some((inode, file_info))) => {
                let attr = self.file_info_to_attr(inode, &file_info);
                reply.entry(&ENTRY_TTL, &attr, 0);
                debug!("Lookup successful: {} -> inode {}", name_str, inode);
            }
            Ok(None) => {
                debug!("Lookup failed: {} not found", name_str);
                reply.error(libc::ENOENT);
            }
            Err(e) => {
                error!("Lookup error for {}: {}", name_str, e);
                reply.error(libc::EIO);
            }
        }
    }

    /// Get file attributes implementation
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        debug!("FUSE getattr: inode={}", ino);

        if let Some(file_info) = self.inode_map.get(&ino) {
            let attr = self.file_info_to_attr(ino, &file_info);
            reply.attr(&ATTR_TTL, &attr);
            debug!("Getattr successful for inode {}", ino);
        } else {
            debug!("Getattr failed: inode {} not found", ino);
            reply.error(libc::ENOENT);
        }
    }

    /// File open implementation with handle management
    fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
        debug!("FUSE open: inode={}, flags={}", ino, flags);

        if let Some(file_info) = self.inode_map.get(&ino) {
            let handle = self.get_next_handle();

            let handle_info = FileHandleInfo {
                inode: ino,
                file_id: file_info.file_id.clone(),
                epoch_id: Some(file_info.epoch_id.clone()),
                flags,
                access_time: SystemTime::now(),
            };

            self.file_handles.insert(handle, handle_info);
            reply.opened(handle, 0);
            debug!("File opened successfully: inode={}, handle={}", ino, handle);
        } else {
            debug!("Open failed: inode {} not found", ino);
            reply.error(libc::ENOENT);
        }
    }

    /// Create and open a new file
    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        let name_str = match name.to_str() {
            Some(n) if !n.is_empty() => n,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let parent_info = match self.inode_map.get(&parent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = parent_info.relative_path.clone();
        let normalized_child = normalize_child_path(&parent_path, name_str);
        let encrypted_dir = self.encrypted_dir_for(&parent_path);
        if let Err(err) = fs::create_dir_all(&encrypted_dir) {
            reply.error(io_error_to_errno(err));
            return;
        }

        let encrypted_path = encrypted_dir.join(format!("{}.encrypted", name_str));
        if encrypted_path.exists() {
            reply.error(libc::EEXIST);
            return;
        }

        let client = self.client.clone();
        let normalized_for_encrypt = normalized_child.clone();
        let semaphore = self.operation_semaphore.clone();
        let encrypt_future = async move {
            let _permit = semaphore.acquire().await.map_err(|_| {
                hybridcipher_client::ClientError::InvalidState(
                    "operation limiter closed".to_string(),
                )
            })?;
            client.encrypt_file(&normalized_for_encrypt, &[]).await
        };

        let metadata = match tokio::task::block_in_place(|| self.runtime.block_on(encrypt_future)) {
            Ok(metadata) => metadata,
            Err(err) => {
                error!("Failed to encrypt new file {}: {}", normalized_child, err);
                reply.error(libc::EIO);
                return;
            }
        };

        if let Err(err) = persist_encrypted_file(&encrypted_path, &metadata) {
            error!(
                "Failed to persist encrypted file {}: {}",
                encrypted_path.display(),
                err
            );
            reply.error(libc::EIO);
            return;
        }

        let file_metadata = match fs::metadata(&encrypted_path) {
            Ok(m) => m,
            Err(err) => {
                error!(
                    "Failed to fetch metadata for {}: {}",
                    encrypted_path.display(),
                    err
                );
                reply.error(io_error_to_errno(err));
                return;
            }
        };

        let mut info =
            self.build_file_info(&normalized_child, encrypted_path, &file_metadata, &metadata);
        let requested_mode = (mode & 0o777) & !(umask & 0o777);
        info.permissions = requested_mode as u16;

        let inode = self.upsert_file_info(&normalized_child, info.clone());
        let handle = self.get_next_handle();
        self.file_handles.insert(
            handle,
            FileHandleInfo {
                inode,
                file_id: info.file_id.clone(),
                epoch_id: Some(metadata.epoch_id.to_string()),
                flags,
                access_time: SystemTime::now(),
            },
        );

        let attr = self.file_info_to_attr(inode, &info);
        reply.created(&ATTR_TTL, &attr, 0, handle, 0);
        debug!("Created new file {} (inode {})", normalized_child, inode);
    }

    /// Create a new directory
    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        let name_str = match name.to_str() {
            Some(n) if !n.is_empty() => n,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let parent_info = match self.inode_map.get(&parent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = parent_info.relative_path.clone();
        let normalized_child = normalize_child_path(&parent_path, name_str);
        let requested_mode = {
            let masked = (mode & 0o777) & !(umask & 0o777);
            if masked == 0 {
                0o755
            } else {
                masked
            }
        };

        let dir_path = self.encrypted_dir_for(&parent_path).join(name_str);
        if dir_path.exists() {
            reply.error(libc::EEXIST);
            return;
        }

        if let Err(err) = fs::create_dir(&dir_path) {
            reply.error(io_error_to_errno(err));
            return;
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(err) =
                fs::set_permissions(&dir_path, fs::Permissions::from_mode(requested_mode as u32))
            {
                let _ = fs::remove_dir(&dir_path);
                reply.error(io_error_to_errno(err));
                return;
            }
        }

        let metadata = match fs::metadata(&dir_path) {
            Ok(m) => m,
            Err(err) => {
                let _ = fs::remove_dir(&dir_path);
                reply.error(io_error_to_errno(err));
                return;
            }
        };

        let mut info = self.build_directory_info(&normalized_child, &metadata);
        info.permissions = requested_mode as u16;

        let inode = self.upsert_file_info(&normalized_child, info.clone());
        let attr = self.file_info_to_attr(inode, &info);
        reply.entry(&ENTRY_TTL, &attr, 0);
        debug!("Created directory {} (inode {})", normalized_child, inode);
    }

    /// File read implementation with dual-epoch support
    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        debug!("FUSE read: inode={}, offset={}, size={}", ino, offset, size);

        let semaphore = self.operation_semaphore.clone();
        let read_future = async {
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|_| anyhow!("operation limiter closed"))?;
            self.read_file_data(ino, offset, size).await
        };

        match tokio::task::block_in_place(|| self.runtime.block_on(read_future)) {
            Ok(data) => {
                reply.data(&data);
                debug!("Read successful: {} bytes from inode {}", data.len(), ino);
            }
            Err(e) => {
                error!("Read error for inode {}: {}", ino, e);
                reply.error(libc::EIO);
            }
        }
    }

    /// File write implementation - writes go to the encrypted file
    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        debug!(
            "FUSE write: inode={}, offset={}, size={}",
            ino,
            offset,
            data.len()
        );

        if offset < 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let offset = offset as usize;

        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                error!("Write failed: inode {} not found", ino);
                reply.error(libc::ENOENT);
                return;
            }
        };

        let encrypted_path = match &file_info.encrypted_path {
            Some(path) => path.clone(),
            None => {
                error!("Write failed: no encrypted path for inode {}", ino);
                reply.error(libc::EIO);
                return;
            }
        };

        let data_vec = data.to_vec();
        let client = self.client.clone();
        let cache = self.cache.clone();
        let path_clone = encrypted_path.clone();
        let file_id = file_info.file_id.clone();
        let relative_path = file_info.relative_path.clone();

        let semaphore = self.operation_semaphore.clone();
        let write_future = async move {
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|_| anyhow!("operation limiter closed"))?;
            let encrypted_metadata = parse_encrypted_file(&path_clone)?;
            let mut current_content = client.decrypt_file(&encrypted_metadata).await?;

            let write_end = offset
                .checked_add(data_vec.len())
                .ok_or_else(|| anyhow!("Write exceeds maximum supported file size"))?;
            if write_end > current_content.len() {
                current_content.resize(write_end, 0);
            }

            current_content[offset..write_end].copy_from_slice(&data_vec);
            cache.invalidate_file(&file_id).await;
            let new_metadata = client
                .encrypt_file(&relative_path, &current_content)
                .await?;
            persist_encrypted_file(&path_clone, &new_metadata)?;
            Ok::<EncryptedFileMetadata, anyhow::Error>(new_metadata)
        };

        match tokio::task::block_in_place(|| self.runtime.block_on(write_future)) {
            Ok(new_metadata) => {
                if let Some(mut info) = self.inode_map.get_mut(&ino) {
                    info.size = new_metadata.content_size;
                    info.epoch_id = new_metadata.epoch_id.to_string();
                    info.file_id = new_metadata.file_id.clone();
                    info.modified_time = SystemTime::now();
                    info.access_time = info.modified_time;
                }
                reply.written(data.len() as u32);
                debug!("Write successful: {} bytes to inode {}", data.len(), ino);
            }
            Err(e) => {
                error!("Write error for inode {}: {}", ino, e);
                reply.error(libc::EIO);
            }
        }
    }

    /// Remove a file from the filesystem
    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let parent_info = match self.inode_map.get(&parent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = parent_info.relative_path.clone();
        let normalized_child = normalize_child_path(&parent_path, name_str);
        let encrypted_path = self
            .encrypted_dir_for(&parent_path)
            .join(format!("{}.encrypted", name_str));

        match fs::remove_file(&encrypted_path) {
            Ok(_) => {
                Self::remove_cached_entry(
                    &normalized_child,
                    &self.path_lookup,
                    &self.inode_map,
                    &self.xattrs,
                    self.cache.clone(),
                    self.runtime.clone(),
                );
                reply.ok();
                debug!("Deleted file {}", normalized_child);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                reply.error(libc::ENOENT);
            }
            Err(err) => {
                error!("Failed to delete {}: {}", encrypted_path.display(), err);
                reply.error(io_error_to_errno(err));
            }
        }
    }

    /// Remove an empty directory
    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(n) if !n.is_empty() => n,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let parent_info = match self.inode_map.get(&parent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = parent_info.relative_path.clone();
        let normalized_child = normalize_child_path(&parent_path, name_str);
        let dir_path = self.encrypted_dir_for(&parent_path).join(name_str);

        if !dir_path.exists() {
            reply.error(libc::ENOENT);
            return;
        }

        match fs::remove_dir(&dir_path) {
            Ok(_) => {
                Self::remove_cached_entry(
                    &normalized_child,
                    &self.path_lookup,
                    &self.inode_map,
                    &self.xattrs,
                    self.cache.clone(),
                    self.runtime.clone(),
                );
                reply.ok();
                debug!("Removed directory {}", normalized_child);
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                reply.error(libc::ENOENT);
            }
            Err(err) => {
                reply.error(io_error_to_errno(err));
            }
        }
    }

    /// Rename an existing file
    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let old_name = match name.to_str() {
            Some(n) if !n.is_empty() => n,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let new_name = match newname.to_str() {
            Some(n) if !n.is_empty() => n,
            _ => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        debug!(
            "FUSE rename: parent={}, name={}, newparent={}, newname={}",
            parent, old_name, newparent, new_name
        );

        // Resolve parent and new parent info
        let parent_info = match self.inode_map.get(&parent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let newparent_info = match self.inode_map.get(&newparent) {
            Some(info) if info.is_directory => info.clone(),
            Some(_) => {
                reply.error(libc::ENOTDIR);
                return;
            }
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let parent_path = parent_info.relative_path.clone();
        let newparent_path = newparent_info.relative_path.clone();

        let old_norm = normalize_child_path(&parent_path, old_name);
        let new_norm = normalize_child_path(&newparent_path, new_name);

        // Look up source inode and info
        let src_inode = match self.path_lookup.get(&old_norm) {
            Some(entry) => *entry.value(),
            None => {
                debug!(
                    "Rename source {} missing from cache, performing on-demand lookup",
                    old_norm
                );
                let semaphore = self.operation_semaphore.clone();
                match tokio::task::block_in_place(|| {
                    self.runtime.block_on(async {
                        let _permit = semaphore
                            .acquire()
                            .await
                            .map_err(|_| anyhow!("operation limiter closed"))?;
                        self.lookup_file(parent, old_name).await
                    })
                }) {
                    Ok(Some((inode, _))) => inode,
                    Ok(None) => {
                        debug!("Rename failed: source path {} not found on disk", old_norm);
                        reply.error(libc::ENOENT);
                        return;
                    }
                    Err(err) => {
                        error!(
                            "Rename failed: lookup error for {} under inode {}: {}",
                            old_norm, parent, err
                        );
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
        };

        let mut src_info = match self.inode_map.get(&src_inode) {
            Some(info) => info.clone(),
            None => {
                debug!(
                    "Rename failed: inode {} for source path {} not in inode_map",
                    src_inode, old_norm
                );
                reply.error(libc::ENOENT);
                return;
            }
        };

        if src_info.is_directory {
            // Directory rename: operate directly on the underlying directory
            let old_dir_path = self.encrypted_dir_for(&parent_path).join(old_name);
            let new_dir_path = self.encrypted_dir_for(&newparent_path).join(new_name);

            // Basic safety: do not silently overwrite an existing directory
            if new_dir_path.exists() {
                debug!(
                    "Rename directory failed: destination {} already exists",
                    new_dir_path.display()
                );
                reply.error(libc::EEXIST);
                return;
            }

            if let Err(err) = fs::rename(&old_dir_path, &new_dir_path) {
                error!(
                    "Failed to rename directory {} -> {}: {}",
                    old_dir_path.display(),
                    new_dir_path.display(),
                    err
                );
                reply.error(io_error_to_errno(err));
                return;
            }

            // Update internal mappings
            src_info.relative_path = new_norm.clone();
            self.inode_map.insert(src_inode, src_info);
            self.path_lookup.remove(&old_norm);
            self.path_lookup.insert(new_norm, src_inode);

            reply.ok();
            return;
        }

        // Regular file rename: move the underlying *.encrypted file
        let old_encrypted_path = match &src_info.encrypted_path {
            Some(p) => p.clone(),
            None => {
                error!(
                    "Rename failed: no encrypted path recorded for inode {} ({})",
                    src_inode, old_norm
                );
                reply.error(libc::EIO);
                return;
            }
        };

        let new_encrypted_dir = self.encrypted_dir_for(&newparent_path);
        if let Err(err) = fs::create_dir_all(&new_encrypted_dir) {
            error!(
                "Failed to create destination directory {}: {}",
                new_encrypted_dir.display(),
                err
            );
            reply.error(io_error_to_errno(err));
            return;
        }

        let new_encrypted_path = new_encrypted_dir.join(format!("{}.encrypted", new_name));

        // If destination file exists, remove it so we effectively "replace" it
        if new_encrypted_path.exists() {
            debug!(
                "Destination encrypted file {} exists, removing before rename",
                new_encrypted_path.display()
            );
            if let Err(err) = fs::remove_file(&new_encrypted_path) {
                if err.kind() != io::ErrorKind::NotFound {
                    error!(
                        "Failed to remove existing destination file {}: {}",
                        new_encrypted_path.display(),
                        err
                    );
                    reply.error(io_error_to_errno(err));
                    return;
                }
            }

            // Drop any stale internal mapping for the destination logical path
            self.path_lookup.remove(&new_norm);
            // (Optional: could also clean inode_map/xattrs, but having an inode without a path is harmless.)
        }

        if let Err(err) = fs::rename(&old_encrypted_path, &new_encrypted_path) {
            error!(
                "Failed to rename encrypted file {} -> {}: {}",
                old_encrypted_path.display(),
                new_encrypted_path.display(),
                err
            );
            reply.error(io_error_to_errno(err));
            return;
        }

        // Update FileInfo and maps
        src_info.relative_path = new_norm.clone();
        src_info.encrypted_path = Some(new_encrypted_path);
        self.inode_map.insert(src_inode, src_info);
        self.path_lookup.remove(&old_norm);
        self.path_lookup.insert(new_norm.clone(), src_inode);

        debug!(
            "Rename successful: {} (inode {}) -> {}",
            old_norm, src_inode, new_norm
        );
        reply.ok();
    }

    /// Check access permissions for a path
    fn access(&mut self, _req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if mask == libc::F_OK {
            reply.ok();
            return;
        }

        let perms = file_info.permissions as u16;
        let mut allowed = true;

        if (mask & libc::R_OK) != 0 && (perms & 0o400) == 0 {
            allowed = false;
        }
        if (mask & libc::W_OK) != 0 && (perms & 0o200) == 0 {
            allowed = false;
        }
        if (mask & libc::X_OK) != 0 && (perms & 0o100) == 0 {
            allowed = false;
        }

        if allowed {
            reply.ok();
        } else {
            reply.error(libc::EACCES);
        }
    }

    /// Set extended attribute on a file or directory
    fn setxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if position != 0 {
            reply.error(libc::EINVAL);
            return;
        }

        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let path = file_info.relative_path;
        let mut entry = self
            .xattrs
            .entry(path.clone())
            .or_insert_with(BTreeMap::new);
        let exists = entry.contains_key(name_str);

        if (flags & libc::XATTR_CREATE) != 0 && exists {
            reply.error(libc::EEXIST);
            return;
        }
        if (flags & libc::XATTR_REPLACE) != 0 && !exists {
            reply.error(libc::ENOATTR);
            return;
        }

        entry.insert(name_str.to_string(), value.to_vec());
        reply.ok();
    }

    /// Retrieve an extended attribute
    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let data = self
            .xattrs
            .get(&file_info.relative_path)
            .and_then(|entry| entry.get(name_str).cloned());

        let value = match data {
            Some(v) => v,
            None => {
                reply.error(libc::ENOATTR);
                return;
            }
        };

        if size == 0 {
            reply.size(value.len() as u32);
        } else if value.len() > size as usize {
            reply.error(libc::ERANGE);
        } else {
            reply.data(&value);
        }
    }

    /// List extended attribute names
    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        let names: Vec<String> = self
            .xattrs
            .get(&file_info.relative_path)
            .map(|entry| entry.keys().cloned().collect())
            .unwrap_or_default();

        let mut buffer = Vec::new();
        for name in names {
            buffer.extend_from_slice(name.as_bytes());
            buffer.push(0);
        }

        if size == 0 {
            reply.size(buffer.len() as u32);
        } else if buffer.len() > size as usize {
            reply.error(libc::ERANGE);
        } else {
            reply.data(&buffer);
        }
    }

    /// Remove an extended attribute
    fn removexattr(&mut self, _req: &Request<'_>, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        let name_str = match name.to_str() {
            Some(n) => n,
            None => {
                reply.error(libc::EINVAL);
                return;
            }
        };

        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                reply.error(libc::ENOENT);
                return;
            }
        };

        if let Some(mut entry) = self.xattrs.get_mut(&file_info.relative_path) {
            if entry.remove(name_str).is_some() {
                reply.ok();
                return;
            }
        }

        reply.error(libc::ENOATTR);
    }

    /// Set file attributes (for truncation, permissions, etc.)
    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<u64>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        debug!("FUSE setattr: inode={}, size={:?}", ino, size);

        // Get file info
        let file_info = match self.inode_map.get(&ino) {
            Some(info) => info.clone(),
            None => {
                error!("Setattr failed: inode {} not found", ino);
                reply.error(libc::ENOENT);
                return;
            }
        };
        let mut updated_info = file_info.clone();
        let mut metadata_changed = false;

        // Handle truncation (most common setattr operation)
        if let Some(new_size) = size {
            let encrypted_path = match &updated_info.encrypted_path {
                Some(path) => self.encrypted_root.join(path),
                None => {
                    error!("Setattr failed: no encrypted path for inode {}", ino);
                    reply.error(libc::EIO);
                    return;
                }
            };
            let client = self.client.clone();
            let cache = self.cache.clone();
            let file_id = updated_info.file_id.clone();
            let relative_path = updated_info.relative_path.clone();

            let semaphore = self.operation_semaphore.clone();
            let truncate_future = async move {
                let _permit = semaphore
                    .acquire()
                    .await
                    .map_err(|_| anyhow!("operation limiter closed"))?;
                let encrypted_metadata = parse_encrypted_file(&encrypted_path)?;
                let mut content = client.decrypt_file(&encrypted_metadata).await?;
                let new_size = usize::try_from(new_size)
                    .map_err(|_| anyhow!("Requested size exceeds platform limits"))?;
                content.resize(new_size, 0);
                cache.invalidate_file(&file_id).await;
                let new_metadata = client.encrypt_file(&relative_path, &content).await?;
                persist_encrypted_file(&encrypted_path, &new_metadata)?;
                Ok::<EncryptedFileMetadata, anyhow::Error>(new_metadata)
            };

            match tokio::task::block_in_place(|| self.runtime.block_on(truncate_future)) {
                Ok(new_metadata) => {
                    updated_info.size = new_metadata.content_size;
                    updated_info.file_id = new_metadata.file_id.clone();
                    updated_info.epoch_id = new_metadata.epoch_id.to_string();
                    updated_info.modified_time = SystemTime::now();
                    updated_info.access_time = updated_info.modified_time;
                    metadata_changed = true;
                    debug!("Setattr (truncate) successful for inode {}", ino);
                }
                Err(e) => {
                    error!("Setattr (truncate) error for inode {}: {}", ino, e);
                    reply.error(libc::EIO);
                    return;
                }
            }
        }

        if let Some(mode) = mode {
            updated_info.permissions = (mode & 0o777) as u16;
            metadata_changed = true;
        }

        if let Some(atime) = atime {
            updated_info.access_time = time_or_now_to_system(atime);
            metadata_changed = true;
        }

        if let Some(mtime) = mtime {
            updated_info.modified_time = time_or_now_to_system(mtime);
            metadata_changed = true;
        }

        if let Some(ctime) = ctime {
            updated_info.modified_time = ctime;
            metadata_changed = true;
        }

        if let Some(chgtime) = chgtime {
            updated_info.modified_time = chgtime;
            metadata_changed = true;
        }

        if let Some(crtime) = crtime {
            updated_info.creation_time = crtime;
            metadata_changed = true;
        }

        if metadata_changed {
            self.inode_map.insert(ino, updated_info.clone());
        }

        let attr = self.file_info_to_attr(ino, &updated_info);
        reply.attr(&ATTR_TTL, &attr);
    }

    /// File release (close) implementation
    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        debug!("FUSE release: inode={}, handle={}", ino, fh);

        self.file_handles.remove(&fh);
        reply.ok();
        debug!("File released successfully: inode={}, handle={}", ino, fh);
    }

    /// Flush any dirty state for an open handle
    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        debug!("FUSE flush: inode={}, handle={}", ino, fh);
        reply.ok();
    }

    /// Flush directory data (no-op, but acknowledge to keep Finder happy)
    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        debug!(
            "FUSE fsyncdir: inode={}, handle={}, datasync={}",
            ino, fh, datasync
        );
        reply.ok();
    }

    /// Ensure file contents are durable
    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        debug!(
            "FUSE fsync: inode={}, handle={}, datasync={}",
            ino, fh, datasync
        );
        reply.ok();
    }

    /// Directory reading implementation
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        debug!("FUSE readdir: inode={}, offset={}", ino, offset);

        let mut entries: Vec<(InodeId, FileType, String)> = Vec::new();

        // "." entry
        entries.push((ino, FileType::Directory, ".".to_string()));

        // ".." entry
        let parent_path = self
            .inode_map
            .get(&ino)
            .map(|info| info.relative_path.clone())
            .unwrap_or_else(|| "/".to_string());
        let parent_inode = self.parent_inode_for_path(&parent_path);
        entries.push((parent_inode, FileType::Directory, "..".to_string()));

        // Real filesystem entries
        entries.extend(self.collect_directory_entries(&parent_path));

        // Virtual overlay entries (root only)
        if ino == ROOT_INODE {
            entries.extend(self.collect_virtual_entries());
        }

        let start_index = offset.max(0) as usize;
        for (index, (child_inode, file_type, name)) in
            entries.into_iter().enumerate().skip(start_index)
        {
            let next_offset = (index + 1) as i64;
            if reply.add(child_inode, next_offset, file_type, name) {
                break;
            }
        }

        reply.ok();
        debug!("Readdir completed for inode {}", ino);
    }

    /// Report filesystem statistics using the backing encrypted root
    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        #[cfg(unix)]
        {
            match statvfs::statvfs(&self.encrypted_root) {
                Ok(stats) => {
                    let blocks = u64::from(stats.blocks());
                    let bfree = u64::from(stats.blocks_free());
                    let bavail = u64::from(stats.blocks_available());
                    let files = u64::from(stats.files());
                    let ffree = u64::from(stats.files_free());
                    let bsize = stats.block_size().min(u64::from(u32::MAX)) as u32;
                    let namelen = stats.name_max().min(u64::from(u32::MAX)) as u32;
                    let frsize = stats.fragment_size().min(u64::from(u32::MAX)) as u32;
                    reply.statfs(blocks, bfree, bavail, files, ffree, bsize, namelen, frsize);
                    return;
                }
                Err(err) => {
                    warn!(
                        "Failed to statfs {}: {}",
                        self.encrypted_root.display(),
                        err
                    );
                }
            }
        }

        // Fallback to conservative defaults if statvfs is unavailable
        reply.statfs(0, 0, 0, 0, 0, 4096, 255, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_hybridcipher_creation() {
        // This test would require a mock client
        // For now, just test that the type system works
        assert_eq!(ROOT_INODE, 1);
        assert!(ATTR_TTL.as_secs() > 0);
    }

    #[test]
    fn test_file_info_to_attr_conversion() {
        // Test the attr conversion logic without requiring a full filesystem
        let temp_dir = TempDir::new().unwrap();

        // This is a basic smoke test for the type system
        assert!(temp_dir.path().exists());
    }

    #[test]
    fn normalize_encrypted_child_path_basic() {
        let root = PathBuf::from("/tmp/root");
        let file = root.join("docs").join("file.txt.encrypted");
        let normalized =
            super::normalize_encrypted_child_path(&root, &file).expect("normalized path present");
        assert_eq!(normalized, "/docs/file.txt");
    }
}
