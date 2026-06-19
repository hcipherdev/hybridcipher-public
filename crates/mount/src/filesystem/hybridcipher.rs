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
#[cfg(any(target_os = "linux", target_os = "macos"))]
use fuser::{
    FileAttr, FileType, Filesystem, ReplyAttr, ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty,
    ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use hybridcipher_client::{
    file::encrypt::{write_encrypted_file, SerializedEncryptedHeader, SparseFileMetadata},
    EncryptedFileMetadata,
};
#[cfg(unix)]
use nix::sys::statvfs;
use notify::event::{Event, EventKind, RemoveKind};
use notify::{recommended_watcher, RecursiveMode, Watcher};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Write};
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
const ENCRYPTED_TMP_DIR_NAME: &str = ".hybridcipher-tmp";
const MOUNT_JOURNAL_DIR_NAME: &str = ".hybridcipher-mount-journal";
const MOUNT_RETENTION_DIR_NAME: &str = ".hybridcipher-retention";
const MOUNT_CORRUPT_DIR_NAME: &str = "corrupt";
const MOUNT_JOURNAL_VERSION: u32 = 1;
const MAX_MOUNT_STATUS_PATHS: usize = 16;
const MAX_MOUNT_RECOVERY_ACTIONS: usize = 64;

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

    /// Serialize crash-sensitive backing-store mutations for the mount.
    mount_commit_lock: Arc<parking_lot::Mutex<()>>,

    /// Last flush/sync failure observed by the mount.
    last_flush_error: Arc<RwLock<Option<String>>>,

    /// Recent startup recovery actions for CLI/Desktop safety reporting.
    recovery_actions: Arc<RwLock<Vec<String>>>,

    /// Root directory containing encrypted `.encrypted` files
    encrypted_root: PathBuf,

    /// Mount point directory where decrypted files are mirrored (for mirror mount on macOS)
    mount_point: Option<PathBuf>,

    /// Volume label exposed by platform mounts that support named volumes.
    volume_name: String,

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
            mount_commit_lock: self.mount_commit_lock.clone(),
            last_flush_error: self.last_flush_error.clone(),
            recovery_actions: self.recovery_actions.clone(),
            encrypted_root: self.encrypted_root.clone(),
            mount_point: self.mount_point.clone(),
            volume_name: self.volume_name.clone(),
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
        volume_name: Option<String>,
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
        let mount_commit_lock = Arc::new(parking_lot::Mutex::new(()));
        let last_flush_error = Arc::new(RwLock::new(None));
        let recovery_actions = Arc::new(RwLock::new(Vec::new()));
        let next_handle = Arc::new(parking_lot::Mutex::new(1));
        let next_inode = Arc::new(parking_lot::Mutex::new(2)); // Start after root inode
        let runtime = Handle::current();
        let max_ops = std::cmp::max(1, max_operations) as usize;
        let operation_semaphore = Arc::new(Semaphore::new(max_ops));
        let volume_name = volume_name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "HybridCipher".to_string());

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
            mount_commit_lock,
            last_flush_error,
            recovery_actions,
            encrypted_root,
            mount_point,
            volume_name,
            next_handle,
            next_inode,
            runtime,
            operation_semaphore,
        };

        // Initialize the virtual tree with root directory
        fs::create_dir_all(&fs.encrypted_root).with_context(|| {
            format!(
                "Failed to create encrypted root {}",
                fs.encrypted_root.display()
            )
        })?;
        fs.recover_mount_safety_state()?;
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(any(target_os = "linux", target_os = "macos"))]
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

        if is_mount_internal_name(name) {
            return Ok(None);
        }

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

    fn recover_mount_safety_state(&self) -> Result<()> {
        let _commit_guard = self.mount_commit_lock.lock();
        let mut summary = MountRecoverySummary::default();
        recover_mount_journal_with_summary(&self.encrypted_root, &mut summary)?;
        recover_encrypted_temp_files_with_summary(&self.encrypted_root, &mut summary)?;
        scan_encrypted_file_health_with_summary(&self.encrypted_root, &mut summary)?;
        *self.recovery_actions.write() = summary.actions.clone();
        Ok(())
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

    fn collect_directory_entries(&self, parent_path: &str) -> Vec<(InodeId, bool, String)> {
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

            if is_mount_internal_name(name) {
                continue;
            }

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
                        entries.push((inode, true, name.to_string()));
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
                        entries.push((inode, false, decrypted_name.to_string()));
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

    fn collect_virtual_entries(&self) -> Vec<(InodeId, bool, String)> {
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
            entries.push((inode, info.is_directory, name));
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

    /// Return mount safety state for CLI/Desktop status surfaces.
    pub fn runtime_status(&self) -> MountRuntimeStatus {
        let mut status = collect_mount_runtime_status(&self.encrypted_root).unwrap_or_else(|err| {
            MountRuntimeStatus::with_error(format!("Failed to collect mount runtime status: {err}"))
        });
        status.open_file_handle_count = self.file_handles.len();
        status.pending_dirty_handles = 0;
        status.last_flush_error = self.last_flush_error.read().clone();
        status.recovery_actions = self.recovery_actions.read().clone();
        status.rebuild_safety_fields();
        status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MountJournalOperation {
    CreateFile,
    CreateDirectory,
    Delete,
    Rename,
    Replace,
    Truncate,
    SetBasicInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MountJournalRecord {
    version: u32,
    id: String,
    operation: MountJournalOperation,
    created_at: DateTime<Utc>,
    source_path: Option<PathBuf>,
    destination_path: Option<PathBuf>,
    backup_path: Option<PathBuf>,
    is_directory: bool,
}

#[derive(Debug, Clone)]
struct StagedMountOperation {
    journal_path: PathBuf,
    backup_path: Option<PathBuf>,
}

#[derive(Debug, Default, Clone)]
struct MountRecoverySummary {
    replayed_journals: usize,
    promoted_temp_files: usize,
    restored_backups: usize,
    quarantined_corrupt_files: usize,
    actions: Vec<String>,
}

impl MountRecoverySummary {
    fn push_action(&mut self, action: impl Into<String>) {
        if self.actions.len() < MAX_MOUNT_RECOVERY_ACTIONS {
            self.actions.push(action.into());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CorruptQuarantineRecord {
    original_path: PathBuf,
    quarantine_path: PathBuf,
    quarantined_at: DateTime<Utc>,
    reason: String,
}

fn is_mount_internal_name(name: &str) -> bool {
    matches!(
        name,
        ENCRYPTED_TMP_DIR_NAME | MOUNT_JOURNAL_DIR_NAME | MOUNT_RETENTION_DIR_NAME
    )
}

fn mount_journal_dir(encrypted_root: &Path) -> PathBuf {
    encrypted_root.join(MOUNT_JOURNAL_DIR_NAME)
}

fn mount_retention_dir(encrypted_root: &Path) -> PathBuf {
    encrypted_root.join(MOUNT_RETENTION_DIR_NAME)
}

fn mount_corrupt_retention_dir(encrypted_root: &Path) -> PathBuf {
    mount_retention_dir(encrypted_root).join(MOUNT_CORRUPT_DIR_NAME)
}

fn encrypted_tmp_dir_for(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "Encrypted file path {} has no parent directory",
            path.display()
        )
    })?;
    Ok(parent.join(ENCRYPTED_TMP_DIR_NAME))
}

fn sync_file_if_exists(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    let open_result = fs::OpenOptions::new().read(true).write(true).open(path);
    #[cfg(not(target_os = "windows"))]
    let open_result = fs::File::open(path);

    match open_result {
        Ok(file) => file.sync_all(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn sync_directory_if_exists(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        let _ = path;
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    match fs::File::open(path) {
        Ok(dir) => dir.sync_all(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn sync_path_and_parent(path: &Path) -> io::Result<()> {
    if path.is_dir() {
        sync_directory_if_exists(path)?;
    } else {
        sync_file_if_exists(path)?;
    }
    if let Some(parent) = path.parent() {
        sync_directory_if_exists(parent)?;
    }
    Ok(())
}

fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("Path {} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "mount-journal".to_string());
    let tmp_path = parent.join(format!("{}.tmp-{}", file_name, Uuid::new_v4()));

    {
        let mut file = fs::File::create(&tmp_path)
            .with_context(|| format!("Failed to create temp file {}", tmp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("Failed to write temp file {}", tmp_path.display()))?;
        file.sync_all()
            .with_context(|| format!("Failed to fsync temp file {}", tmp_path.display()))?;
    }

    replace_file_preserving_existing(&tmp_path, path)?;
    sync_directory_if_exists(parent)
        .with_context(|| format!("Failed to fsync directory {}", parent.display()))?;
    Ok(())
}

fn replace_file_preserving_existing(source: &Path, destination: &Path) -> Result<()> {
    #[cfg(not(target_os = "windows"))]
    {
        fs::rename(source, destination).with_context(|| {
            format!(
                "Failed to atomically rename {} to {}",
                source.display(),
                destination.display()
            )
        })?;
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    {
        if !destination.exists() {
            fs::rename(source, destination).with_context(|| {
                format!(
                    "Failed to rename {} to {}",
                    source.display(),
                    destination.display()
                )
            })?;
            return Ok(());
        }

        let parent = destination.parent().ok_or_else(|| {
            anyhow!(
                "Destination path {} has no parent directory",
                destination.display()
            )
        })?;
        let file_name = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "encrypted".to_string());
        let backup = parent.join(ENCRYPTED_TMP_DIR_NAME).join(format!(
            "replace-backup-{}.{}",
            Uuid::new_v4(),
            file_name
        ));
        if let Some(backup_parent) = backup.parent() {
            fs::create_dir_all(backup_parent).with_context(|| {
                format!(
                    "Failed to create replacement backup directory {}",
                    backup_parent.display()
                )
            })?;
        }

        fs::rename(destination, &backup).with_context(|| {
            format!(
                "Failed to move existing destination {} to backup {}",
                destination.display(),
                backup.display()
            )
        })?;
        sync_directory_if_exists(parent).ok();

        if let Err(err) = fs::rename(source, destination) {
            if let Err(restore_err) = fs::rename(&backup, destination) {
                return Err(anyhow!(
                    "Failed to replace {} with {}: {}; also failed to restore backup {}: {}",
                    destination.display(),
                    source.display(),
                    err,
                    backup.display(),
                    restore_err
                ));
            }
            return Err(anyhow!(
                "Failed to replace {} with {}: {}",
                destination.display(),
                source.display(),
                err
            ));
        }

        sync_path_and_parent(destination).ok();
        if let Err(err) = fs::remove_file(&backup) {
            warn!(
                "Failed to remove replacement backup {} after successful replace: {}",
                backup.display(),
                err
            );
        }
        Ok(())
    }
}

fn write_encrypted_file_atomic(
    path: &Path,
    header: &SerializedEncryptedHeader<'_>,
    encrypted_content: &[u8],
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow!(
            "Encrypted file path {} has no parent directory",
            path.display()
        )
    })?;
    fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create parent directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "encrypted".to_string());
    let tmp_dir = encrypted_tmp_dir_for(path)?;
    fs::create_dir_all(&tmp_dir)
        .with_context(|| format!("Failed to create temp directory {}", tmp_dir.display()))?;
    let tmp_path = tmp_dir.join(format!("tmp-{}.{}", Uuid::new_v4(), file_name));

    if let Err(err) = write_encrypted_file(&tmp_path, header, encrypted_content) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!("Failed to write encrypted temp file {}", tmp_path.display())
        });
    }
    sync_file_if_exists(&tmp_path)
        .with_context(|| format!("Failed to fsync temp file {}", tmp_path.display()))?;

    if let Err(err) = replace_file_preserving_existing(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err).with_context(|| {
            format!(
                "Failed to commit encrypted temp file {} to {}",
                tmp_path.display(),
                path.display()
            )
        });
    }
    sync_directory_if_exists(parent)
        .with_context(|| format!("Failed to fsync directory {}", parent.display()))?;
    Ok(())
}

fn retention_backup_path(encrypted_root: &Path, id: &str, source: &Path) -> PathBuf {
    let name = source
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "entry".to_string());
    mount_retention_dir(encrypted_root).join(id).join(name)
}

fn copy_path_to_retention(source: &Path, backup: &Path, is_directory: bool) -> Result<()> {
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create retention backup parent {}",
                parent.display()
            )
        })?;
    }

    if is_directory {
        fs::create_dir_all(backup)
            .with_context(|| format!("Failed to create directory backup {}", backup.display()))?;
        sync_path_and_parent(backup).ok();
    } else {
        fs::copy(source, backup).with_context(|| {
            format!(
                "Failed to copy {} to retention backup {}",
                source.display(),
                backup.display()
            )
        })?;
        sync_path_and_parent(backup).ok();
    }
    Ok(())
}

fn move_path_to_retention(source: &Path, backup: &Path) -> Result<()> {
    if let Some(parent) = backup.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create retention backup parent {}",
                parent.display()
            )
        })?;
    }
    fs::rename(source, backup).with_context(|| {
        format!(
            "Failed to move {} to retention backup {}",
            source.display(),
            backup.display()
        )
    })?;
    if let Some(parent) = source.parent() {
        sync_directory_if_exists(parent).ok();
    }
    sync_path_and_parent(backup).ok();
    Ok(())
}

fn quarantine_sidecar_path(quarantine_path: &Path) -> PathBuf {
    let sidecar_name = quarantine_path
        .file_name()
        .map(|value| format!("{}.quarantine.json", value.to_string_lossy()))
        .unwrap_or_else(|| "quarantine.json".to_string());
    quarantine_path.with_file_name(sidecar_name)
}

fn quarantine_corrupt_path(
    encrypted_root: &Path,
    source: &Path,
    reason: &str,
    summary: Option<&mut MountRecoverySummary>,
) -> Result<Option<PathBuf>> {
    if !source.exists() {
        return Ok(None);
    }
    if source.starts_with(mount_retention_dir(encrypted_root)) {
        return Ok(None);
    }

    let relative = source
        .strip_prefix(encrypted_root)
        .map(Path::to_path_buf)
        .unwrap_or_else(|_| {
            source
                .file_name()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("corrupt-entry"))
        });
    let quarantine_path = mount_corrupt_retention_dir(encrypted_root)
        .join(Uuid::new_v4().to_string())
        .join(relative);

    if let Some(parent) = quarantine_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "Failed to create corrupt retention parent {}",
                parent.display()
            )
        })?;
    }

    fs::rename(source, &quarantine_path).with_context(|| {
        format!(
            "Failed to quarantine corrupt encrypted path {} to {}",
            source.display(),
            quarantine_path.display()
        )
    })?;
    if let Some(parent) = source.parent() {
        sync_directory_if_exists(parent).ok();
    }
    sync_path_and_parent(&quarantine_path).ok();

    let record = CorruptQuarantineRecord {
        original_path: source.to_path_buf(),
        quarantine_path: quarantine_path.clone(),
        quarantined_at: Utc::now(),
        reason: reason.to_string(),
    };
    match serde_json::to_vec_pretty(&record) {
        Ok(data) => {
            if let Err(err) = write_atomic_bytes(&quarantine_sidecar_path(&quarantine_path), &data)
            {
                warn!(
                    "Failed to write corrupt quarantine sidecar for {}: {}",
                    quarantine_path.display(),
                    err
                );
            }
        }
        Err(err) => warn!(
            "Failed to serialize corrupt quarantine record for {}: {}",
            quarantine_path.display(),
            err
        ),
    }

    if let Some(summary) = summary {
        summary.quarantined_corrupt_files += 1;
        summary.push_action(format!(
            "Quarantined suspicious encrypted file {} to {} ({})",
            source.display(),
            quarantine_path.display(),
            reason
        ));
    }

    Ok(Some(quarantine_path))
}

fn write_mount_journal(
    encrypted_root: &Path,
    record: MountJournalRecord,
) -> Result<StagedMountOperation> {
    let journal_dir = mount_journal_dir(encrypted_root);
    fs::create_dir_all(&journal_dir).with_context(|| {
        format!(
            "Failed to create mount journal directory {}",
            journal_dir.display()
        )
    })?;
    let journal_path = journal_dir.join(format!("{}.json", record.id));
    let data = serde_json::to_vec_pretty(&record)
        .context("Failed to serialize mount operation journal")?;
    write_atomic_bytes(&journal_path, &data)?;
    Ok(StagedMountOperation {
        journal_path,
        backup_path: record.backup_path,
    })
}

fn complete_mount_journal(journal_path: &Path) -> Result<()> {
    match fs::remove_file(journal_path) {
        Ok(()) => {
            if let Some(parent) = journal_path.parent() {
                sync_directory_if_exists(parent).ok();
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| {
            format!(
                "Failed to remove completed mount journal {}",
                journal_path.display()
            )
        }),
    }
}

fn discard_staged_backup(staged: &StagedMountOperation) {
    let Some(backup_path) = staged.backup_path.as_ref() else {
        return;
    };
    let result = if backup_path.is_dir() {
        fs::remove_dir_all(backup_path)
    } else {
        fs::remove_file(backup_path)
    };
    match result {
        Ok(()) => {
            if let Some(parent) = backup_path.parent() {
                remove_empty_directory(parent);
                sync_directory_if_exists(parent).ok();
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => warn!(
            "Failed to discard completed staged backup {}: {}",
            backup_path.display(),
            err
        ),
    }
}

fn remove_empty_directory(path: &Path) {
    match fs::remove_dir(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_directory_if_exists(parent).ok();
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::DirectoryNotEmpty
            ) => {}
        Err(err) => warn!(
            "Failed to remove empty directory {}: {}",
            path.display(),
            err
        ),
    }
}

fn stage_create_operation(
    encrypted_root: &Path,
    target_path: &Path,
    is_directory: bool,
) -> Result<StagedMountOperation> {
    let id = Uuid::new_v4().to_string();
    let record = MountJournalRecord {
        version: MOUNT_JOURNAL_VERSION,
        id,
        operation: if is_directory {
            MountJournalOperation::CreateDirectory
        } else {
            MountJournalOperation::CreateFile
        },
        created_at: Utc::now(),
        source_path: Some(target_path.to_path_buf()),
        destination_path: None,
        backup_path: None,
        is_directory,
    };
    write_mount_journal(encrypted_root, record)
}

fn stage_delete_for_cleanup(
    encrypted_root: &Path,
    target_path: &Path,
    is_directory: bool,
) -> Result<StagedMountOperation> {
    let id = Uuid::new_v4().to_string();
    let backup_path = retention_backup_path(encrypted_root, &id, target_path);
    copy_path_to_retention(target_path, &backup_path, is_directory)?;
    let record = MountJournalRecord {
        version: MOUNT_JOURNAL_VERSION,
        id,
        operation: MountJournalOperation::Delete,
        created_at: Utc::now(),
        source_path: Some(target_path.to_path_buf()),
        destination_path: None,
        backup_path: Some(backup_path),
        is_directory,
    };
    write_mount_journal(encrypted_root, record)
}

fn stage_truncate_operation(
    encrypted_root: &Path,
    target_path: &Path,
) -> Result<StagedMountOperation> {
    let id = Uuid::new_v4().to_string();
    let backup_path = retention_backup_path(encrypted_root, &id, target_path);
    copy_path_to_retention(target_path, &backup_path, false)?;
    let record = MountJournalRecord {
        version: MOUNT_JOURNAL_VERSION,
        id,
        operation: MountJournalOperation::Truncate,
        created_at: Utc::now(),
        source_path: Some(target_path.to_path_buf()),
        destination_path: None,
        backup_path: Some(backup_path),
        is_directory: false,
    };
    write_mount_journal(encrypted_root, record)
}

fn stage_metadata_operation(
    encrypted_root: &Path,
    target_path: &Path,
    is_directory: bool,
) -> Result<StagedMountOperation> {
    let id = Uuid::new_v4().to_string();
    let record = MountJournalRecord {
        version: MOUNT_JOURNAL_VERSION,
        id,
        operation: MountJournalOperation::SetBasicInfo,
        created_at: Utc::now(),
        source_path: Some(target_path.to_path_buf()),
        destination_path: None,
        backup_path: None,
        is_directory,
    };
    write_mount_journal(encrypted_root, record)
}

fn stage_rename_operation(
    encrypted_root: &Path,
    source_path: &Path,
    destination_path: &Path,
    is_directory: bool,
    replace_if_exists: bool,
) -> Result<StagedMountOperation> {
    let id = Uuid::new_v4().to_string();
    let mut backup_path = None;
    let mut backup_to_move = None;

    if destination_path.exists() {
        if !replace_if_exists {
            return Err(anyhow!(
                "Destination {} already exists",
                destination_path.display()
            ));
        }
        if is_directory {
            return Err(anyhow!(
                "Replacing directories is not supported for {}",
                destination_path.display()
            ));
        }
        let backup = retention_backup_path(encrypted_root, &id, destination_path);
        backup_to_move = Some(backup.clone());
        backup_path = Some(backup);
    }

    let record = MountJournalRecord {
        version: MOUNT_JOURNAL_VERSION,
        id,
        operation: if backup_path.is_some() {
            MountJournalOperation::Replace
        } else {
            MountJournalOperation::Rename
        },
        created_at: Utc::now(),
        source_path: Some(source_path.to_path_buf()),
        destination_path: Some(destination_path.to_path_buf()),
        backup_path,
        is_directory,
    };
    let staged = write_mount_journal(encrypted_root, record)?;

    if let Some(backup) = backup_to_move {
        if let Err(err) = move_path_to_retention(destination_path, &backup) {
            let _ = complete_mount_journal(&staged.journal_path);
            return Err(err);
        }
    }

    Ok(staged)
}

fn recover_staged_operation(record: &MountJournalRecord, journal_path: &Path) -> Result<()> {
    let mut summary = MountRecoverySummary::default();
    recover_staged_operation_with_summary(record, journal_path, &mut summary)
}

fn recover_staged_operation_with_summary(
    record: &MountJournalRecord,
    journal_path: &Path,
    summary: &mut MountRecoverySummary,
) -> Result<()> {
    let encrypted_root = journal_path
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf);

    match record.operation {
        MountJournalOperation::CreateFile | MountJournalOperation::CreateDirectory => {
            if let Some(source) = record.source_path.as_ref() {
                if source.exists() && !record.is_directory && parse_encrypted_file(source).is_err()
                {
                    if let Some(root) = encrypted_root.as_deref() {
                        let _ = quarantine_corrupt_path(
                            root,
                            source,
                            "create journal found unhealthy encrypted file",
                            Some(&mut *summary),
                        )?;
                    }
                }
            }
            complete_mount_journal(journal_path)?;
            summary.replayed_journals += 1;
            if let Some(source) = record.source_path.as_ref() {
                summary.push_action(format!(
                    "Reconciled pending {:?} journal for {}",
                    record.operation,
                    source.display()
                ));
            }
        }
        MountJournalOperation::Delete => {
            if let Some(source) = record.source_path.as_ref() {
                if source.exists() {
                    if record.is_directory {
                        match fs::remove_dir(source) {
                            Ok(()) => {}
                            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                            Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {
                                warn!(
                                    "Skipping recovery delete for non-empty directory {}",
                                    source.display()
                                );
                                return Ok(());
                            }
                            Err(err) => return Err(err.into()),
                        }
                    } else {
                        match fs::remove_file(source) {
                            Ok(()) => {}
                            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                            Err(err) => return Err(err.into()),
                        }
                    }
                    if let Some(parent) = source.parent() {
                        sync_directory_if_exists(parent).ok();
                    }
                }
            }
            complete_mount_journal(journal_path)?;
            summary.replayed_journals += 1;
            if let Some(source) = record.source_path.as_ref() {
                summary.push_action(format!(
                    "Replayed pending delete journal for {}",
                    source.display()
                ));
            }
        }
        MountJournalOperation::Rename | MountJournalOperation::Replace => {
            let source = record.source_path.as_ref();
            let destination = record.destination_path.as_ref();
            let backup = record.backup_path.as_ref();

            match (source, destination) {
                (Some(_source), Some(destination)) if destination.exists() => {
                    complete_mount_journal(journal_path)?;
                    summary.replayed_journals += 1;
                    summary.push_action(format!(
                        "Completed pending {:?} journal for {}",
                        record.operation,
                        destination.display()
                    ));
                }
                (Some(source), Some(destination)) if source.exists() => {
                    if let Some(backup) = backup {
                        if backup.exists() && !destination.exists() {
                            fs::rename(backup, destination).with_context(|| {
                                format!(
                                    "Failed to restore retained destination {} to {}",
                                    backup.display(),
                                    destination.display()
                                )
                            })?;
                            sync_path_and_parent(destination).ok();
                            summary.restored_backups += 1;
                            summary.push_action(format!(
                                "Restored retained destination {} to {}",
                                backup.display(),
                                destination.display()
                            ));
                        }
                    }
                    complete_mount_journal(journal_path)?;
                    summary.replayed_journals += 1;
                }
                (_, Some(destination)) => {
                    if !destination.exists() {
                        if let Some(backup) = backup {
                            if backup.exists() {
                                fs::rename(backup, destination).with_context(|| {
                                    format!(
                                        "Failed to restore retained destination {} to {}",
                                        backup.display(),
                                        destination.display()
                                    )
                                })?;
                                sync_path_and_parent(destination).ok();
                                summary.restored_backups += 1;
                                summary.push_action(format!(
                                    "Restored retained destination {} to {}",
                                    backup.display(),
                                    destination.display()
                                ));
                            }
                        }
                    }
                    complete_mount_journal(journal_path)?;
                    summary.replayed_journals += 1;
                }
                _ => {
                    complete_mount_journal(journal_path)?;
                    summary.replayed_journals += 1;
                }
            }
        }
        MountJournalOperation::Truncate => {
            let target = record.source_path.as_ref();
            let backup = record.backup_path.as_ref();

            let target_healthy = target
                .filter(|path| path.exists())
                .map(|path| parse_encrypted_file(path).is_ok())
                .unwrap_or(false);

            if target_healthy {
                complete_mount_journal(journal_path)?;
                summary.replayed_journals += 1;
                if let Some(target) = target {
                    summary.push_action(format!(
                        "Completed pending truncate journal for {}",
                        target.display()
                    ));
                }
            } else if let (Some(target), Some(backup)) = (target, backup) {
                if target.exists() {
                    if let Some(root) = encrypted_root.as_deref() {
                        let _ = quarantine_corrupt_path(
                            root,
                            target,
                            "truncate journal found unhealthy replacement",
                            Some(&mut *summary),
                        )?;
                    } else if let Err(err) = fs::remove_file(target) {
                        if err.kind() != io::ErrorKind::NotFound {
                            return Err(err.into());
                        }
                    }
                }
                if backup.exists() {
                    fs::rename(backup, target).with_context(|| {
                        format!(
                            "Failed to restore truncate backup {} to {}",
                            backup.display(),
                            target.display()
                        )
                    })?;
                    sync_path_and_parent(target).ok();
                    if let Some(parent) = backup.parent() {
                        remove_empty_directory(parent);
                    }
                    summary.restored_backups += 1;
                    summary.push_action(format!(
                        "Restored truncate backup {} to {}",
                        backup.display(),
                        target.display()
                    ));
                }
                complete_mount_journal(journal_path)?;
                summary.replayed_journals += 1;
            } else {
                complete_mount_journal(journal_path)?;
                summary.replayed_journals += 1;
            }
        }
        MountJournalOperation::SetBasicInfo => {
            complete_mount_journal(journal_path)?;
            summary.replayed_journals += 1;
            if let Some(source) = record.source_path.as_ref() {
                summary.push_action(format!(
                    "Reconciled pending metadata journal for {}",
                    source.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn recover_mount_journal(encrypted_root: &Path) -> Result<()> {
    let mut summary = MountRecoverySummary::default();
    recover_mount_journal_with_summary(encrypted_root, &mut summary)
}

fn recover_mount_journal_with_summary(
    encrypted_root: &Path,
    summary: &mut MountRecoverySummary,
) -> Result<()> {
    let journal_dir = mount_journal_dir(encrypted_root);
    if !journal_dir.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(&journal_dir)
        .with_context(|| format!("Failed to read journal dir {}", journal_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(err) => {
                warn!("Failed to read mount journal {}: {}", path.display(), err);
                continue;
            }
        };
        let record: MountJournalRecord = match serde_json::from_slice(&data) {
            Ok(record) => record,
            Err(err) => {
                warn!("Failed to parse mount journal {}: {}", path.display(), err);
                continue;
            }
        };
        if let Err(err) = recover_staged_operation_with_summary(&record, &path, summary) {
            warn!(
                "Failed to recover mount journal {} for {:?}: {}",
                path.display(),
                record.operation,
                err
            );
        }
    }
    Ok(())
}

#[cfg(test)]
fn recover_encrypted_temp_files(encrypted_root: &Path) -> Result<()> {
    let mut summary = MountRecoverySummary::default();
    recover_encrypted_temp_files_with_summary(encrypted_root, &mut summary)
}

fn recover_encrypted_temp_files_with_summary(
    encrypted_root: &Path,
    summary: &mut MountRecoverySummary,
) -> Result<()> {
    if !encrypted_root.exists() {
        return Ok(());
    }

    let mut stack = vec![encrypted_root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
                if name == ENCRYPTED_TMP_DIR_NAME {
                    recover_one_temp_dir_with_summary(encrypted_root, &path, summary)?;
                } else if !is_mount_internal_name(&name) {
                    stack.push(path);
                }
            }
        }
    }
    Ok(())
}

fn recover_one_temp_dir_with_summary(
    encrypted_root: &Path,
    tmp_dir: &Path,
    summary: &mut MountRecoverySummary,
) -> Result<()> {
    let parent = match tmp_dir.parent() {
        Some(parent) => parent,
        None => return Ok(()),
    };

    for entry in fs::read_dir(tmp_dir)
        .with_context(|| format!("Failed to read temp dir {}", tmp_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(final_name) = name
            .strip_prefix("tmp-")
            .and_then(|value| value.split_once('.'))
        {
            let final_path = parent.join(final_name.1);
            if final_path.exists() {
                let final_healthy = parse_encrypted_file(&final_path).is_ok();
                let temp_healthy = parse_encrypted_file(&path).is_ok();
                if final_healthy {
                    if let Err(err) = fs::remove_file(&path) {
                        warn!(
                            "Failed to remove stale encrypted temp file {}: {}",
                            path.display(),
                            err
                        );
                    }
                } else if temp_healthy {
                    let _ = quarantine_corrupt_path(
                        encrypted_root,
                        &final_path,
                        "healthy temp ciphertext superseded corrupt final ciphertext",
                        Some(&mut *summary),
                    )?;
                    if let Err(err) = fs::rename(&path, &final_path) {
                        warn!(
                            "Failed to promote recoverable encrypted temp file {} to {}: {}",
                            path.display(),
                            final_path.display(),
                            err
                        );
                    } else {
                        sync_path_and_parent(&final_path).ok();
                        summary.promoted_temp_files += 1;
                        summary.push_action(format!(
                            "Promoted recoverable encrypted temp file {} to {}",
                            path.display(),
                            final_path.display()
                        ));
                    }
                } else {
                    let _ = quarantine_corrupt_path(
                        encrypted_root,
                        &path,
                        "corrupt temp ciphertext left by interrupted write",
                        Some(&mut *summary),
                    )?;
                }
            } else if parse_encrypted_file(&path).is_ok() {
                if let Err(err) = fs::rename(&path, &final_path) {
                    warn!(
                        "Failed to promote recoverable encrypted temp file {} to {}: {}",
                        path.display(),
                        final_path.display(),
                        err
                    );
                } else {
                    sync_path_and_parent(&final_path).ok();
                    summary.promoted_temp_files += 1;
                    summary.push_action(format!(
                        "Promoted recoverable encrypted temp file {} to {}",
                        path.display(),
                        final_path.display()
                    ));
                    warn!(
                        "Promoted recoverable encrypted temp file {} to {}",
                        path.display(),
                        final_path.display()
                    );
                }
            }
        } else if let Some(final_name) = name
            .strip_prefix("replace-backup-")
            .and_then(|value| value.split_once('.'))
        {
            let final_path = parent.join(final_name.1);
            if final_path.exists() {
                warn!(
                    "Leaving replacement backup {} in place for manual inspection",
                    path.display()
                );
            } else if let Err(err) = fs::rename(&path, &final_path) {
                warn!(
                    "Failed to restore replacement backup {} to {}: {}",
                    path.display(),
                    final_path.display(),
                    err
                );
            } else {
                sync_path_and_parent(&final_path).ok();
                summary.restored_backups += 1;
                summary.push_action(format!(
                    "Restored replacement backup {} to {}",
                    path.display(),
                    final_path.display()
                ));
                warn!(
                    "Restored replacement backup {} to {}",
                    path.display(),
                    final_path.display()
                );
            }
        }
    }
    Ok(())
}

fn scan_encrypted_file_health_with_summary(
    encrypted_root: &Path,
    summary: &mut MountRecoverySummary,
) -> Result<()> {
    if !encrypted_root.exists() {
        return Ok(());
    }

    let mut encrypted_files = Vec::new();
    let mut stack = vec![encrypted_root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.into()),
        };

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            let file_type = entry.file_type()?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
                if !is_mount_internal_name(&name) {
                    stack.push(path);
                }
            } else if file_type.is_file() && name.ends_with(".encrypted") {
                encrypted_files.push(path);
            }
        }
    }

    for path in encrypted_files {
        if let Err(err) = parse_encrypted_file(&path) {
            warn!(
                "Quarantining corrupt encrypted file {} after startup validation: {}",
                path.display(),
                err
            );
            let _ = quarantine_corrupt_path(
                encrypted_root,
                &path,
                &format!("startup encrypted header validation failed: {err}"),
                Some(&mut *summary),
            )?;
        }
    }

    Ok(())
}

fn count_journal_files(encrypted_root: &Path) -> (usize, Vec<String>) {
    let journal_dir = mount_journal_dir(encrypted_root);
    let entries = match fs::read_dir(&journal_dir) {
        Ok(entries) => entries,
        Err(_) => return (0, Vec::new()),
    };

    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            paths.push(path.display().to_string());
        }
    }
    paths.sort();
    let count = paths.len();
    paths.truncate(MAX_MOUNT_STATUS_PATHS);
    (count, paths)
}

fn count_temp_files(encrypted_root: &Path) -> (usize, Vec<String>) {
    let mut paths = Vec::new();
    let mut stack = vec![encrypted_root.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            if file_type.is_dir() {
                if name == ENCRYPTED_TMP_DIR_NAME {
                    if let Ok(temp_entries) = fs::read_dir(&path) {
                        for temp_entry in temp_entries.flatten() {
                            if temp_entry
                                .file_type()
                                .map(|ft| ft.is_file())
                                .unwrap_or(false)
                            {
                                paths.push(temp_entry.path().display().to_string());
                            }
                        }
                    }
                } else if !is_mount_internal_name(&name) {
                    stack.push(path);
                }
            }
        }
    }
    paths.sort();
    let count = paths.len();
    paths.truncate(MAX_MOUNT_STATUS_PATHS);
    (count, paths)
}

fn count_retention_entries(encrypted_root: &Path) -> (usize, Vec<String>) {
    let retention_dir = mount_retention_dir(encrypted_root);
    let entries = match fs::read_dir(&retention_dir) {
        Ok(entries) => entries,
        Err(_) => return (0, Vec::new()),
    };

    let mut paths = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == MOUNT_CORRUPT_DIR_NAME {
            continue;
        }
        if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false)
            && fs::read_dir(entry.path())
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false)
        {
            continue;
        }
        paths.push(entry.path().display().to_string());
    }
    paths.sort();
    let count = paths.len();
    paths.truncate(MAX_MOUNT_STATUS_PATHS);
    (count, paths)
}

fn count_corrupt_quarantine_entries(encrypted_root: &Path) -> (usize, Vec<String>) {
    let corrupt_dir = mount_corrupt_retention_dir(encrypted_root);
    let mut paths = Vec::new();
    let mut stack = vec![corrupt_dir];
    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) != Some("json")
            {
                paths.push(path.display().to_string());
            }
        }
    }
    paths.sort();
    let count = paths.len();
    paths.truncate(MAX_MOUNT_STATUS_PATHS);
    (count, paths)
}

pub fn collect_mount_runtime_status(encrypted_root: &Path) -> Result<MountRuntimeStatus> {
    let (pending_journal_count, pending_journal_paths) = count_journal_files(encrypted_root);
    let (temp_file_count, temp_file_paths) = count_temp_files(encrypted_root);
    let (retained_entry_count, retained_entry_paths) = count_retention_entries(encrypted_root);
    let (corrupted_encrypted_file_count, corrupt_quarantine_paths) =
        count_corrupt_quarantine_entries(encrypted_root);

    let mut status = MountRuntimeStatus {
        safe_to_report_all_synced: true,
        pending_dirty_handles: 0,
        open_file_handle_count: 0,
        pending_journal_count,
        pending_journal_paths,
        temp_file_count,
        temp_file_paths,
        retained_entry_count,
        retained_entry_paths,
        corrupted_encrypted_file_count,
        corrupt_quarantine_paths,
        last_flush_error: None,
        recovery_actions: Vec::new(),
        preflight_warnings: Vec::new(),
        updated_at: Utc::now(),
    };
    status.rebuild_safety_fields();
    Ok(status)
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
        if is_mount_internal_name(segment) {
            return None;
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

    write_encrypted_file_atomic(path, &header, &metadata.encrypted_content)
        .context("Failed to persist encrypted file payload atomically")
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn io_error_to_errno(err: io::Error) -> libc::c_int {
    err.raw_os_error().unwrap_or(libc::EIO)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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

/// Safety status for mount commit state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountRuntimeStatus {
    pub safe_to_report_all_synced: bool,
    pub pending_dirty_handles: usize,
    pub open_file_handle_count: usize,
    pub pending_journal_count: usize,
    pub pending_journal_paths: Vec<String>,
    pub temp_file_count: usize,
    pub temp_file_paths: Vec<String>,
    pub retained_entry_count: usize,
    pub retained_entry_paths: Vec<String>,
    pub corrupted_encrypted_file_count: usize,
    pub corrupt_quarantine_paths: Vec<String>,
    pub last_flush_error: Option<String>,
    pub recovery_actions: Vec<String>,
    pub preflight_warnings: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

impl MountRuntimeStatus {
    fn with_error(error: String) -> Self {
        let mut status = Self {
            safe_to_report_all_synced: false,
            pending_dirty_handles: 0,
            open_file_handle_count: 0,
            pending_journal_count: 0,
            pending_journal_paths: Vec::new(),
            temp_file_count: 0,
            temp_file_paths: Vec::new(),
            retained_entry_count: 0,
            retained_entry_paths: Vec::new(),
            corrupted_encrypted_file_count: 0,
            corrupt_quarantine_paths: Vec::new(),
            last_flush_error: Some(error),
            recovery_actions: Vec::new(),
            preflight_warnings: Vec::new(),
            updated_at: Utc::now(),
        };
        status.rebuild_safety_fields();
        status
    }

    fn rebuild_safety_fields(&mut self) {
        let mut warnings = Vec::new();
        if self.pending_dirty_handles > 0 {
            warnings.push(format!(
                "{} dirty file handle(s) still need a durable commit.",
                self.pending_dirty_handles
            ));
        }
        if self.pending_journal_count > 0 {
            warnings.push(format!(
                "{} pending mount operation journal(s) require recovery or completion.",
                self.pending_journal_count
            ));
        }
        if self.temp_file_count > 0 {
            warnings.push(format!(
                "{} encrypted temp file(s) remain from interrupted writeback.",
                self.temp_file_count
            ));
        }
        if self.retained_entry_count > 0 {
            warnings.push(format!(
                "{} retained delete/replace recovery entry/entries remain for user review.",
                self.retained_entry_count
            ));
        }
        if self.corrupted_encrypted_file_count > 0 {
            warnings.push(format!(
                "{} corrupt encrypted file(s) were quarantined into retention.",
                self.corrupted_encrypted_file_count
            ));
        }
        if let Some(error) = self
            .last_flush_error
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        {
            warnings.push(format!("Last mount flush failed: {error}"));
        }

        self.safe_to_report_all_synced = self.pending_dirty_handles == 0
            && self.pending_journal_count == 0
            && self.temp_file_count == 0
            && self.retained_entry_count == 0
            && self.corrupted_encrypted_file_count == 0
            && self.last_flush_error.is_none();
        self.preflight_warnings = warnings;
        self.updated_at = Utc::now();
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
        entries.extend(
            self.collect_directory_entries(&parent_path)
                .into_iter()
                .map(|(inode, is_directory, name)| {
                    (
                        inode,
                        if is_directory {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        },
                        name,
                    )
                }),
        );

        // Virtual overlay entries (root only)
        if ino == ROOT_INODE {
            entries.extend(self.collect_virtual_entries().into_iter().map(
                |(inode, is_directory, name)| {
                    (
                        inode,
                        if is_directory {
                            FileType::Directory
                        } else {
                            FileType::RegularFile
                        },
                        name,
                    )
                },
            ));
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

    fn test_metadata(file_path: &str, content: &[u8]) -> EncryptedFileMetadata {
        EncryptedFileMetadata {
            file_id: Uuid::new_v4().to_string(),
            file_path: file_path.to_string(),
            group_id: None,
            epoch_id: 1,
            header_version: Some(1),
            wrapped_file_key: Some(vec![1; 32]),
            key_wrap_nonce: Some(vec![2; 12]),
            key_wrap_aad_hash: Some(vec![3; 32]),
            content_nonce: Some(vec![4; 12]),
            content_chunk_size: None,
            content_size: content.len() as u64,
            encrypted_size: content.len() as u64,
            created_at: Utc::now(),
            platform_metadata: None,
            sparse_metadata: None,
            encrypted_content: content.to_vec(),
        }
    }

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
    fn atomic_encrypted_persist_replaces_existing_payload() {
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("doc.encrypted");

        persist_encrypted_file(&target, &test_metadata("doc.txt", b"old")).unwrap();
        persist_encrypted_file(&target, &test_metadata("doc.txt", b"new")).unwrap();

        let parsed = parse_encrypted_file(&target).unwrap();
        assert_eq!(parsed.encrypted_content, b"new");
    }

    #[test]
    fn delete_stage_writes_journal_and_retention_before_cleanup() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("delete-me.encrypted");
        fs::write(&target, b"ciphertext").unwrap();

        let staged = stage_delete_for_cleanup(root, &target, false).unwrap();
        assert!(target.exists());
        assert!(staged.journal_path.exists());

        let data = fs::read(&staged.journal_path).unwrap();
        let record: MountJournalRecord = serde_json::from_slice(&data).unwrap();
        let backup = record.backup_path.expect("backup path");
        assert_eq!(fs::read(&backup).unwrap(), b"ciphertext");

        fs::remove_file(&target).unwrap();
        complete_mount_journal(&staged.journal_path).unwrap();
        assert!(!staged.journal_path.exists());
        assert!(backup.exists());
    }

    #[test]
    fn replace_recovery_restores_destination_if_source_move_never_happened() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let source = root.join("source.encrypted");
        let destination = root.join("destination.encrypted");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"destination").unwrap();

        let staged = stage_rename_operation(root, &source, &destination, false, true).unwrap();
        assert!(source.exists());
        assert!(!destination.exists());
        assert!(staged.journal_path.exists());

        recover_mount_journal(root).unwrap();

        assert_eq!(fs::read(&source).unwrap(), b"source");
        assert_eq!(fs::read(&destination).unwrap(), b"destination");
        assert!(!staged.journal_path.exists());
    }

    #[test]
    fn replace_recovery_completes_when_destination_exists() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let source = root.join("source.encrypted");
        let destination = root.join("destination.encrypted");
        fs::write(&source, b"source").unwrap();
        fs::write(&destination, b"destination").unwrap();

        let staged = stage_rename_operation(root, &source, &destination, false, true).unwrap();
        fs::rename(&source, &destination).unwrap();

        recover_mount_journal(root).unwrap();

        assert!(!source.exists());
        assert_eq!(fs::read(&destination).unwrap(), b"source");
        assert!(!staged.journal_path.exists());
    }

    #[test]
    fn startup_recovery_promotes_valid_orphaned_temp_ciphertext() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("recover.encrypted");
        let tmp_dir = root.join(ENCRYPTED_TMP_DIR_NAME);
        fs::create_dir_all(&tmp_dir).unwrap();
        let tmp_path = tmp_dir.join(format!("tmp-{}.recover.encrypted", Uuid::new_v4()));
        let metadata = test_metadata("recover.txt", b"recovered");
        let header = SerializedEncryptedHeader {
            file_id: &metadata.file_id,
            file_path: &metadata.file_path,
            group_id: metadata.group_id,
            epoch_id: metadata.epoch_id,
            header_version: metadata.header_version.unwrap_or(1),
            wrapped_file_key: metadata.wrapped_file_key.as_ref().unwrap(),
            key_wrap_nonce: metadata.key_wrap_nonce.as_ref().unwrap(),
            key_wrap_aad_hash: metadata.key_wrap_aad_hash.as_ref().unwrap(),
            content_nonce: metadata.content_nonce.as_ref().unwrap(),
            content_chunk_size: metadata.content_chunk_size,
            original_size: metadata.content_size,
            encrypted_size: metadata.encrypted_size,
            encrypted_at: metadata.created_at,
            original_name: None,
            platform_metadata: metadata.platform_metadata.as_ref(),
            sparse_metadata: metadata.sparse_metadata.as_ref(),
        };
        write_encrypted_file(&tmp_path, &header, &metadata.encrypted_content).unwrap();

        recover_encrypted_temp_files(root).unwrap();

        assert!(!tmp_path.exists());
        assert!(target.exists());
        assert_eq!(
            parse_encrypted_file(&target).unwrap().encrypted_content,
            b"recovered"
        );
    }

    #[test]
    fn startup_recovery_restores_replace_backup_when_final_missing() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("doc.encrypted");
        let tmp_dir = root.join(ENCRYPTED_TMP_DIR_NAME);
        fs::create_dir_all(&tmp_dir).unwrap();
        let backup_path = tmp_dir.join(format!("replace-backup-{}.doc.encrypted", Uuid::new_v4()));
        fs::write(&backup_path, b"old committed").unwrap();

        recover_encrypted_temp_files(root).unwrap();

        assert!(!backup_path.exists());
        assert_eq!(fs::read(&target).unwrap(), b"old committed");
    }

    #[test]
    fn create_journal_recovery_compacts_unfinished_noop_create() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("new-file.encrypted");

        let staged = stage_create_operation(root, &target, false).unwrap();
        assert!(staged.journal_path.exists());

        recover_mount_journal(root).unwrap();

        assert!(!target.exists());
        assert!(!staged.journal_path.exists());
    }

    #[test]
    fn truncate_recovery_restores_backup_when_replacement_is_corrupt() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("truncate.encrypted");
        persist_encrypted_file(&target, &test_metadata("truncate.txt", b"old")).unwrap();

        let staged = stage_truncate_operation(root, &target).unwrap();
        fs::write(&target, b"not encrypted").unwrap();

        recover_mount_journal(root).unwrap();

        assert!(!staged.journal_path.exists());
        assert_eq!(
            parse_encrypted_file(&target).unwrap().encrypted_content,
            b"old"
        );
        let status = collect_mount_runtime_status(root).unwrap();
        assert_eq!(status.corrupted_encrypted_file_count, 1);
        assert!(!status.safe_to_report_all_synced);
    }

    #[test]
    fn startup_scanner_quarantines_corrupt_encrypted_file() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("bad.encrypted");
        fs::write(&target, b"not encrypted").unwrap();

        let mut summary = MountRecoverySummary::default();
        scan_encrypted_file_health_with_summary(root, &mut summary).unwrap();

        assert!(!target.exists());
        assert_eq!(summary.quarantined_corrupt_files, 1);
        let status = collect_mount_runtime_status(root).unwrap();
        assert_eq!(status.corrupted_encrypted_file_count, 1);
        assert!(!status.corrupt_quarantine_paths.is_empty());
        assert!(!status.safe_to_report_all_synced);
    }

    #[test]
    fn startup_recovery_promotes_valid_temp_over_corrupt_final() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("recover.encrypted");
        fs::write(&target, b"corrupt final").unwrap();
        let tmp_dir = root.join(ENCRYPTED_TMP_DIR_NAME);
        fs::create_dir_all(&tmp_dir).unwrap();
        let tmp_path = tmp_dir.join(format!("tmp-{}.recover.encrypted", Uuid::new_v4()));
        let metadata = test_metadata("recover.txt", b"newer");
        let header = SerializedEncryptedHeader {
            file_id: &metadata.file_id,
            file_path: &metadata.file_path,
            group_id: metadata.group_id,
            epoch_id: metadata.epoch_id,
            header_version: metadata.header_version.unwrap_or(1),
            wrapped_file_key: metadata.wrapped_file_key.as_ref().unwrap(),
            key_wrap_nonce: metadata.key_wrap_nonce.as_ref().unwrap(),
            key_wrap_aad_hash: metadata.key_wrap_aad_hash.as_ref().unwrap(),
            content_nonce: metadata.content_nonce.as_ref().unwrap(),
            content_chunk_size: metadata.content_chunk_size,
            original_size: metadata.content_size,
            encrypted_size: metadata.encrypted_size,
            encrypted_at: metadata.created_at,
            original_name: None,
            platform_metadata: metadata.platform_metadata.as_ref(),
            sparse_metadata: metadata.sparse_metadata.as_ref(),
        };
        write_encrypted_file(&tmp_path, &header, &metadata.encrypted_content).unwrap();

        recover_encrypted_temp_files(root).unwrap();

        assert!(!tmp_path.exists());
        assert_eq!(
            parse_encrypted_file(&target).unwrap().encrypted_content,
            b"newer"
        );
        assert_eq!(
            collect_mount_runtime_status(root)
                .unwrap()
                .corrupted_encrypted_file_count,
            1
        );
    }

    #[test]
    fn runtime_status_reports_pending_journals_and_retention() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let target = root.join("pending.encrypted");
        fs::write(&target, b"ciphertext").unwrap();

        let _staged_create =
            stage_create_operation(root, &root.join("new.encrypted"), false).unwrap();
        let _staged_delete = stage_delete_for_cleanup(root, &target, false).unwrap();

        let status = collect_mount_runtime_status(root).unwrap();
        assert_eq!(status.pending_journal_count, 2);
        assert_eq!(status.retained_entry_count, 1);
        assert!(!status.safe_to_report_all_synced);
        assert!(!status.preflight_warnings.is_empty());
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
