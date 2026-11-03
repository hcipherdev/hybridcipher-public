use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};

/// A connected request stream on either side: a Unix socket, or a Windows named pipe.
trait IpcStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> IpcStream for T {}

/// Connect to the desktop's coverage service at `socket_path`: the socket itself on Unix; on
/// Windows that path is a marker file and the service listens on a named pipe derived from it.
async fn connect_endpoint(socket_path: &Path) -> Result<impl IpcStream, CoverageIpcError> {
    #[cfg(unix)]
    {
        Ok(UnixStream::connect(socket_path).await?)
    }
    #[cfg(windows)]
    {
        windows_pipe::connect(socket_path).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = socket_path;
        Err::<tokio::io::DuplexStream, _>(CoverageIpcError::Unsupported)
    }
}

/// Windows has no Unix sockets here, so the service listens on a named pipe whose name is
/// derived from the marker path (the CLI finds it the same way). Only the current user can open
/// it, and only from this machine.
#[cfg(windows)]
mod windows_pipe {
    use super::CoverageIpcError;
    use sha2::{Digest, Sha256};
    use std::io;
    use std::path::Path;
    use std::ptr::null_mut;
    use tokio::net::windows::named_pipe::{
        ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
    };
    use winapi::shared::sddl::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use winapi::um::handleapi::CloseHandle;
    use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
    use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
    use winapi::um::securitybaseapi::GetTokenInformation;
    use winapi::um::winbase::LocalFree;
    use winapi::um::winnt::{TokenUser, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER};

    const ERROR_PIPE_BUSY: i32 = 231;
    const BUSY_RETRIES: u32 = 40;

    pub(super) fn pipe_name(socket_path: &Path) -> String {
        let digest = Sha256::digest(socket_path.to_string_lossy().as_bytes());
        format!(
            r"\\.\pipe\hybridcipher-coverage-{}",
            &hex::encode(digest)[..16]
        )
    }

    pub(super) async fn connect(socket_path: &Path) -> Result<NamedPipeClient, CoverageIpcError> {
        let name = pipe_name(socket_path);
        let mut retries = 0;
        loop {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(client),
                // Every instance is serving someone; the server opens the next one shortly.
                Err(err)
                    if err.raw_os_error() == Some(ERROR_PIPE_BUSY) && retries < BUSY_RETRIES =>
                {
                    retries += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(err) => return Err(err.into()),
            }
        }
    }

    /// A listening instance of `name`. The first one fails if any process already owns the name,
    /// so another program cannot sit on the pipe ahead of the app.
    pub(super) fn listen(name: &str, first: bool) -> io::Result<NamedPipeServer> {
        let security = UserOnlySecurity::new()?;
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first)
            .reject_remote_clients(true);
        // SAFETY: the attributes and the descriptor they point to live until this call returns.
        unsafe { options.create_with_security_attributes_raw(name, security.as_ptr()) }
    }

    /// Security attributes whose DACL grants access to the current user only.
    struct UserOnlySecurity {
        attributes: SECURITY_ATTRIBUTES,
        descriptor: PSECURITY_DESCRIPTOR,
    }

    impl UserOnlySecurity {
        fn new() -> io::Result<Self> {
            let sddl: Vec<u16> = format!("D:P(A;;GA;;;{})", current_user_sid()?)
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: `sddl` is NUL-terminated and `descriptor` receives a LocalAlloc'd pointer.
            let converted = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1 as u32,
                    &mut descriptor,
                    null_mut(),
                )
            };
            if converted == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                attributes: SECURITY_ATTRIBUTES {
                    nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: descriptor,
                    bInheritHandle: 0,
                },
                descriptor,
            })
        }

        fn as_ptr(&self) -> *mut std::ffi::c_void {
            &self.attributes as *const SECURITY_ATTRIBUTES as *mut std::ffi::c_void
        }
    }

    impl Drop for UserOnlySecurity {
        fn drop(&mut self) {
            // SAFETY: the descriptor came from ConvertStringSecurityDescriptorToSecurityDescriptorW.
            unsafe { LocalFree(self.descriptor as _) };
        }
    }

    fn current_user_sid() -> io::Result<String> {
        // SAFETY: plain Win32 calls on this process's own token; every buffer is sized by the
        // call that fills it and every handle or allocation is released before returning.
        unsafe {
            let mut token = null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut needed = 0u32;
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
            // u64 storage keeps TOKEN_USER's pointer field aligned.
            let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
            let filled = GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr() as *mut _,
                needed,
                &mut needed,
            );
            CloseHandle(token);
            if filled == 0 {
                return Err(io::Error::last_os_error());
            }
            let user = &*(buffer.as_ptr() as *const TOKEN_USER);
            let mut wide = null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut wide) == 0 {
                return Err(io::Error::last_os_error());
            }
            let len = (0..).take_while(|&i| *wide.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(wide, len));
            LocalFree(wide as _);
            Ok(sid)
        }
    }
}

use crate::coverage::CoverageRoot;
use crate::errors::ClientError;
use crate::network::Network;
use crate::state::client::{
    Client, CoverageAdoptResult, CoverageFileRecord, CoverageGuardSummary,
    CoverageMarkerRecoveryResult, CoverageMigrationProgress, CoveragePendingFile,
    CoverageProofArtifact, CoverageRegistryEntry, CoverageRootStats, CoverageScanSummary,
    CoverageSnapshotArtifact, CoverageSyncSummary, KeyStateReport, MigrationState,
};
use crate::storage::Storage;
use hybridcipher_messages::transparency::TransparencyConfig;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CoverageHydrationSummary {
    pub scanned_files: usize,
    pub already_tracked: usize,
    pub already_encrypted_without_metadata: usize,
    pub newly_encrypted: usize,
    pub skipped_due_to_errors: usize,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub errors: Vec<String>,
}

impl CoverageHydrationSummary {
    /// Add the counts and messages of a part of the same run.
    pub(crate) fn absorb(&mut self, part: Self) {
        self.scanned_files += part.scanned_files;
        self.already_tracked += part.already_tracked;
        self.already_encrypted_without_metadata += part.already_encrypted_without_metadata;
        self.newly_encrypted += part.newly_encrypted;
        self.skipped_due_to_errors += part.skipped_due_to_errors;
        self.warnings.extend(part.warnings);
        self.errors.extend(part.errors);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageEnrollOutcome {
    pub root: CoverageRoot,
    pub hydration: CoverageHydrationSummary,
    pub scan: CoverageScanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageUnenrollOutcome {
    pub root: CoverageRoot,
    pub decrypted_files: usize,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CoverageScanProgressUpdate {
    pub processed: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageScanProgressEvent {
    pub root: CoverageRoot,
    pub progress: CoverageScanProgressUpdate,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageEnrollPhase {
    #[default]
    Hydrating,
    Finalizing,
    Rescanning,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CoverageEnrollProgress {
    #[serde(default)]
    pub phase: CoverageEnrollPhase,
    pub total_files: usize,
    pub processed_files: usize,
    pub newly_encrypted: usize,
    pub skipped_due_to_errors: usize,
}

#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CoverageDecryptProgress {
    pub total_files: usize,
    pub decrypted_files: usize,
    pub failed_files: usize,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum CoverageIpcRequest {
    Ping,
    CoverageRootStats,
    CoverageRescan {
        root: Option<PathBuf>,
    },
    CoverageRescanWithProgress {
        root: Option<PathBuf>,
    },
    CoverageFileRecords {
        root: Option<PathBuf>,
    },
    CoverageRoots,
    CoverageRootRegistryEntries,
    CoverageEnrollRoot {
        path: PathBuf,
    },
    CoverageUnenrollRoot {
        path: PathBuf,
    },
    CoverageEnrollAndHydrate {
        path: PathBuf,
    },
    CoverageEnrollAndHydrateWithProgress {
        path: PathBuf,
    },
    CoverageUnenrollAndDecrypt {
        path: PathBuf,
    },
    CoverageUnenrollAndDecryptWithProgress {
        path: PathBuf,
    },
    CoverageAdoptPath {
        path: PathBuf,
    },
    CoverageAdoptMissingMetadata {
        root: Option<PathBuf>,
        all: bool,
    },
    CoverageMigrateOrphans {
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    },
    CoverageMigrateOrphansWithProgress {
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    },
    CoveragePruneOrphanFile {
        path: PathBuf,
    },
    CoveragePruneOrphans {
        root: Option<PathBuf>,
        all: bool,
    },
    CoveragePurgeOutcasts {
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    },
    CoverageGuard {
        root: Option<PathBuf>,
        all: bool,
    },
    CoverageSync {
        root: Option<PathBuf>,
    },
    CoveragePendingFiles,
    CoverageRecoverMarkers {
        search: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    },
    CoverageCurrentEpoch,
    CoverageMigrationSnapshot,
    CoverageSnapshotArtifact,
    CoverageFileProof {
        file_id: String,
    },
    CoverageTransparencyConfig,
    CoverageKeyState,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum CoverageIpcResponse {
    Pong,
    CoverageRootStats(Vec<CoverageRootStats>),
    CoverageRescan(CoverageScanSummary),
    CoverageScanProgress(CoverageScanProgressEvent),
    CoverageFileRecords(Vec<CoverageFileRecord>),
    CoverageRoots(Vec<CoverageRoot>),
    CoverageRootRegistryEntries(Vec<CoverageRegistryEntry>),
    CoverageEnrollRoot(CoverageRoot),
    CoverageUnenrollRoot(CoverageRoot),
    CoverageEnrollOutcome(CoverageEnrollOutcome),
    CoverageEnrollProgress(CoverageEnrollProgress),
    CoverageUnenrollOutcome(CoverageUnenrollOutcome),
    CoverageDecryptProgress(CoverageDecryptProgress),
    CoverageAdoptResult(CoverageAdoptResult),
    CoverageGuardSummary(CoverageGuardSummary),
    CoverageMigrationProgress(CoverageMigrationProgress),
    CoveragePruneOrphanFile(bool),
    CoveragePruneOrphans(usize),
    CoveragePurgeOutcasts(usize),
    CoverageSync(CoverageSyncSummary),
    CoveragePendingFiles(Vec<CoveragePendingFile>),
    CoverageRecoverMarkers(CoverageMarkerRecoveryResult),
    CoverageCurrentEpoch(Option<u64>),
    CoverageMigrationSnapshot(Option<MigrationState>),
    CoverageSnapshotArtifact(CoverageSnapshotArtifact),
    CoverageFileProof(CoverageProofArtifact),
    CoverageTransparencyConfig(Option<TransparencyConfig>),
    CoverageKeyState(KeyStateReport),
    Error(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CoverageIpcError {
    #[error("coverage IPC unsupported on this platform")]
    Unsupported,
    #[error("coverage IPC transport error: {0}")]
    Transport(#[from] std::io::Error),
    #[error("coverage IPC serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("coverage IPC server error: {0}")]
    Remote(String),
    #[error("coverage IPC client error: {0}")]
    Client(#[from] ClientError),
}

impl CoverageIpcError {
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            CoverageIpcError::Transport(_) | CoverageIpcError::Unsupported
        )
    }
}

#[async_trait::async_trait]
pub trait CoverageIpcHandler: Send + Sync {
    async fn coverage_root_stats(&self) -> Result<Vec<CoverageRootStats>, ClientError>;
    async fn coverage_rescan(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageScanSummary, ClientError>;
    async fn coverage_rescan_with_progress(
        &self,
        root: Option<PathBuf>,
        progress: mpsc::UnboundedSender<CoverageScanProgressEvent>,
    ) -> Result<CoverageScanSummary, ClientError>;
    async fn coverage_file_records(
        &self,
        root: Option<PathBuf>,
    ) -> Result<Vec<CoverageFileRecord>, ClientError>;
    async fn coverage_roots(&self) -> Result<Vec<CoverageRoot>, ClientError>;
    async fn coverage_root_registry_entries(
        &self,
    ) -> Result<Vec<CoverageRegistryEntry>, ClientError>;
    async fn coverage_enroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError>;
    async fn coverage_unenroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError>;
    async fn coverage_enroll_and_hydrate(
        &self,
        path: PathBuf,
    ) -> Result<CoverageEnrollOutcome, ClientError>;
    async fn coverage_enroll_and_hydrate_with_progress(
        &self,
        path: PathBuf,
        progress: mpsc::UnboundedSender<CoverageEnrollProgress>,
    ) -> Result<CoverageEnrollOutcome, ClientError>;
    async fn coverage_unenroll_and_decrypt(
        &self,
        path: PathBuf,
    ) -> Result<CoverageUnenrollOutcome, ClientError>;
    async fn coverage_unenroll_and_decrypt_with_progress(
        &self,
        path: PathBuf,
        progress: mpsc::UnboundedSender<CoverageDecryptProgress>,
    ) -> Result<CoverageUnenrollOutcome, ClientError>;
    async fn coverage_adopt_path(&self, path: PathBuf) -> Result<CoverageAdoptResult, ClientError>;
    async fn coverage_adopt_missing_metadata(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError>;
    async fn coverage_migrate_orphans(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageMigrationProgress, ClientError>;
    async fn coverage_migrate_orphans_with_progress(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
        progress: mpsc::UnboundedSender<CoverageMigrationProgress>,
    ) -> Result<CoverageMigrationProgress, ClientError>;
    async fn coverage_prune_orphan_file(&self, path: PathBuf) -> Result<bool, ClientError>;
    async fn coverage_prune_orphans(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError>;
    async fn coverage_purge_outcasts(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError>;
    async fn coverage_guard(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError>;
    async fn coverage_sync(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageSyncSummary, ClientError>;
    async fn pending_coverage_files(&self) -> Result<Vec<CoveragePendingFile>, ClientError>;
    async fn coverage_recover_from_markers(
        &self,
        search: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    ) -> Result<CoverageMarkerRecoveryResult, ClientError>;
    async fn current_epoch_id(&self) -> Option<u64>;
    async fn migration_snapshot(&self) -> Option<MigrationState>;
    async fn download_coverage_snapshot_artifact(
        &self,
    ) -> Result<CoverageSnapshotArtifact, ClientError>;
    async fn download_coverage_file_proof(
        &self,
        file_id: &str,
    ) -> Result<CoverageProofArtifact, ClientError>;
    async fn coverage_transparency_config(&self) -> Option<TransparencyConfig>;
    /// Older handlers that predate the report say so instead of failing to build.
    async fn key_state_report(&self) -> Result<KeyStateReport, ClientError> {
        Err(ClientError::InvalidState(
            "This HybridCipher app cannot report key state; update it".into(),
        ))
    }
}

#[async_trait::async_trait]
impl<S, N> CoverageIpcHandler for Client<S, N>
where
    S: Storage,
    N: Network,
{
    async fn coverage_root_stats(&self) -> Result<Vec<CoverageRootStats>, ClientError> {
        self.coverage_root_stats().await
    }

    async fn coverage_rescan(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageScanSummary, ClientError> {
        self.coverage_rescan(root).await
    }

    async fn coverage_rescan_with_progress(
        &self,
        root: Option<PathBuf>,
        progress: mpsc::UnboundedSender<CoverageScanProgressEvent>,
    ) -> Result<CoverageScanSummary, ClientError> {
        let progress_cb: crate::state::client::CoverageScanProgress =
            std::sync::Arc::new(move |root: &CoverageRoot, processed: usize, total: usize| {
                let _ = progress.send(CoverageScanProgressEvent {
                    root: root.clone(),
                    progress: CoverageScanProgressUpdate { processed, total },
                });
            });
        self.coverage_rescan_with_progress(root, Some(progress_cb))
            .await
    }

    async fn coverage_file_records(
        &self,
        root: Option<PathBuf>,
    ) -> Result<Vec<CoverageFileRecord>, ClientError> {
        self.coverage_file_records(root).await
    }

    async fn coverage_roots(&self) -> Result<Vec<CoverageRoot>, ClientError> {
        self.coverage_roots().await
    }

    async fn coverage_root_registry_entries(
        &self,
    ) -> Result<Vec<CoverageRegistryEntry>, ClientError> {
        self.coverage_root_registry_entries().await
    }

    async fn coverage_enroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError> {
        self.coverage_enroll_root(path).await
    }

    async fn coverage_unenroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError> {
        self.coverage_unenroll_root(path).await
    }

    async fn coverage_enroll_and_hydrate(
        &self,
        _path: PathBuf,
    ) -> Result<CoverageEnrollOutcome, ClientError> {
        Err(ClientError::InvalidInput(
            "Coverage hydration requires a desktop IPC handler".to_string(),
        ))
    }

    async fn coverage_enroll_and_hydrate_with_progress(
        &self,
        _path: PathBuf,
        _progress: mpsc::UnboundedSender<CoverageEnrollProgress>,
    ) -> Result<CoverageEnrollOutcome, ClientError> {
        Err(ClientError::InvalidInput(
            "Coverage hydration requires a desktop IPC handler".to_string(),
        ))
    }

    async fn coverage_unenroll_and_decrypt(
        &self,
        _path: PathBuf,
    ) -> Result<CoverageUnenrollOutcome, ClientError> {
        Err(ClientError::InvalidInput(
            "Coverage decrypt requires a desktop IPC handler".to_string(),
        ))
    }

    async fn coverage_unenroll_and_decrypt_with_progress(
        &self,
        _path: PathBuf,
        _progress: mpsc::UnboundedSender<CoverageDecryptProgress>,
    ) -> Result<CoverageUnenrollOutcome, ClientError> {
        Err(ClientError::InvalidInput(
            "Coverage decrypt requires a desktop IPC handler".to_string(),
        ))
    }

    async fn coverage_adopt_path(&self, path: PathBuf) -> Result<CoverageAdoptResult, ClientError> {
        self.coverage_adopt_path(path).await
    }

    async fn coverage_adopt_missing_metadata(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.coverage_adopt_missing_metadata(root, all).await
    }

    async fn coverage_migrate_orphans(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageMigrationProgress, ClientError> {
        self.coverage_migrate_orphans_with_progress(file, root, all, |_| {})
            .await
    }

    async fn coverage_migrate_orphans_with_progress(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
        progress: mpsc::UnboundedSender<CoverageMigrationProgress>,
    ) -> Result<CoverageMigrationProgress, ClientError> {
        Client::coverage_migrate_orphans_with_progress(self, file, root, all, |update| {
            let _ = progress.send(update);
        })
        .await
    }

    async fn coverage_prune_orphan_file(&self, path: PathBuf) -> Result<bool, ClientError> {
        self.coverage_prune_orphan_file(path).await
    }

    async fn coverage_prune_orphans(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.coverage_prune_orphans(root, all).await
    }

    async fn coverage_purge_outcasts(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.coverage_purge_outcasts(file, root, all).await
    }

    async fn coverage_guard(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.coverage_guard(root, all).await
    }

    async fn coverage_sync(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageSyncSummary, ClientError> {
        self.coverage_sync(root).await
    }

    async fn pending_coverage_files(&self) -> Result<Vec<CoveragePendingFile>, ClientError> {
        self.pending_coverage_files().await
    }

    async fn coverage_recover_from_markers(
        &self,
        search: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    ) -> Result<CoverageMarkerRecoveryResult, ClientError> {
        self.coverage_recover_from_markers(search, max_depth, show_progress)
            .await
    }

    async fn current_epoch_id(&self) -> Option<u64> {
        self.current_epoch_id().await
    }

    async fn migration_snapshot(&self) -> Option<MigrationState> {
        self.migration_snapshot().await
    }

    async fn download_coverage_snapshot_artifact(
        &self,
    ) -> Result<CoverageSnapshotArtifact, ClientError> {
        self.download_coverage_snapshot_artifact().await
    }

    async fn download_coverage_file_proof(
        &self,
        file_id: &str,
    ) -> Result<CoverageProofArtifact, ClientError> {
        self.download_coverage_file_proof(file_id).await
    }

    async fn coverage_transparency_config(&self) -> Option<TransparencyConfig> {
        crate::coverage::current_transparency_config()
    }

    async fn key_state_report(&self) -> Result<KeyStateReport, ClientError> {
        Client::key_state_report(self).await
    }
}

pub struct CoverageIpcClient {
    socket_path: PathBuf,
}

impl CoverageIpcClient {
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn ping(&self) -> Result<(), CoverageIpcError> {
        match self.send_request(CoverageIpcRequest::Ping).await? {
            CoverageIpcResponse::Pong => Ok(()),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_root_stats(&self) -> Result<Vec<CoverageRootStats>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageRootStats)
            .await?
        {
            CoverageIpcResponse::CoverageRootStats(stats) => Ok(stats),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_rescan(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageScanSummary, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageRescan { root })
            .await?
        {
            CoverageIpcResponse::CoverageRescan(summary) => Ok(summary),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_rescan_with_progress<F>(
        &self,
        root: Option<PathBuf>,
        mut on_progress: F,
    ) -> Result<CoverageScanSummary, CoverageIpcError>
    where
        F: FnMut(CoverageScanProgressEvent),
    {
        let mut stream = connect_endpoint(&self.socket_path).await?;
        let payload = serde_json::to_vec(&CoverageIpcRequest::CoverageRescanWithProgress { root })?;
        stream.write_all(&payload).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            let response: CoverageIpcResponse = serde_json::from_str(&line)?;
            match response {
                CoverageIpcResponse::CoverageScanProgress(progress) => {
                    on_progress(progress);
                }
                CoverageIpcResponse::CoverageRescan(summary) => {
                    return Ok(summary);
                }
                CoverageIpcResponse::Error(err) => return Err(CoverageIpcError::Remote(err)),
                other => {
                    return Err(CoverageIpcError::Remote(format!(
                        "unexpected response: {other:?}"
                    )))
                }
            }
        }

        Err(CoverageIpcError::Remote(
            "empty response from coverage IPC server".to_string(),
        ))
    }

    pub async fn coverage_file_records(
        &self,
        root: Option<PathBuf>,
    ) -> Result<Vec<CoverageFileRecord>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageFileRecords { root })
            .await?
        {
            CoverageIpcResponse::CoverageFileRecords(records) => Ok(records),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_roots(&self) -> Result<Vec<CoverageRoot>, CoverageIpcError> {
        match self.send_request(CoverageIpcRequest::CoverageRoots).await? {
            CoverageIpcResponse::CoverageRoots(roots) => Ok(roots),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_root_registry_entries(
        &self,
    ) -> Result<Vec<CoverageRegistryEntry>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageRootRegistryEntries)
            .await?
        {
            CoverageIpcResponse::CoverageRootRegistryEntries(entries) => Ok(entries),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_enroll_root(
        &self,
        path: PathBuf,
    ) -> Result<CoverageRoot, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageEnrollRoot { path })
            .await?
        {
            CoverageIpcResponse::CoverageEnrollRoot(root) => Ok(root),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_unenroll_root(
        &self,
        path: PathBuf,
    ) -> Result<CoverageRoot, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageUnenrollRoot { path })
            .await?
        {
            CoverageIpcResponse::CoverageUnenrollRoot(root) => Ok(root),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_enroll_and_hydrate(
        &self,
        path: PathBuf,
    ) -> Result<CoverageEnrollOutcome, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageEnrollAndHydrate { path })
            .await?
        {
            CoverageIpcResponse::CoverageEnrollOutcome(outcome) => Ok(outcome),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_enroll_and_hydrate_with_progress<F>(
        &self,
        path: PathBuf,
        mut on_progress: F,
    ) -> Result<CoverageEnrollOutcome, CoverageIpcError>
    where
        F: FnMut(CoverageEnrollProgress),
    {
        let mut stream = connect_endpoint(&self.socket_path).await?;
        let payload =
            serde_json::to_vec(&CoverageIpcRequest::CoverageEnrollAndHydrateWithProgress { path })?;
        stream.write_all(&payload).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            let response: CoverageIpcResponse = serde_json::from_str(&line)?;
            match response {
                CoverageIpcResponse::CoverageEnrollProgress(progress) => {
                    on_progress(progress);
                }
                CoverageIpcResponse::CoverageEnrollOutcome(outcome) => {
                    return Ok(outcome);
                }
                CoverageIpcResponse::Error(err) => return Err(CoverageIpcError::Remote(err)),
                other => {
                    return Err(CoverageIpcError::Remote(format!(
                        "unexpected response: {other:?}"
                    )))
                }
            }
        }

        Err(CoverageIpcError::Remote(
            "empty response from coverage IPC server".to_string(),
        ))
    }

    pub async fn coverage_unenroll_and_decrypt(
        &self,
        path: PathBuf,
    ) -> Result<CoverageUnenrollOutcome, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageUnenrollAndDecrypt { path })
            .await?
        {
            CoverageIpcResponse::CoverageUnenrollOutcome(outcome) => Ok(outcome),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_unenroll_and_decrypt_with_progress<F>(
        &self,
        path: PathBuf,
        mut on_progress: F,
    ) -> Result<CoverageUnenrollOutcome, CoverageIpcError>
    where
        F: FnMut(CoverageDecryptProgress),
    {
        let mut stream = connect_endpoint(&self.socket_path).await?;
        let payload = serde_json::to_vec(
            &CoverageIpcRequest::CoverageUnenrollAndDecryptWithProgress { path },
        )?;
        stream.write_all(&payload).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            let response: CoverageIpcResponse = serde_json::from_str(&line)?;
            match response {
                CoverageIpcResponse::CoverageDecryptProgress(progress) => {
                    on_progress(progress);
                }
                CoverageIpcResponse::CoverageUnenrollOutcome(outcome) => {
                    return Ok(outcome);
                }
                CoverageIpcResponse::Error(err) => return Err(CoverageIpcError::Remote(err)),
                other => {
                    return Err(CoverageIpcError::Remote(format!(
                        "unexpected response: {other:?}"
                    )))
                }
            }
        }

        Err(CoverageIpcError::Remote(
            "empty response from coverage IPC server".to_string(),
        ))
    }

    pub async fn coverage_adopt_path(
        &self,
        path: PathBuf,
    ) -> Result<CoverageAdoptResult, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageAdoptPath { path })
            .await?
        {
            CoverageIpcResponse::CoverageAdoptResult(result) => Ok(result),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_adopt_missing_metadata(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageAdoptMissingMetadata { root, all })
            .await?
        {
            CoverageIpcResponse::CoverageGuardSummary(summary) => Ok(summary),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_migrate_orphans(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageMigrationProgress, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageMigrateOrphans { file, root, all })
            .await?
        {
            CoverageIpcResponse::CoverageMigrationProgress(progress) => Ok(progress),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_migrate_orphans_with_progress<F>(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
        mut on_progress: F,
    ) -> Result<CoverageMigrationProgress, CoverageIpcError>
    where
        F: FnMut(CoverageMigrationProgress),
    {
        let mut stream = connect_endpoint(&self.socket_path).await?;
        let payload =
            serde_json::to_vec(&CoverageIpcRequest::CoverageMigrateOrphansWithProgress {
                file,
                root,
                all,
            })?;
        stream.write_all(&payload).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        let mut last_progress: Option<CoverageMigrationProgress> = None;
        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            let response: CoverageIpcResponse = serde_json::from_str(&line)?;
            match response {
                CoverageIpcResponse::CoverageMigrationProgress(progress) => {
                    on_progress(progress);
                    last_progress = Some(progress);
                }
                CoverageIpcResponse::Error(err) => return Err(CoverageIpcError::Remote(err)),
                other => {
                    return Err(CoverageIpcError::Remote(format!(
                        "unexpected response: {other:?}"
                    )))
                }
            }
        }

        last_progress.ok_or_else(|| {
            CoverageIpcError::Remote("empty response from coverage IPC server".to_string())
        })
    }

    pub async fn coverage_prune_orphan_file(
        &self,
        path: PathBuf,
    ) -> Result<bool, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoveragePruneOrphanFile { path })
            .await?
        {
            CoverageIpcResponse::CoveragePruneOrphanFile(removed) => Ok(removed),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_prune_orphans(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoveragePruneOrphans { root, all })
            .await?
        {
            CoverageIpcResponse::CoveragePruneOrphans(count) => Ok(count),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_purge_outcasts(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoveragePurgeOutcasts { file, root, all })
            .await?
        {
            CoverageIpcResponse::CoveragePurgeOutcasts(count) => Ok(count),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_guard(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageGuard { root, all })
            .await?
        {
            CoverageIpcResponse::CoverageGuardSummary(summary) => Ok(summary),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_sync(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageSyncSummary, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageSync { root })
            .await?
        {
            CoverageIpcResponse::CoverageSync(summary) => Ok(summary),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn pending_coverage_files(
        &self,
    ) -> Result<Vec<CoveragePendingFile>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoveragePendingFiles)
            .await?
        {
            CoverageIpcResponse::CoveragePendingFiles(files) => Ok(files),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_recover_from_markers(
        &self,
        search: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    ) -> Result<CoverageMarkerRecoveryResult, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageRecoverMarkers {
                search,
                max_depth,
                show_progress,
            })
            .await?
        {
            CoverageIpcResponse::CoverageRecoverMarkers(result) => Ok(result),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn current_epoch_id(&self) -> Result<Option<u64>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageCurrentEpoch)
            .await?
        {
            CoverageIpcResponse::CoverageCurrentEpoch(epoch) => Ok(epoch),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn migration_snapshot(&self) -> Result<Option<MigrationState>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageMigrationSnapshot)
            .await?
        {
            CoverageIpcResponse::CoverageMigrationSnapshot(snapshot) => Ok(snapshot),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn download_coverage_snapshot_artifact(
        &self,
    ) -> Result<CoverageSnapshotArtifact, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageSnapshotArtifact)
            .await?
        {
            CoverageIpcResponse::CoverageSnapshotArtifact(snapshot) => Ok(snapshot),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn download_coverage_file_proof(
        &self,
        file_id: &str,
    ) -> Result<CoverageProofArtifact, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageFileProof {
                file_id: file_id.to_string(),
            })
            .await?
        {
            CoverageIpcResponse::CoverageFileProof(proof) => Ok(proof),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn coverage_transparency_config(
        &self,
    ) -> Result<Option<TransparencyConfig>, CoverageIpcError> {
        match self
            .send_request(CoverageIpcRequest::CoverageTransparencyConfig)
            .await?
        {
            CoverageIpcResponse::CoverageTransparencyConfig(config) => Ok(config),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    pub async fn key_state_report(&self) -> Result<KeyStateReport, CoverageIpcError> {
        match self.send_request(CoverageIpcRequest::CoverageKeyState).await? {
            CoverageIpcResponse::CoverageKeyState(report) => Ok(report),
            CoverageIpcResponse::Error(err) => Err(CoverageIpcError::Remote(err)),
            other => Err(CoverageIpcError::Remote(format!(
                "unexpected response: {other:?}"
            ))),
        }
    }

    async fn send_request(
        &self,
        request: CoverageIpcRequest,
    ) -> Result<CoverageIpcResponse, CoverageIpcError> {
        let mut stream = connect_endpoint(&self.socket_path).await?;
        let payload = serde_json::to_vec(&request)?;
        stream.write_all(&payload).await?;
        stream.write_all(b"\n").await?;
        stream.flush().await?;

        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        if line.trim().is_empty() {
            return Err(CoverageIpcError::Remote(
                "empty response from coverage IPC server".to_string(),
            ));
        }
        Ok(serde_json::from_str(&line)?)
    }
}

pub struct CoverageIpcServer {
    shutdown: Option<oneshot::Sender<()>>,
    join_handle: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
}

impl CoverageIpcServer {
    #[cfg(unix)]
    pub async fn start(
        socket_path: PathBuf,
        handler: Arc<dyn CoverageIpcHandler>,
    ) -> Result<Self, CoverageIpcError> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if socket_path.exists() {
            let _ = tokio::fs::remove_file(&socket_path).await;
        }
        let listener = UnixListener::bind(&socket_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                tokio::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
                    .await;
        }

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let socket_clone = socket_path.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => {
                        let _ = tokio::fs::remove_file(&socket_clone).await;
                        break;
                    }
                    accept_result = listener.accept() => {
                        let (stream, _) = match accept_result {
                            Ok(value) => value,
                            Err(_) => {
                                continue;
                            }
                        };
                        let handler = handler.clone();
                        tokio::spawn(async move {
                            let _ = handle_connection(stream, handler).await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            join_handle,
            socket_path,
        })
    }

    #[cfg(windows)]
    pub async fn start(
        socket_path: PathBuf,
        handler: Arc<dyn CoverageIpcHandler>,
    ) -> Result<Self, CoverageIpcError> {
        if let Some(parent) = socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let name = windows_pipe::pipe_name(&socket_path);
        let mut listener = windows_pipe::listen(&name, true)?;
        // The marker lets the CLI find the service with the same existence check as on Unix.
        tokio::fs::write(&socket_path, name.as_bytes()).await?;

        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let socket_clone = socket_path.clone();
        let join_handle = tokio::spawn(async move {
            loop {
                let connected = tokio::select! {
                    _ = &mut shutdown_rx => break,
                    connected = listener.connect() => connected,
                };
                // Listen on a fresh instance before serving this one, so callers never find
                // the pipe missing in between.
                let next = match windows_pipe::listen(&name, false) {
                    Ok(next) => next,
                    Err(_) => break,
                };
                let stream = std::mem::replace(&mut listener, next);
                if connected.is_err() {
                    continue;
                }
                let handler = handler.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, handler).await;
                });
            }
            let _ = tokio::fs::remove_file(&socket_clone).await;
        });

        Ok(Self {
            shutdown: Some(shutdown_tx),
            join_handle,
            socket_path,
        })
    }

    #[cfg(not(any(unix, windows)))]
    pub async fn start(
        _socket_path: PathBuf,
        _handler: Arc<dyn CoverageIpcHandler>,
    ) -> Result<Self, CoverageIpcError> {
        Err(CoverageIpcError::Unsupported)
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = self.join_handle.await;
    }
}

async fn handle_connection<S: IpcStream>(
    stream: S,
    handler: Arc<dyn CoverageIpcHandler>,
) -> Result<(), CoverageIpcError> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.trim().is_empty() {
        return Ok(());
    }
    let request: CoverageIpcRequest = serde_json::from_str(&request_line)?;
    let mut stream = reader.into_inner();
    let response = match request {
        CoverageIpcRequest::Ping => CoverageIpcResponse::Pong,
        CoverageIpcRequest::CoverageRootStats => match handler.coverage_root_stats().await {
            Ok(stats) => CoverageIpcResponse::CoverageRootStats(stats),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoverageRescan { root } => match handler.coverage_rescan(root).await {
            Ok(summary) => CoverageIpcResponse::CoverageRescan(summary),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoverageRescanWithProgress { root } => {
            return stream_rescan_with_progress(stream, handler, root).await;
        }
        CoverageIpcRequest::CoverageFileRecords { root } => {
            match handler.coverage_file_records(root).await {
                Ok(records) => CoverageIpcResponse::CoverageFileRecords(records),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageRoots => match handler.coverage_roots().await {
            Ok(roots) => CoverageIpcResponse::CoverageRoots(roots),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoverageRootRegistryEntries => {
            match handler.coverage_root_registry_entries().await {
                Ok(entries) => CoverageIpcResponse::CoverageRootRegistryEntries(entries),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageEnrollRoot { path } => {
            match handler.coverage_enroll_root(path).await {
                Ok(root) => CoverageIpcResponse::CoverageEnrollRoot(root),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageUnenrollRoot { path } => {
            match handler.coverage_unenroll_root(path).await {
                Ok(root) => CoverageIpcResponse::CoverageUnenrollRoot(root),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageEnrollAndHydrate { path } => {
            match handler.coverage_enroll_and_hydrate(path).await {
                Ok(outcome) => CoverageIpcResponse::CoverageEnrollOutcome(outcome),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageEnrollAndHydrateWithProgress { path } => {
            return stream_enroll_and_hydrate_with_progress(stream, handler, path).await;
        }
        CoverageIpcRequest::CoverageUnenrollAndDecrypt { path } => {
            match handler.coverage_unenroll_and_decrypt(path).await {
                Ok(outcome) => CoverageIpcResponse::CoverageUnenrollOutcome(outcome),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageUnenrollAndDecryptWithProgress { path } => {
            return stream_unenroll_and_decrypt_with_progress(stream, handler, path).await;
        }
        CoverageIpcRequest::CoverageAdoptPath { path } => {
            match handler.coverage_adopt_path(path).await {
                Ok(result) => CoverageIpcResponse::CoverageAdoptResult(result),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageAdoptMissingMetadata { root, all } => {
            match handler.coverage_adopt_missing_metadata(root, all).await {
                Ok(summary) => CoverageIpcResponse::CoverageGuardSummary(summary),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageMigrateOrphans { file, root, all } => {
            match handler.coverage_migrate_orphans(file, root, all).await {
                Ok(progress) => CoverageIpcResponse::CoverageMigrationProgress(progress),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageMigrateOrphansWithProgress { file, root, all } => {
            return stream_migrate_orphans_with_progress(stream, handler, file, root, all).await;
        }
        CoverageIpcRequest::CoveragePruneOrphanFile { path } => {
            match handler.coverage_prune_orphan_file(path).await {
                Ok(removed) => CoverageIpcResponse::CoveragePruneOrphanFile(removed),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoveragePruneOrphans { root, all } => {
            match handler.coverage_prune_orphans(root, all).await {
                Ok(count) => CoverageIpcResponse::CoveragePruneOrphans(count),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoveragePurgeOutcasts { file, root, all } => {
            match handler.coverage_purge_outcasts(file, root, all).await {
                Ok(count) => CoverageIpcResponse::CoveragePurgeOutcasts(count),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageGuard { root, all } => {
            match handler.coverage_guard(root, all).await {
                Ok(summary) => CoverageIpcResponse::CoverageGuardSummary(summary),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageSync { root } => match handler.coverage_sync(root).await {
            Ok(summary) => CoverageIpcResponse::CoverageSync(summary),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoveragePendingFiles => match handler.pending_coverage_files().await {
            Ok(files) => CoverageIpcResponse::CoveragePendingFiles(files),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoverageRecoverMarkers {
            search,
            max_depth,
            show_progress,
        } => match handler
            .coverage_recover_from_markers(search, max_depth, show_progress)
            .await
        {
            Ok(result) => CoverageIpcResponse::CoverageRecoverMarkers(result),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
        CoverageIpcRequest::CoverageCurrentEpoch => {
            CoverageIpcResponse::CoverageCurrentEpoch(handler.current_epoch_id().await)
        }
        CoverageIpcRequest::CoverageMigrationSnapshot => {
            CoverageIpcResponse::CoverageMigrationSnapshot(handler.migration_snapshot().await)
        }
        CoverageIpcRequest::CoverageSnapshotArtifact => {
            match handler.download_coverage_snapshot_artifact().await {
                Ok(snapshot) => CoverageIpcResponse::CoverageSnapshotArtifact(snapshot),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageFileProof { file_id } => {
            match handler.download_coverage_file_proof(&file_id).await {
                Ok(proof) => CoverageIpcResponse::CoverageFileProof(proof),
                Err(err) => CoverageIpcResponse::Error(err.to_string()),
            }
        }
        CoverageIpcRequest::CoverageTransparencyConfig => {
            CoverageIpcResponse::CoverageTransparencyConfig(
                handler.coverage_transparency_config().await,
            )
        }
        CoverageIpcRequest::CoverageKeyState => match handler.key_state_report().await {
            Ok(report) => CoverageIpcResponse::CoverageKeyState(report),
            Err(err) => CoverageIpcResponse::Error(err.to_string()),
        },
    };
    write_response_line(&mut stream, &response).await
}

async fn stream_migrate_orphans_with_progress<S: IpcStream>(
    mut stream: S,
    handler: Arc<dyn CoverageIpcHandler>,
    file: Option<PathBuf>,
    root: Option<PathBuf>,
    all: bool,
) -> Result<(), CoverageIpcError> {
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let mut migration =
        Box::pin(handler.coverage_migrate_orphans_with_progress(file, root, all, progress_tx));
    let mut progress_open = true;

    loop {
        tokio::select! {
            progress = progress_rx.recv(), if progress_open => {
                match progress {
                    Some(progress) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageMigrationProgress(progress),
                        )
                        .await?;
                    }
                    None => {
                        progress_open = false;
                    }
                }
            }
            result = &mut migration => {
                match result {
                    Ok(progress) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageMigrationProgress(progress),
                        )
                        .await?;
                    }
                    Err(err) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::Error(err.to_string()),
                        )
                        .await?;
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

async fn stream_unenroll_and_decrypt_with_progress<S: IpcStream>(
    mut stream: S,
    handler: Arc<dyn CoverageIpcHandler>,
    path: PathBuf,
) -> Result<(), CoverageIpcError> {
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let mut task = Box::pin(handler.coverage_unenroll_and_decrypt_with_progress(path, progress_tx));
    let mut progress_open = true;

    loop {
        tokio::select! {
            progress = progress_rx.recv(), if progress_open => {
                match progress {
                    Some(progress) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageDecryptProgress(progress),
                        )
                        .await?;
                    }
                    None => {
                        progress_open = false;
                    }
                }
            }
            result = &mut task => {
                match result {
                    Ok(outcome) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageUnenrollOutcome(outcome),
                        )
                        .await?;
                    }
                    Err(err) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::Error(err.to_string()),
                        )
                        .await?;
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

async fn stream_enroll_and_hydrate_with_progress<S: IpcStream>(
    mut stream: S,
    handler: Arc<dyn CoverageIpcHandler>,
    path: PathBuf,
) -> Result<(), CoverageIpcError> {
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let mut task = Box::pin(handler.coverage_enroll_and_hydrate_with_progress(path, progress_tx));
    let mut progress_open = true;

    loop {
        tokio::select! {
            progress = progress_rx.recv(), if progress_open => {
                match progress {
                    Some(progress) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageEnrollProgress(progress),
                        )
                        .await?;
                    }
                    None => {
                        progress_open = false;
                    }
                }
            }
            result = &mut task => {
                match result {
                    Ok(outcome) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageEnrollOutcome(outcome),
                        )
                        .await?;
                    }
                    Err(err) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::Error(err.to_string()),
                        )
                        .await?;
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

async fn stream_rescan_with_progress<S: IpcStream>(
    mut stream: S,
    handler: Arc<dyn CoverageIpcHandler>,
    root: Option<PathBuf>,
) -> Result<(), CoverageIpcError> {
    let (progress_tx, mut progress_rx) = mpsc::unbounded_channel();
    let mut task = Box::pin(handler.coverage_rescan_with_progress(root, progress_tx));
    let mut progress_open = true;

    loop {
        tokio::select! {
            progress = progress_rx.recv(), if progress_open => {
                match progress {
                    Some(progress) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageScanProgress(progress),
                        )
                        .await?;
                    }
                    None => {
                        progress_open = false;
                    }
                }
            }
            result = &mut task => {
                match result {
                    Ok(summary) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::CoverageRescan(summary),
                        )
                        .await?;
                    }
                    Err(err) => {
                        write_response_line(
                            &mut stream,
                            &CoverageIpcResponse::Error(err.to_string()),
                        )
                        .await?;
                    }
                }
                break;
            }
        }
    }

    Ok(())
}

async fn write_response_line<S: IpcStream>(
    stream: &mut S,
    response: &CoverageIpcResponse,
) -> Result<(), CoverageIpcError> {
    let payload = serde_json::to_vec(response)?;
    stream.write_all(&payload).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "../../tests/ipc/test_coverage_ipc_transport.rs"]
mod coverage_ipc_transport_tests;
