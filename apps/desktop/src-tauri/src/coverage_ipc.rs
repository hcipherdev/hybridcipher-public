use crate::local_client::LocalClient;
use async_trait::async_trait;
use hybridcipher_client::coverage::{current_transparency_config, CoverageRoot};
use hybridcipher_client::errors::ClientError;
use hybridcipher_client::ipc::coverage::{
    CoverageDecryptProgress, CoverageEnrollOutcome, CoverageEnrollProgress, CoverageIpcHandler,
    CoverageScanProgressEvent, CoverageUnenrollOutcome,
};
use hybridcipher_client::state::client::{
    CoverageAdoptResult, CoverageFileRecord, CoverageGuardSummary, CoverageMarkerRecoveryResult,
    CoverageMigrationProgress, CoveragePendingFile, CoverageProofArtifact, CoverageRegistryEntry,
    CoverageRootStats, CoverageScanProgress, CoverageScanSummary, CoverageSnapshotArtifact,
    CoverageSyncSummary, MigrationState,
};
use hybridcipher_client::TransparencyConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

pub struct DesktopCoverageIpcHandler {
    client: Arc<LocalClient>,
}

impl DesktopCoverageIpcHandler {
    pub fn new(client: Arc<LocalClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CoverageIpcHandler for DesktopCoverageIpcHandler {
    async fn coverage_root_stats(&self) -> Result<Vec<CoverageRootStats>, ClientError> {
        self.client.coverage_root_stats().await
    }

    async fn coverage_rescan(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageScanSummary, ClientError> {
        self.client.coverage_rescan(root).await
    }

    async fn coverage_rescan_with_progress(
        &self,
        root: Option<PathBuf>,
        progress: mpsc::UnboundedSender<CoverageScanProgressEvent>,
    ) -> Result<CoverageScanSummary, ClientError> {
        let progress_cb: CoverageScanProgress =
            Arc::new(move |root: &CoverageRoot, processed: usize, total: usize| {
                let _ = progress.send(CoverageScanProgressEvent {
                    root: root.clone(),
                    progress: hybridcipher_client::ipc::coverage::CoverageScanProgressUpdate {
                        processed,
                        total,
                    },
                });
            });
        self.client
            .coverage_rescan_with_progress(root, Some(progress_cb))
            .await
    }

    async fn coverage_file_records(
        &self,
        root: Option<PathBuf>,
    ) -> Result<Vec<CoverageFileRecord>, ClientError> {
        self.client.coverage_file_records(root).await
    }

    async fn coverage_roots(&self) -> Result<Vec<CoverageRoot>, ClientError> {
        self.client.coverage_roots().await
    }

    async fn coverage_root_registry_entries(
        &self,
    ) -> Result<Vec<CoverageRegistryEntry>, ClientError> {
        self.client.coverage_root_registry_entries().await
    }

    async fn coverage_enroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError> {
        self.client.coverage_enroll_root(&path).await
    }

    async fn coverage_unenroll_root(&self, path: PathBuf) -> Result<CoverageRoot, ClientError> {
        self.client.coverage_unenroll_root(&path).await
    }

    async fn coverage_enroll_and_hydrate(
        &self,
        path: PathBuf,
    ) -> Result<CoverageEnrollOutcome, ClientError> {
        hybridcipher_client::ipc::coverage_workflows::enroll_and_hydrate(&self.client, path).await
    }

    async fn coverage_enroll_and_hydrate_with_progress(
        &self,
        path: PathBuf,
        progress: mpsc::UnboundedSender<CoverageEnrollProgress>,
    ) -> Result<CoverageEnrollOutcome, ClientError> {
        let mut on_progress = |update: CoverageEnrollProgress| {
            let _ = progress.send(update);
        };
        hybridcipher_client::ipc::coverage_workflows::enroll_and_hydrate_with_progress(
            &self.client,
            path,
            &mut on_progress,
        )
        .await
    }

    async fn coverage_unenroll_and_decrypt(
        &self,
        path: PathBuf,
    ) -> Result<CoverageUnenrollOutcome, ClientError> {
        hybridcipher_client::ipc::coverage_workflows::unenroll_and_decrypt(&self.client, path).await
    }

    async fn coverage_unenroll_and_decrypt_with_progress(
        &self,
        path: PathBuf,
        progress: mpsc::UnboundedSender<CoverageDecryptProgress>,
    ) -> Result<CoverageUnenrollOutcome, ClientError> {
        let mut on_progress = |update: CoverageDecryptProgress| {
            let _ = progress.send(update);
        };
        hybridcipher_client::ipc::coverage_workflows::unenroll_and_decrypt_with_progress(
            &self.client,
            path,
            &mut on_progress,
        )
        .await
    }

    async fn coverage_adopt_path(&self, path: PathBuf) -> Result<CoverageAdoptResult, ClientError> {
        self.client.coverage_adopt_path(&path).await
    }

    async fn coverage_adopt_missing_metadata(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.client.coverage_adopt_missing_metadata(root, all).await
    }

    async fn coverage_migrate_orphans(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageMigrationProgress, ClientError> {
        self.client
            .coverage_migrate_orphans_with_progress(file, root, all, |_| {})
            .await
    }

    async fn coverage_migrate_orphans_with_progress(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
        progress: mpsc::UnboundedSender<CoverageMigrationProgress>,
    ) -> Result<CoverageMigrationProgress, ClientError> {
        self.client
            .coverage_migrate_orphans_with_progress(file, root, all, |update| {
                let _ = progress.send(update);
            })
            .await
    }

    async fn coverage_prune_orphan_file(&self, path: PathBuf) -> Result<bool, ClientError> {
        self.client.coverage_prune_orphan_file(path).await
    }

    async fn coverage_prune_orphans(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.client.coverage_prune_orphans(root, all).await
    }

    async fn coverage_purge_outcasts(
        &self,
        file: Option<PathBuf>,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<usize, ClientError> {
        self.client.coverage_purge_outcasts(file, root, all).await
    }

    async fn coverage_guard(
        &self,
        root: Option<PathBuf>,
        all: bool,
    ) -> Result<CoverageGuardSummary, ClientError> {
        self.client.coverage_guard(root, all).await
    }

    async fn coverage_sync(
        &self,
        root: Option<PathBuf>,
    ) -> Result<CoverageSyncSummary, ClientError> {
        self.client.coverage_sync(root).await
    }

    async fn pending_coverage_files(&self) -> Result<Vec<CoveragePendingFile>, ClientError> {
        self.client.pending_coverage_files().await
    }

    async fn coverage_recover_from_markers(
        &self,
        search: Vec<PathBuf>,
        max_depth: usize,
        show_progress: bool,
    ) -> Result<CoverageMarkerRecoveryResult, ClientError> {
        self.client
            .coverage_recover_from_markers(search, max_depth, show_progress)
            .await
    }

    async fn current_epoch_id(&self) -> Option<u64> {
        self.client.current_epoch_id().await
    }

    async fn migration_snapshot(&self) -> Option<MigrationState> {
        self.client.migration_snapshot().await
    }

    async fn download_coverage_snapshot_artifact(
        &self,
    ) -> Result<CoverageSnapshotArtifact, ClientError> {
        self.client.download_coverage_snapshot_artifact().await
    }

    async fn download_coverage_file_proof(
        &self,
        file_id: &str,
    ) -> Result<CoverageProofArtifact, ClientError> {
        self.client.download_coverage_file_proof(file_id).await
    }

    async fn coverage_transparency_config(&self) -> Option<TransparencyConfig> {
        current_transparency_config()
    }
}
