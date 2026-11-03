//! Unmounting several folders at once, with progress the app window can show
//! or leave running in the background. Each folder still goes through
//! `unmount_desktop_cloud_root_record`, unchanged; only the folders run side by
//! side, and one folder at a time per root (see `unmount_lock`).

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub(crate) const UNMOUNT_PROGRESS_EVENT: &str = "unmount_progress";

/// Folders stopped at once. Each folder's stop takes its own locks (the
/// macOS bridge's, or the Cloud Files root's operation and writer locks), so
/// folders don't wait on each other.
pub(super) const MAX_PARALLEL_UNMOUNTS: usize = 4;

static NEXT_UNMOUNT_BATCH_ID: AtomicU64 = AtomicU64::new(1);

type FolderLock = Arc<tokio::sync::Mutex<()>>;
type FolderLocks = std::sync::Mutex<HashMap<Uuid, FolderLock>>;

/// One async lock per folder: a second unmount of the same folder (quit or
/// sign-out while a background batch runs) waits for the first, so the
/// folder is never removed while the first one still waits for Finder edits.
static UNMOUNT_LOCKS: Lazy<FolderLocks> = Lazy::new(|| std::sync::Mutex::new(HashMap::new()));

pub(super) fn unmount_lock(root_id: Uuid) -> FolderLock {
    UNMOUNT_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(root_id)
        .or_default()
        .clone()
}

/// Whether the folder is being unmounted right now; mounting it then waits.
pub(super) fn unmount_in_progress(root_id: Uuid) -> bool {
    let lock = UNMOUNT_LOCKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&root_id)
        .cloned();
    lock.is_some_and(|lock| lock.try_lock().is_err())
}

/// Runs `f` for every item, at most `limit` at a time, and returns every
/// result: a failing item never stops the others.
pub(super) async fn run_bounded<T, R, F, Fut>(items: Vec<T>, limit: usize, f: F) -> Vec<R>
where
    F: FnMut(T) -> Fut,
    Fut: std::future::Future<Output = R>,
{
    use futures::stream::StreamExt;
    futures::stream::iter(items.into_iter().map(f))
        .buffer_unordered(limit.max(1))
        .collect()
        .await
}

#[derive(Debug, Clone, Serialize)]
pub struct UnmountFolderProgress {
    pub batch_id: u64,
    pub root_id: String,
    pub name: String,
    /// `queued`, `running`, `done` or `failed`.
    pub status: &'static str,
    /// While running: `waiting_for_finder` or `removing`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnmountBatchResult {
    pub batch_id: u64,
    pub folders: Vec<UnmountFolderProgress>,
    /// A failure outside any one folder, e.g. the final sweep.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl UnmountBatchResult {
    fn failures(&self) -> Vec<String> {
        self.folders
            .iter()
            .filter_map(|folder| folder.error.clone())
            .chain(self.error.clone())
            .collect()
    }
}

enum UnmountTarget {
    Cloud(PathBuf, MountRuntimeState),
    Sync(MountRuntimeState),
}

impl UnmountTarget {
    fn mount_state(&self) -> &MountRuntimeState {
        match self {
            Self::Cloud(_, mount_state) | Self::Sync(mount_state) => mount_state,
        }
    }
}

fn mount_name(mount_state: &MountRuntimeState) -> String {
    mount_state.display_name.clone().unwrap_or_else(|| {
        mount_state
            .encrypted_dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| mount_state.root_id.clone())
    })
}

fn unmount_error_code(error: &str) -> Option<&'static str> {
    error
        .contains("not safe to unmount")
        .then_some("UNMOUNT_NOT_SAFE")
}

struct UnmountReporter<'a> {
    app: Option<&'a AppHandle>,
    batch_id: u64,
}

impl UnmountReporter<'_> {
    fn emit(&self, progress: &UnmountFolderProgress) {
        if let Some(app) = self.app {
            let _ = app.emit(UNMOUNT_PROGRESS_EVENT, progress);
        }
    }
}

/// Sync-backend (CLI fallback) mounts recorded for the account.
async fn sync_mount_states(user_dir: &Path) -> Vec<MountRuntimeState> {
    let mut states = Vec::new();
    let Ok(mut entries) = fs::read_dir(mount_states_dir(user_dir)).await else {
        return states;
    };
    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if !(file_name.starts_with("mount_state_") && file_name.ends_with(".json")) {
            continue;
        }
        let Ok(content) = fs::read_to_string(&path).await else {
            continue;
        };
        if let Ok(mount_state) = serde_json::from_str::<MountRuntimeState>(&content) {
            let backend = mount_state.backend();
            if !mount_state.requested_unmount
                && !backend.is_windows_cloud_files()
                && !backend.is_macos_file_provider()
            {
                states.push(mount_state);
            }
        }
    }
    states
}

async fn unmount_target(
    state: &AppState,
    user_dir: &Path,
    target: UnmountTarget,
    force: bool,
    reporter: &UnmountReporter<'_>,
) -> UnmountFolderProgress {
    let started = Instant::now();
    let mount_state = target.mount_state().clone();
    let progress = |status, step, error: Option<String>| UnmountFolderProgress {
        batch_id: reporter.batch_id,
        root_id: mount_state.root_id.clone(),
        name: mount_name(&mount_state),
        status,
        step,
        error_code: error.as_deref().and_then(unmount_error_code),
        error,
        elapsed_ms: started.elapsed().as_millis() as u64,
    };
    let on_step = |step: &'static str| reporter.emit(&progress("running", Some(step), None));
    on_step("waiting_for_finder");
    let result = match target {
        UnmountTarget::Cloud(state_path, mount_state) => {
            unmount_desktop_cloud_root_record(
                state,
                user_dir,
                state_path,
                mount_state,
                force,
                &on_step,
            )
            .await
        }
        UnmountTarget::Sync(mount_state) => state
            .mount_manager
            .unmount_by_root_id(&mount_state.root_id, force)
            .await
            .map(|()| true),
    };
    let finished = match result {
        Ok(_) => progress("done", None, None),
        Err(err) => progress("failed", None, Some(err)),
    };
    tracing::info!(
        "unmount {}: {} after {} ms",
        finished.root_id,
        finished.status,
        finished.elapsed_ms
    );
    reporter.emit(&finished);
    finished
}

/// Unmounts the given folders (`None`: every mounted folder), cloud folders
/// side by side and CLI fallback mounts one at a time. Every folder is
/// attempted; the result says how each one went.
pub(super) async fn run_unmount_batch(
    state: &AppState,
    root_ids: Option<Vec<String>>,
    force: bool,
    app: Option<&AppHandle>,
) -> Result<UnmountBatchResult, String> {
    let batch_id = NEXT_UNMOUNT_BATCH_ID.fetch_add(1, Ordering::Relaxed);
    let reporter = UnmountReporter { app, batch_id };
    let wanted = |mount_state: &MountRuntimeState| {
        root_ids
            .as_ref()
            .is_none_or(|ids| ids.iter().any(|id| id == &mount_state.root_id))
    };
    let user_dir = match local_vault_storage_dir(state).await {
        Some(user_dir) => Some(user_dir),
        None => match state.session.lock().await.clone() {
            Some(session) => Some(get_user_dir(
                &session.email,
                &current_server_url(state, &session),
            )?),
            None => None,
        },
    };

    let mut cloud = Vec::new();
    let mut sync = Vec::new();
    if let Some(user_dir) = user_dir.as_deref() {
        for (path, mount_state) in load_cloud_mount_state_records_for_unmount(user_dir).await? {
            if wanted(&mount_state) {
                cloud.push(UnmountTarget::Cloud(path, mount_state));
            }
        }
        for mount_state in sync_mount_states(user_dir).await {
            if wanted(&mount_state) {
                sync.push(UnmountTarget::Sync(mount_state));
            }
        }
    }
    tracing::info!(
        "Unmounting {} folder(s) (batch {})",
        cloud.len() + sync.len(),
        batch_id
    );
    for target in cloud.iter().chain(sync.iter()) {
        let mount_state = target.mount_state();
        reporter.emit(&UnmountFolderProgress {
            batch_id,
            root_id: mount_state.root_id.clone(),
            name: mount_name(mount_state),
            status: "queued",
            step: None,
            error: None,
            error_code: None,
            elapsed_ms: 0,
        });
    }

    let mut folders = Vec::new();
    if let Some(user_dir) = user_dir.as_deref() {
        folders = run_bounded(cloud, MAX_PARALLEL_UNMOUNTS, |target| {
            unmount_target(state, user_dir, target, force, &reporter)
        })
        .await;
        for target in sync {
            folders.push(unmount_target(state, user_dir, target, force, &reporter).await);
        }
    }

    let mut result = UnmountBatchResult {
        batch_id,
        folders,
        error: None,
    };
    // "Everything" also stops what no record describes, as Unmount all always has.
    if root_ids.is_none() && result.failures().is_empty() {
        let sweep = match state.cloud_provider.stop_all(true, force).await {
            Ok(()) => state.mount_manager.unmount_all(force).await,
            Err(err) => Err(err),
        };
        result.error = sweep.err();
    }
    Ok(result)
}

/// Unmounts several folders (`root_ids` omitted: every mounted folder) and
/// reports each folder's progress as `unmount_progress` events.
#[tauri::command]
pub async fn unmount_mounts(
    root_ids: Option<Vec<String>>,
    force: Option<bool>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CommandResponse<UnmountBatchResult>, String> {
    let _operation_guard = UPDATE_OPERATION_GATE.read().await;
    match run_unmount_batch(&state, root_ids, force.unwrap_or(false), Some(&app)).await {
        Ok(result) => Ok(CommandResponse::ok(result)),
        Err(err) => Ok(CommandResponse::err(err)),
    }
}

/// Unmount all, for callers that only need to know whether everything stopped.
pub(super) async fn unmount_everything(state: &AppState, force: bool) -> Result<(), String> {
    let failures = run_unmount_batch(state, None, force, None)
        .await?
        .failures();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}
