//! Mounts queued folders in the background, a few at a time, independent of the
//! app window: a hidden window can pause the page, so the queue must not live
//! there. Each job reports the step it is on, and the app follows along through
//! `mount_queue_changed` events or `get_mount_queue`.

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Mounts started together while none of them is slow.
const MAX_PARALLEL_MOUNTS: usize = 3;
/// Mounts running at once, slow ones included.
const MAX_RUNNING_MOUNTS: usize = 4;
/// After this long a mount stops holding up the queue; it keeps running.
const SLOW_AFTER: Duration = Duration::from_secs(45);
/// How often the dispatcher looks for mounts that turned slow.
const DISPATCH_TICK: Duration = Duration::from_secs(5);
/// Finished jobs kept so a paused window can still read their outcome.
const MAX_FINISHED_JOBS: usize = 200;

pub(crate) const MOUNT_QUEUE_EVENT: &str = "mount_queue_changed";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MountJobStatus {
    Queued,
    Running,
    Ready,
    Failed,
    Cancelled,
}

impl MountJobStatus {
    fn finished(self) -> bool {
        matches!(self, Self::Ready | Self::Failed | Self::Cancelled)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MountStepRecord {
    pub step: String,
    pub ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct MountJobSnapshot {
    pub job_id: u64,
    pub batch_id: u64,
    pub root_id: String,
    pub name: String,
    pub origin: String,
    pub status: MountJobStatus,
    pub step: Option<String>,
    pub step_elapsed_ms: u64,
    pub elapsed_ms: u64,
    pub slow: bool,
    pub cancel_requested: bool,
    /// Steps already completed, with how long each took.
    pub steps: Vec<MountStepRecord>,
    pub mount: Option<MountStatusPayload>,
    pub error: Option<String>,
    pub error_code: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MountQueueSnapshot {
    /// The batch `enqueue_mounts` just created, if it queued anything.
    pub batch_id: Option<u64>,
    pub jobs: Vec<MountJobSnapshot>,
}

#[derive(Debug)]
struct MountJob {
    job_id: u64,
    batch_id: u64,
    root_id: Uuid,
    name: String,
    origin: String,
    account_key: String,
    status: MountJobStatus,
    step: Option<&'static str>,
    step_started: Option<Instant>,
    started_at: Option<Instant>,
    finished_ms: Option<u64>,
    steps: Vec<MountStepRecord>,
    mount: Option<MountStatusPayload>,
    error: Option<String>,
    error_code: Option<String>,
    cancel_requested: bool,
}

impl MountJob {
    fn new(
        job_id: u64,
        batch_id: u64,
        root_id: Uuid,
        name: String,
        origin: &str,
        account_key: &str,
    ) -> Self {
        Self {
            job_id,
            batch_id,
            root_id,
            name,
            origin: origin.to_string(),
            account_key: account_key.to_string(),
            status: MountJobStatus::Queued,
            step: None,
            step_started: None,
            started_at: None,
            finished_ms: None,
            steps: Vec::new(),
            mount: None,
            error: None,
            error_code: None,
            cancel_requested: false,
        }
    }

    fn is_slow(&self, now: Instant) -> bool {
        self.status == MountJobStatus::Running
            && self
                .started_at
                .is_some_and(|started| now.saturating_duration_since(started) >= SLOW_AFTER)
    }

    fn snapshot(&self, now: Instant) -> MountJobSnapshot {
        let ms = |since: Option<Instant>| {
            since.map_or(0, |since| {
                now.saturating_duration_since(since).as_millis() as u64
            })
        };
        MountJobSnapshot {
            job_id: self.job_id,
            batch_id: self.batch_id,
            root_id: self.root_id.to_string(),
            name: self.name.clone(),
            origin: self.origin.clone(),
            status: self.status,
            step: self.step.map(str::to_string),
            step_elapsed_ms: if self.status == MountJobStatus::Running {
                ms(self.step_started)
            } else {
                0
            },
            elapsed_ms: self.finished_ms.unwrap_or_else(|| ms(self.started_at)),
            slow: self.is_slow(now),
            cancel_requested: self.cancel_requested,
            steps: self.steps.clone(),
            mount: self.mount.clone(),
            error: self.error.clone(),
            error_code: self.error_code.clone(),
        }
    }
}

#[derive(Default)]
struct MountQueue {
    jobs: Vec<MountJob>,
    dispatcher_running: bool,
    app: Option<AppHandle>,
}

static MOUNT_QUEUE: Lazy<std::sync::Mutex<MountQueue>> =
    Lazy::new(|| std::sync::Mutex::new(MountQueue::default()));
static DISPATCH_WAKE: Lazy<tokio::sync::Notify> = Lazy::new(tokio::sync::Notify::new);
static NEXT_JOB_ID: AtomicU64 = AtomicU64::new(1);

fn queue() -> std::sync::MutexGuard<'static, MountQueue> {
    MOUNT_QUEUE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Queued jobs to start now: while fewer than `MAX_PARALLEL_MOUNTS` running
/// jobs are not yet slow, and fewer than `MAX_RUNNING_MOUNTS` run in total.
fn next_jobs_to_start(jobs: &[MountJob], now: Instant) -> Vec<u64> {
    let running = jobs
        .iter()
        .filter(|job| job.status == MountJobStatus::Running);
    let total = running.clone().count();
    let active = running.filter(|job| !job.is_slow(now)).count();
    let room = MAX_PARALLEL_MOUNTS
        .saturating_sub(active)
        .min(MAX_RUNNING_MOUNTS.saturating_sub(total));
    jobs.iter()
        .filter(|job| job.status == MountJobStatus::Queued)
        .take(room)
        .map(|job| job.job_id)
        .collect()
}

/// Adds jobs for roots not already queued or running for this account.
fn add_jobs(
    jobs: &mut Vec<MountJob>,
    roots: Vec<(Uuid, String)>,
    origin: &str,
    account_key: &str,
) -> Vec<u64> {
    let batch_id = NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed);
    let mut added = Vec::new();
    for (root_id, name) in roots {
        let pending = jobs.iter().any(|job| {
            job.root_id == root_id && job.account_key == account_key && !job.status.finished()
        });
        if pending {
            continue;
        }
        let job_id = NEXT_JOB_ID.fetch_add(1, Ordering::Relaxed);
        jobs.push(MountJob::new(
            job_id,
            batch_id,
            root_id,
            name,
            origin,
            account_key,
        ));
        added.push(job_id);
    }
    // Drop the oldest finished jobs once there are many.
    let finished = jobs.iter().filter(|job| job.status.finished()).count();
    if finished > MAX_FINISHED_JOBS {
        let mut excess = finished - MAX_FINISHED_JOBS;
        jobs.retain(|job| {
            if excess > 0 && job.status.finished() {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }
    added
}

/// Cancels queued jobs at once and asks running ones to stop. `None` means all.
fn cancel_jobs(
    jobs: &mut [MountJob],
    account_key: Option<&str>,
    roots: Option<&[Uuid]>,
) -> Vec<u64> {
    let mut changed = Vec::new();
    for job in jobs.iter_mut() {
        if account_key.is_some_and(|key| key != job.account_key)
            || roots.is_some_and(|roots| !roots.contains(&job.root_id))
        {
            continue;
        }
        match job.status {
            MountJobStatus::Queued => {
                job.status = MountJobStatus::Cancelled;
                job.finished_ms = Some(0);
                changed.push(job.job_id);
            }
            MountJobStatus::Running if !job.cancel_requested => {
                job.cancel_requested = true;
                changed.push(job.job_id);
            }
            _ => {}
        }
    }
    changed
}

fn emit_jobs(job_ids: &[u64]) {
    let (app, snapshots) = {
        let queue = queue();
        let now = Instant::now();
        let snapshots = queue
            .jobs
            .iter()
            .filter(|job| job_ids.contains(&job.job_id))
            .map(|job| job.snapshot(now))
            .collect::<Vec<_>>();
        (queue.app.clone(), snapshots)
    };
    if let Some(app) = app {
        for snapshot in snapshots {
            let _ = app.emit(MOUNT_QUEUE_EVENT, &snapshot);
        }
    }
}

/// The open account (or vault) that queued jobs belong to.
async fn current_account_key(state: &AppState) -> Option<String> {
    if let Some(group) = state.local_vault_group().await {
        return Some(format!("vault:{group}"));
    }
    state
        .session
        .lock()
        .await
        .as_ref()
        .map(|session| format!("account:{}", session.user_id))
}

/// Reports the step a running job is on, for the app and the log.
pub(super) struct MountProgress {
    job_id: u64,
}

impl MountProgress {
    pub(super) fn step(&self, step: &'static str) {
        let now = Instant::now();
        {
            let mut queue = queue();
            let Some(job) = queue.jobs.iter_mut().find(|job| job.job_id == self.job_id) else {
                return;
            };
            if let (Some(previous), Some(started)) = (job.step, job.step_started) {
                let ms = now.saturating_duration_since(started).as_millis() as u64;
                tracing::info!("mount {}: {} took {} ms", job.root_id, previous, ms);
                job.steps.push(MountStepRecord {
                    step: previous.to_string(),
                    ms,
                });
            }
            tracing::info!("mount {}: {}", job.root_id, step);
            job.step = Some(step);
            job.step_started = Some(now);
        }
        emit_jobs(&[self.job_id]);
    }
}

pub(super) fn report_mount_step(progress: Option<&MountProgress>, step: &'static str) {
    if let Some(progress) = progress {
        progress.step(step);
    }
}

/// Cancels every queued mount before sign-out, restart or another account
/// transition takes the exclusive gate; running mounts finish their step.
pub(super) fn cancel_for_transition() {
    super::mount_center::forget_group_access_checks();
    let changed = cancel_jobs(&mut queue().jobs, None, None);
    emit_jobs(&changed);
}

fn ensure_dispatcher(app: &AppHandle) {
    {
        let mut queue = queue();
        queue.app = Some(app.clone());
        if queue.dispatcher_running {
            drop(queue);
            DISPATCH_WAKE.notify_one();
            return;
        }
        queue.dispatcher_running = true;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move { dispatch(app).await });
}

async fn dispatch(app: AppHandle) {
    let mut reported_slow = std::collections::HashSet::new();
    loop {
        let (started, newly_slow) = {
            let mut queue = queue();
            let now = Instant::now();
            let newly_slow = queue
                .jobs
                .iter()
                .filter(|job| job.is_slow(now) && !reported_slow.contains(&job.job_id))
                .map(|job| job.job_id)
                .collect::<Vec<_>>();
            let started = next_jobs_to_start(&queue.jobs, now);
            for job in queue
                .jobs
                .iter_mut()
                .filter(|job| started.contains(&job.job_id))
            {
                job.status = MountJobStatus::Running;
                job.started_at = Some(now);
            }
            if started.is_empty()
                && !queue.jobs.iter().any(|job| {
                    matches!(job.status, MountJobStatus::Queued | MountJobStatus::Running)
                })
            {
                queue.dispatcher_running = false;
                return;
            }
            (started, newly_slow)
        };
        for job_id in &newly_slow {
            reported_slow.insert(*job_id);
            let root = queue()
                .jobs
                .iter()
                .find(|job| job.job_id == *job_id)
                .map(|job| job.root_id);
            if let Some(root) = root {
                tracing::warn!(
                    "mount {}: still running after {} s; starting the next folder",
                    root,
                    SLOW_AFTER.as_secs()
                );
            }
        }
        emit_jobs(&newly_slow);
        emit_jobs(&started);
        for job_id in started {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { run_job(app, job_id).await });
        }
        tokio::select! {
            _ = DISPATCH_WAKE.notified() => {}
            _ = sleep(DISPATCH_TICK) => {}
        }
    }
}

async fn run_job(app: AppHandle, job_id: u64) {
    let state = app.state::<AppState>();
    let (root_id, account_key) = {
        let queue = queue();
        match queue.jobs.iter().find(|job| job.job_id == job_id) {
            Some(job) => (job.root_id, job.account_key.clone()),
            None => return,
        }
    };
    let progress = MountProgress { job_id };
    let result = if current_account_key(&state).await.as_deref() != Some(account_key.as_str()) {
        Err("The account changed before this folder was mounted".to_string())
    } else {
        match ensure_local_team_write_or_vault(&state).await {
            Ok(_operation_guard) => {
                progress.step("checking");
                super::mount_center::mount_root_by_id(&state, root_id.to_string(), Some(&progress))
                    .await
            }
            Err(err) => Err(err),
        }
    };

    let cancel_after = {
        let mut queue = queue();
        let Some(job) = queue.jobs.iter_mut().find(|job| job.job_id == job_id) else {
            return;
        };
        let now = Instant::now();
        if let (Some(previous), Some(started)) = (job.step, job.step_started) {
            job.steps.push(MountStepRecord {
                step: previous.to_string(),
                ms: now.saturating_duration_since(started).as_millis() as u64,
            });
        }
        job.finished_ms = job
            .started_at
            .map(|started| now.saturating_duration_since(started).as_millis() as u64);
        match result {
            Ok(response) if response.success => {
                job.status = MountJobStatus::Ready;
                job.mount = response.data;
                job.step = Some("ready");
            }
            Ok(response) => {
                job.status = MountJobStatus::Failed;
                job.error = response.error;
                job.error_code = response.error_code;
                job.step = Some("failed");
            }
            Err(err) => {
                job.status = MountJobStatus::Failed;
                job.error = Some(err);
                job.step = Some("failed");
            }
        }
        tracing::info!(
            "mount {}: {:?} after {} ms",
            job.root_id,
            job.status,
            job.finished_ms.unwrap_or(0)
        );
        job.cancel_requested && job.status == MountJobStatus::Ready
    };
    emit_jobs(&[job_id]);
    DISPATCH_WAKE.notify_one();

    // Cancelled while the native start was already under way: undo it.
    if cancel_after {
        if let Err(err) = unmount_mount_by_root_id(root_id.to_string(), Some(false), state).await {
            tracing::warn!(
                "mount {}: undoing a cancelled mount failed: {}",
                root_id,
                err
            );
        }
        {
            let mut queue = queue();
            if let Some(job) = queue.jobs.iter_mut().find(|job| job.job_id == job_id) {
                job.status = MountJobStatus::Cancelled;
                job.mount = None;
            }
        }
        emit_jobs(&[job_id]);
    }
}

/// Queues folders to mount in the background and returns at once.
#[tauri::command]
pub async fn enqueue_mounts(
    root_ids: Vec<String>,
    origin: Option<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountQueueSnapshot>, String> {
    let _operation_guard = ensure_local_team_write_or_vault(&state).await?;
    let Some(account_key) = current_account_key(&state).await else {
        return Ok(CommandResponse::err("No account or vault is open"));
    };
    let client = state.local_client.client().await?;
    let enrolled = match super::mount_center::enrolled_roots_with_groups(&client).await {
        Ok(roots) => roots,
        Err(err) => return Ok(CommandResponse::err(err)),
    };
    let roots = root_ids
        .iter()
        .filter_map(|id| Uuid::parse_str(id.trim()).ok())
        .filter_map(|id| {
            enrolled
                .iter()
                .find(|(root, _)| root.root_id == id)
                .map(|(root, _)| (id, super::mount_center::folder_name(&root.path)))
        })
        .collect::<Vec<_>>();
    let origin = match origin.as_deref() {
        Some("user") => "user",
        Some("group") => "group",
        _ => "auto",
    };
    let added = add_jobs(&mut queue().jobs, roots, origin, &account_key);
    tracing::info!("Queued {} folder(s) to mount ({})", added.len(), origin);
    emit_jobs(&added);
    let batch_id = if added.is_empty() {
        None
    } else {
        ensure_dispatcher(&app);
        queue()
            .jobs
            .iter()
            .find(|job| job.job_id == added[0])
            .map(|job| job.batch_id)
    };
    let mut snapshot = snapshot_for(&account_key);
    snapshot.batch_id = batch_id;
    Ok(CommandResponse::ok(snapshot))
}

fn snapshot_for(account_key: &str) -> MountQueueSnapshot {
    let queue = queue();
    let now = Instant::now();
    MountQueueSnapshot {
        batch_id: None,
        jobs: queue
            .jobs
            .iter()
            .filter(|job| job.account_key == account_key)
            .map(|job| job.snapshot(now))
            .collect(),
    }
}

/// Queued and recent mounts of the open account or vault.
#[tauri::command]
pub async fn get_mount_queue(
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountQueueSnapshot>, String> {
    let Some(account_key) = current_account_key(&state).await else {
        return Ok(CommandResponse::ok(MountQueueSnapshot {
            batch_id: None,
            jobs: Vec::new(),
        }));
    };
    Ok(CommandResponse::ok(snapshot_for(&account_key)))
}

/// Cancels queued mounts and stops running ones once their current step ends.
/// Without `root_ids`, every mount of the open account or vault.
#[tauri::command]
pub async fn cancel_mounts(
    root_ids: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> Result<CommandResponse<MountQueueSnapshot>, String> {
    let Some(account_key) = current_account_key(&state).await else {
        return Ok(CommandResponse::ok(MountQueueSnapshot {
            batch_id: None,
            jobs: Vec::new(),
        }));
    };
    let roots = root_ids.map(|ids| {
        ids.iter()
            .filter_map(|id| Uuid::parse_str(id.trim()).ok())
            .collect::<Vec<_>>()
    });
    let changed = cancel_jobs(&mut queue().jobs, Some(&account_key), roots.as_deref());
    emit_jobs(&changed);
    DISPATCH_WAKE.notify_one();
    Ok(CommandResponse::ok(snapshot_for(&account_key)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(job_id: u64, status: MountJobStatus, started_secs_ago: Option<u64>) -> MountJob {
        let mut job = MountJob::new(
            job_id,
            1,
            Uuid::new_v4(),
            format!("f{job_id}"),
            "auto",
            "account:a",
        );
        job.status = status;
        job.started_at = started_secs_ago.map(|secs| Instant::now() - Duration::from_secs(secs));
        job
    }

    #[test]
    fn starts_three_mounts_at_a_time() {
        let jobs = vec![
            job(1, MountJobStatus::Queued, None),
            job(2, MountJobStatus::Queued, None),
            job(3, MountJobStatus::Queued, None),
            job(4, MountJobStatus::Queued, None),
        ];
        assert_eq!(next_jobs_to_start(&jobs, Instant::now()), vec![1, 2, 3]);

        let jobs = vec![
            job(1, MountJobStatus::Running, Some(1)),
            job(2, MountJobStatus::Ready, Some(9)),
            job(3, MountJobStatus::Queued, None),
            job(4, MountJobStatus::Queued, None),
            job(5, MountJobStatus::Queued, None),
        ];
        assert_eq!(next_jobs_to_start(&jobs, Instant::now()), vec![3, 4]);
    }

    #[test]
    fn a_slow_mount_frees_its_slot_up_to_the_cap() {
        let slow = SLOW_AFTER.as_secs() + 1;
        let jobs = vec![
            job(1, MountJobStatus::Running, Some(slow)),
            job(2, MountJobStatus::Running, Some(1)),
            job(3, MountJobStatus::Queued, None),
            job(4, MountJobStatus::Queued, None),
            job(5, MountJobStatus::Queued, None),
        ];
        // The slow mount no longer counts, so two more start (four running in all).
        assert_eq!(next_jobs_to_start(&jobs, Instant::now()), vec![3, 4]);

        let jobs = vec![
            job(1, MountJobStatus::Running, Some(slow)),
            job(2, MountJobStatus::Running, Some(slow)),
            job(3, MountJobStatus::Running, Some(slow)),
            job(4, MountJobStatus::Running, Some(1)),
            job(5, MountJobStatus::Queued, None),
        ];
        assert!(
            next_jobs_to_start(&jobs, Instant::now()).is_empty(),
            "cap of four"
        );
    }

    #[test]
    fn a_folder_already_queued_or_running_is_not_added_again() {
        let root = Uuid::new_v4();
        let mut jobs = Vec::new();
        let first = add_jobs(&mut jobs, vec![(root, "a".into())], "auto", "account:a");
        let again = add_jobs(&mut jobs, vec![(root, "a".into())], "user", "account:a");
        let other_account = add_jobs(&mut jobs, vec![(root, "a".into())], "auto", "account:b");
        assert_eq!(first.len(), 1);
        assert!(again.is_empty());
        assert_eq!(other_account.len(), 1);

        jobs[0].status = MountJobStatus::Failed;
        assert_eq!(
            add_jobs(&mut jobs, vec![(root, "a".into())], "user", "account:a").len(),
            1
        );
    }

    #[test]
    fn cancelling_stops_queued_jobs_and_flags_running_ones() {
        let mut jobs = vec![
            job(1, MountJobStatus::Queued, None),
            job(2, MountJobStatus::Running, Some(1)),
            job(3, MountJobStatus::Ready, Some(5)),
        ];
        let changed = cancel_jobs(&mut jobs, Some("account:a"), None);
        assert_eq!(changed, vec![1, 2]);
        assert_eq!(jobs[0].status, MountJobStatus::Cancelled);
        assert_eq!(jobs[1].status, MountJobStatus::Running);
        assert!(jobs[1].cancel_requested);
        assert_eq!(jobs[2].status, MountJobStatus::Ready);
        assert!(cancel_jobs(&mut jobs, Some("account:other"), None).is_empty());
    }

    #[test]
    fn cancelling_selected_folders_leaves_the_others() {
        let mut jobs = vec![
            job(1, MountJobStatus::Queued, None),
            job(2, MountJobStatus::Queued, None),
        ];
        let keep = jobs[1].root_id;
        let target = [jobs[0].root_id];
        cancel_jobs(&mut jobs, None, Some(&target));
        assert_eq!(jobs[0].status, MountJobStatus::Cancelled);
        assert_eq!(jobs[1].status, MountJobStatus::Queued);
        assert_eq!(jobs[1].root_id, keep);
    }

    #[test]
    fn a_snapshot_reports_slow_running_jobs() {
        let running = job(1, MountJobStatus::Running, Some(SLOW_AFTER.as_secs() + 2));
        let snapshot = running.snapshot(Instant::now());
        assert!(snapshot.slow);
        assert!(snapshot.elapsed_ms >= SLOW_AFTER.as_millis() as u64);
        assert_eq!(snapshot.status, MountJobStatus::Running);
    }
}
