//! Progress for protecting a folder or removing its protection. The commands
//! report through `folder_job_progress` events so the app can show a bar, or
//! let the user send the work to the background. The end is announced from
//! here rather than the page: a hidden window can pause the page, so a notice
//! sent from it would only appear once the user came back.

use super::*;
use hybridcipher_client::ipc::coverage::{
    CoverageDecryptProgress, CoverageEnrollPhase, CoverageEnrollProgress,
};
use std::time::Instant;
use tauri_plugin_notification::NotificationExt;

pub(crate) const FOLDER_JOB_PROGRESS_EVENT: &str = "folder_job_progress";
/// Updates closer together than this are dropped unless the percent changed.
const MIN_EMIT_INTERVAL: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderJobKind {
    Protect,
    Unprotect,
}

#[derive(Debug, Clone, Serialize)]
pub struct FolderJobProgressPayload {
    pub job_id: String,
    pub kind: FolderJobKind,
    pub root_path: String,
    /// "encrypting", "finalizing", "rescanning" or "decrypting".
    pub phase: &'static str,
    pub processed_files: usize,
    pub total_files: usize,
    pub failed_files: usize,
}

/// Decides which updates are worth sending: a folder of 100k files reports
/// every file, and each event crosses into the page.
#[derive(Debug, Default)]
pub(crate) struct ProgressThrottle {
    last: Option<(Instant, &'static str, usize)>,
}

impl ProgressThrottle {
    /// The first update, a new phase, the last file and each new whole percent
    /// are always sent; otherwise at most one per `MIN_EMIT_INTERVAL`.
    pub(crate) fn should_emit(
        &mut self,
        phase: &'static str,
        processed: usize,
        total: usize,
        now: Instant,
    ) -> bool {
        let percent = processed
            .saturating_mul(100)
            .checked_div(total)
            .unwrap_or(0);
        let emit = match self.last {
            None => true,
            Some((at, last_phase, last_percent)) => {
                phase != last_phase
                    || processed >= total
                    || percent != last_percent
                    || now.duration_since(at) >= MIN_EMIT_INTERVAL
            }
        };
        if emit {
            self.last = Some((now, phase, percent));
        }
        emit
    }
}

pub(crate) struct FolderJobReporter {
    app: AppHandle,
    job_id: String,
    kind: FolderJobKind,
    root_path: String,
    throttle: ProgressThrottle,
}

impl FolderJobReporter {
    pub(crate) fn new(
        app: AppHandle,
        job_id: String,
        kind: FolderJobKind,
        root_path: &Path,
    ) -> Self {
        Self {
            app,
            job_id,
            kind,
            root_path: root_path.display().to_string(),
            throttle: ProgressThrottle::default(),
        }
    }

    pub(crate) fn enroll(&mut self, update: CoverageEnrollProgress) {
        let phase = match update.phase {
            CoverageEnrollPhase::Hydrating => "encrypting",
            CoverageEnrollPhase::Finalizing => "finalizing",
            CoverageEnrollPhase::Rescanning => "rescanning",
        };
        self.report(
            phase,
            update.processed_files,
            update.total_files,
            update.skipped_due_to_errors,
        );
    }

    pub(crate) fn decrypt(&mut self, update: CoverageDecryptProgress) {
        self.report(
            "decrypting",
            update.decrypted_files + update.failed_files,
            update.total_files,
            update.failed_files,
        );
    }

    fn report(&mut self, phase: &'static str, processed: usize, total: usize, failed: usize) {
        if !self
            .throttle
            .should_emit(phase, processed, total, Instant::now())
        {
            return;
        }
        let payload = FolderJobProgressPayload {
            job_id: self.job_id.clone(),
            kind: self.kind,
            root_path: self.root_path.clone(),
            phase,
            processed_files: processed,
            total_files: total,
            failed_files: failed,
        };
        let _ = self.app.emit(FOLDER_JOB_PROGRESS_EVENT, &payload);
    }
}

/// Tell the user through the OS that a job ended, unless they are looking at
/// the app; then the page's own notice is enough.
pub(crate) fn notify_folder_job_finished(app: &AppHandle, title: &str, body: &str) {
    let in_view = app.get_webview_window("main").is_some_and(|window| {
        window.is_visible().unwrap_or(false)
            && !window.is_minimized().unwrap_or(false)
            && window.is_focused().unwrap_or(false)
    });
    if in_view {
        return;
    }
    if let Err(err) = app.notification().builder().title(title).body(body).show() {
        tracing::warn!("Failed to show folder job notification: {}", err);
    }
}

pub(crate) fn folder_display_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| path.display().to_string())
}

pub(crate) fn files_phrase(count: u64) -> String {
    if count == 1 {
        "1 file".to_string()
    } else {
        format!("{} files", count)
    }
}

#[cfg(test)]
#[path = "../../tests/coverage/test_folder_job_progress.rs"]
mod folder_job_progress_tests;
