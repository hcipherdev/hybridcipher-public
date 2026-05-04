use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// Start filesystem watchers after explicit initialization.
    pub async fn start_coverage_watchers(&self) -> Result<(), ClientError> {
        if !self.config.coverage_watchers_enabled {
            self.logger.log(
                crate::logging::LogLevel::Debug,
                "Coverage watchers are disabled by configuration",
                Some("coverage_watchers_disabled"),
            );
            return Ok(());
        }
        self.ensure_state_loaded().await?;
        self.ensure_coverage_watcher().await;
        Ok(())
    }

    /// Start the coverage replication worker in the background (non-blocking).
    /// This will upload coverage log entries to the server without blocking other operations.
    pub fn start_coverage_replication(&self) {
        self.ensure_coverage_replication_worker();
    }

    /// Check if coverage filesystem watchers are enabled.
    pub fn coverage_watchers_enabled(&self) -> bool {
        self.config.coverage_watchers_enabled
    }

    /// Return the raw file exclusion pattern strings from client config.
    pub fn excluded_file_patterns(&self) -> Vec<String> {
        self.config.excluded_file_patterns.clone()
    }

    pub(in super::super) async fn ensure_coverage_watcher(&self) {
        if !self.config.coverage_watchers_enabled {
            return;
        }
        if !self.has_active_roots().await {
            return;
        }

        let mut watcher = self.coverage_watcher.lock().await;
        if watcher.running {
            return;
        }

        watcher.running = true;
        let client = self.clone();
        let control = self.coverage_watcher.clone();
        tokio::spawn(async move {
            client.run_coverage_watcher_loop(control).await;
        });
    }

    pub(in super::super) async fn run_coverage_watcher_loop(
        self,
        control: Arc<Mutex<CoverageWatcherState>>,
    ) {
        let (event_tx, mut event_rx) = mpsc::unbounded_channel();
        let mut watchers: HashMap<Uuid, CoverageRootWatcher> = HashMap::new();
        let mut dirty_roots: HashSet<Uuid> = HashSet::new();
        let mut last_scanned: HashMap<Uuid, Instant> = HashMap::new();

        let mut periodic_scan = interval(std::time::Duration::from_secs(
            COVERAGE_WATCHER_INTERVAL_SECS,
        ));
        periodic_scan.set_missed_tick_behavior(MissedTickBehavior::Delay);

        let mut root_refresh = interval(std::time::Duration::from_secs(
            COVERAGE_WATCHER_ROOT_REFRESH_SECS,
        ));
        root_refresh.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            let active_roots = self.active_coverage_roots_snapshot().await;
            if active_roots.is_empty() {
                watchers.clear();
                dirty_roots.clear();
                last_scanned.clear();

                let mut guard = control.lock().await;
                guard.running = false;
                break;
            }

            let active_ids: HashSet<Uuid> = active_roots.iter().map(|root| root.root_id).collect();

            watchers.retain(|root_id, _| active_ids.contains(root_id));
            last_scanned.retain(|root_id, _| active_ids.contains(root_id));

            for root in active_roots.iter() {
                if watchers.contains_key(&root.root_id) {
                    continue;
                }

                match CoverageRootWatcher::new(root.clone(), event_tx.clone(), self.logger.clone())
                {
                    Ok(watcher) => {
                        self.logger.log(
                            crate::logging::LogLevel::Debug,
                            &format!(
                                "Attached filesystem watcher to coverage root {}",
                                root.path.display()
                            ),
                            Some("coverage_watcher_attach"),
                        );
                        watchers.insert(root.root_id, watcher);
                    }
                    Err(err) => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Failed to attach filesystem watcher to {}: {}",
                                root.path.display(),
                                err
                            ),
                            Some("coverage_watcher_attach_failed"),
                        );
                    }
                }
            }

            let root_paths: HashMap<Uuid, PathBuf> = active_roots
                .iter()
                .map(|root| (root.root_id, root.path.clone()))
                .collect();

            for root_id in active_ids.iter() {
                if !last_scanned.contains_key(root_id) {
                    dirty_roots.insert(*root_id);
                }
            }

            if !dirty_roots.is_empty() {
                self.flush_dirty_coverage_roots(&mut dirty_roots, &root_paths, &mut last_scanned)
                    .await;
                continue;
            }

            tokio::select! {
                maybe_event = event_rx.recv() => {
                    let Some(event) = maybe_event else {
                        watchers.clear();
                        dirty_roots.clear();
                        last_scanned.clear();

                        let mut guard = control.lock().await;
                        guard.running = false;
                        break;
                    };

                    match event {
                        CoverageWatcherEvent::RootChanged(root_id) => {
                            let still_active = self.coverage_root_is_active(root_id).await;
                            if !still_active {
                                watchers.remove(&root_id);
                                last_scanned.remove(&root_id);
                            } else if active_ids.contains(&root_id) {
                                dirty_roots.insert(root_id);
                            }
                        }
                        CoverageWatcherEvent::FileCreated { root_id, root_path, created_path } => {
                            let still_active = self.coverage_root_is_active(root_id).await;
                            if !still_active {
                                watchers.remove(&root_id);
                                last_scanned.remove(&root_id);
                            } else if active_ids.contains(&root_id) {
                                if let Err(err) = self
                                    .handle_new_file_event(
                                        root_id,
                                        root_path.clone(),
                                        created_path.clone(),
                                    )
                                    .await
                                {
                                    self.logger.log(
                                        crate::logging::LogLevel::Warn,
                                        &format!(
                                            "Auto-encryption for new file {} failed: {}",
                                            created_path.display(),
                                            err
                                        ),
                                        Some("coverage_auto_encrypt_error"),
                                    );
                                } else {
                                    dirty_roots.insert(root_id);
                                }
                            }
                        }
                        CoverageWatcherEvent::WatcherError { root_id, message } => {
                            let still_active = self.coverage_root_is_active(root_id).await;
                            if !still_active {
                                watchers.remove(&root_id);
                                last_scanned.remove(&root_id);
                            } else if active_ids.contains(&root_id) {
                                dirty_roots.insert(root_id);
                            }
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &message,
                                Some("coverage_watcher_error"),
                            );
                        }
                    }
                }
                _ = periodic_scan.tick() => {
                    dirty_roots.extend(active_ids.iter().copied());
                }
                _ = root_refresh.tick() => {
                    // Wake loop so new roots are discovered quickly even without filesystem events.
                }
            }

            self.flush_dirty_coverage_roots(&mut dirty_roots, &root_paths, &mut last_scanned)
                .await;
        }
    }

    pub(in super::super) async fn has_unreplicated_coverage(&self) -> bool {
        let state = self.state.read().await;
        if let Some(gid) = state.active_group_id {
            if let Some(ledger) = state.coverage_ledgers.get(&gid) {
                return ledger.loaded
                    && !ledger.permanently_disabled
                    && ledger.sequence > ledger.ack_sequence;
            }
        }
        false
    }

    pub(in super::super) fn ensure_coverage_replication_worker(&self) {
        let client = self.clone();
        let control = self.coverage_replication.clone();

        // Spawn the task immediately without any blocking checks
        // The check for unreplicated coverage happens inside the task
        tokio::spawn(async move {
            // Check if worker is already running (fast check)
            {
                let worker = control.lock().await;
                if worker.running {
                    return;
                }
            }

            // Check if there's unreplicated coverage (non-blocking async check)
            if !client.has_unreplicated_coverage().await {
                return;
            }

            // Mark as running and start the replication loop
            {
                let mut worker = control.lock().await;
                if worker.running {
                    return; // Double-check after async operation
                }
                worker.running = true;
            }

            client.run_coverage_replication_loop(control).await;
        });
    }

    pub async fn begin_coverage_bulk_operation(&self) -> CoverageBulkGuard<S, N> {
        let mut state = self.coverage_compaction.lock().await;
        state.bulk_depth = state.bulk_depth.saturating_add(1);
        drop(state);

        CoverageBulkGuard {
            client: self.clone(),
        }
    }

    pub(in super::super) async fn end_coverage_bulk_operation(&self) {
        let bulk_active = {
            let mut state = self.coverage_compaction.lock().await;
            if state.bulk_depth > 0 {
                state.bulk_depth = state.bulk_depth.saturating_sub(1);
            }
            state.bulk_depth > 0
        };

        if !bulk_active {
            let group_id = {
                let state = self.state.read().await;
                state.active_group_id
            };
            if let Some(group_id) = group_id {
                self.request_coverage_compaction(group_id, false).await;
            }
            self.flush_deferred_state_save().await;
        }
    }

    pub(in super::super) async fn request_coverage_compaction(
        &self,
        group_id: Uuid,
        mark_activity: bool,
    ) {
        let now = Instant::now();
        let mut state = self.coverage_compaction.lock().await;
        let tracker = state.trackers.entry(group_id).or_default();
        if mark_activity {
            tracker.last_update_at = Some(now);
        }
        state.pending_groups.insert(group_id);
        drop(state);

        self.ensure_coverage_compaction_worker();
    }

    pub(in super::super) fn ensure_coverage_compaction_worker(&self) {
        let client = self.clone();
        let control = self.coverage_compaction.clone();

        tokio::spawn(async move {
            let mut guard = control.lock().await;
            if guard.running {
                return;
            }
            guard.running = true;
            drop(guard);

            client.run_coverage_compaction_loop(control).await;
        });
    }

    pub(in super::super) async fn run_coverage_compaction_loop(
        self,
        control: Arc<Mutex<CoverageCompactionState>>,
    ) {
        loop {
            let (pending_groups, bulk_active) = {
                let mut state = control.lock().await;
                if state.pending_groups.is_empty() {
                    state.running = false;
                    return;
                }
                (
                    state.pending_groups.iter().copied().collect::<Vec<_>>(),
                    state.bulk_depth > 0,
                )
            };

            let mut did_work = false;

            for group_id in pending_groups {
                if let Some(plan) = self.coverage_compaction_plan(group_id, bulk_active).await {
                    let result = self
                        .compact_coverage_log_deltas(group_id, plan.compact_up_to)
                        .await;

                    match result {
                        Ok(()) => {
                            let mut state = control.lock().await;
                            if let Some(tracker) = state.trackers.get_mut(&group_id) {
                                tracker.last_compact_sequence = plan.compact_up_to;
                                tracker.last_compact_at = Some(Instant::now());
                                tracker.backoff_until = None;
                            }
                            drop(state);

                            let pending_remaining = {
                                let state = self.state.read().await;
                                state
                                    .coverage_ledgers
                                    .get(&group_id)
                                    .map(|ledger| {
                                        ledger.snapshot_sequence.min(ledger.ack_sequence)
                                            > plan.compact_up_to
                                    })
                                    .unwrap_or(false)
                            };

                            if !pending_remaining {
                                let mut state = control.lock().await;
                                state.pending_groups.remove(&group_id);
                            }
                        }
                        Err(err) => {
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "Coverage compaction failed for group {}: {}",
                                    group_id, err
                                ),
                                Some("coverage_compaction"),
                            );
                            let backoff = self.config.coverage_compaction.error_backoff_secs;
                            let mut state = control.lock().await;
                            if let Some(tracker) = state.trackers.get_mut(&group_id) {
                                tracker.backoff_until =
                                    Some(Instant::now() + std::time::Duration::from_secs(backoff));
                            }
                        }
                    }

                    did_work = true;
                }
            }

            if !did_work {
                sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    }

    pub(in super::super) async fn coverage_compaction_plan(
        &self,
        group_id: Uuid,
        bulk_active: bool,
    ) -> Option<CoverageCompactionPlan> {
        let config = &self.config.coverage_compaction;
        let now = Instant::now();

        let (snapshot_sequence, ack_sequence) = {
            let state = self.state.read().await;
            let ledger = state.coverage_ledgers.get(&group_id)?;
            (ledger.snapshot_sequence, ledger.ack_sequence)
        };

        let compact_up_to = snapshot_sequence.min(ack_sequence);
        if compact_up_to == 0 {
            return None;
        }

        let tracker = {
            let state = self.coverage_compaction.lock().await;
            state.trackers.get(&group_id).cloned().unwrap_or_default()
        };

        if compact_up_to <= tracker.last_compact_sequence {
            return None;
        }

        if let Some(backoff_until) = tracker.backoff_until {
            if now < backoff_until {
                return None;
            }
        }

        if let Some(last_compact_at) = tracker.last_compact_at {
            let elapsed = now.duration_since(last_compact_at).as_secs();
            if config.min_interval_secs > 0 && elapsed < config.min_interval_secs {
                return None;
            }
        }

        let pending_entries = compact_up_to.saturating_sub(tracker.last_compact_sequence);
        if pending_entries == 0 {
            return None;
        }

        let needs_journal_bytes =
            config.max_journal_bytes > 0 || config.bulk_force_journal_bytes > 0;
        let journal_bytes = if needs_journal_bytes {
            match self.storage.coverage_log_journal_size(group_id).await {
                Ok(bytes) => bytes,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Failed to read coverage journal size for group {}: {}",
                            group_id, err
                        ),
                        Some("coverage_compaction"),
                    );
                    None
                }
            }
        } else {
            None
        };

        if bulk_active && config.bulk_mode_enabled {
            let force_bytes = config.bulk_force_journal_bytes;
            let force =
                force_bytes > 0 && journal_bytes.unwrap_or(0) >= config.bulk_force_journal_bytes;
            if !force {
                return None;
            }
        }

        let since_last_update = tracker
            .last_update_at
            .map(|t| now.duration_since(t).as_secs())
            .unwrap_or(u64::MAX);
        let since_last_compact = tracker
            .last_compact_at
            .map(|t| now.duration_since(t).as_secs())
            .unwrap_or(u64::MAX);

        let mut trigger = false;

        if config.min_entries > 0 && pending_entries >= config.min_entries {
            trigger = true;
        }

        if config.idle_quiet_secs > 0 && since_last_update >= config.idle_quiet_secs {
            trigger = true;
        }

        if config.max_interval_secs > 0 && since_last_compact >= config.max_interval_secs {
            trigger = true;
        }

        if config.max_journal_bytes > 0 {
            if let Some(bytes) = journal_bytes {
                if bytes >= config.max_journal_bytes {
                    trigger = true;
                }
            }
        }

        if !trigger {
            return None;
        }

        Some(CoverageCompactionPlan { compact_up_to })
    }

    pub(in super::super) async fn update_coverage_ack_sequence(&self, group_id: Uuid, ack: u64) {
        {
            let mut state = self.state.write().await;
            let meta_snapshot = {
                if let Some(ledger) = state.coverage_ledgers.get_mut(&group_id) {
                    if ack > ledger.ack_sequence {
                        ledger.ack_sequence = ack;
                        ledger.delta_ack_sequence = ledger.delta_ack_sequence.max(ack);
                    }
                    if ledger.consecutive_failures > 0 {
                        ledger.consecutive_failures = 0;
                    }
                    Some(ledger.to_meta())
                } else {
                    None
                }
            };
            if let Some(meta_snapshot) = meta_snapshot {
                state.coverage_ledgers_meta.insert(group_id, meta_snapshot);
            }
        }
        self.request_coverage_compaction(group_id, false).await;
    }

    pub(in super::super) async fn record_coverage_terminal_failure(
        &self,
        group_id: Uuid,
        reason: &str,
    ) -> Option<(u32, bool)> {
        let mut state = self.state.write().await;
        let meta_snapshot;
        let result;
        {
            let ledger = state.coverage_ledgers.get_mut(&group_id)?;
            ledger.consecutive_failures = ledger.consecutive_failures.saturating_add(1);
            let failures = ledger.consecutive_failures;
            let hit_limit = failures >= COVERAGE_TERMINAL_FAILURE_LIMIT;
            if hit_limit {
                ledger.permanently_disabled = true;
                ledger.disabled_reason = Some(reason.to_string());
                ledger.consecutive_failures = 0;
                ledger.ack_sequence = ledger.sequence;
                ledger.delta_ack_sequence = ledger.sequence;
            }
            meta_snapshot = ledger.to_meta();
            result = (failures, hit_limit);
        }
        state.coverage_ledgers_meta.insert(group_id, meta_snapshot);
        Some(result)
    }

    pub(in super::super) async fn run_coverage_replication_loop(
        self,
        control: Arc<Mutex<CoverageReplicationState>>,
    ) {
        let http_client = reqwest::Client::new();
        let parallel_uploads = self.config.coverage_parallel_uploads.max(1);
        let throttle = Arc::new(CoverageUploadThrottle::new(&self.config));

        if parallel_uploads > 1 {
            // Parallel upload mode
            self.run_parallel_coverage_uploads(control, http_client, parallel_uploads, throttle)
                .await;
        } else {
            // Sequential upload mode (original behavior)
            self.run_sequential_coverage_uploads(control, http_client, throttle)
                .await;
        }
    }

    pub(in super::super) async fn run_sequential_coverage_uploads(
        &self,
        control: Arc<Mutex<CoverageReplicationState>>,
        http_client: reqwest::Client,
        throttle: Arc<CoverageUploadThrottle>,
    ) {
        loop {
            let (needs_work, group_id, ack_sequence) = {
                let state = self.state.read().await;
                let gid = state.active_group_id;
                let (needs, ack_seq) = gid
                    .and_then(|g| state.coverage_ledgers.get(&g))
                    .map(|ledger| {
                        (
                            ledger.loaded
                                && !ledger.permanently_disabled
                                && ledger.sequence > ledger.ack_sequence,
                            ledger.ack_sequence,
                        )
                    })
                    .unwrap_or((false, 0));
                (needs, gid, ack_seq)
            };

            if !needs_work {
                break;
            }

            let Some(group_id) = group_id else {
                break;
            };

            let session = match self.get_session_info().await {
                Ok(info) => info,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "coverage replication aborted: failed to fetch session info ({})",
                            err
                        ),
                        Some("coverage_replication_session"),
                    );
                    break;
                }
            };

            let Some(device_id) = session.device_id.clone() else {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "coverage replication aborted: session missing device identifier",
                    Some("coverage_replication_session"),
                );
                break;
            };

            let token = session.token.clone();
            let server_base = Self::resolve_server_base_url(session.server_url.clone());
            let url = format!("{}/api/v1/groups/{}/coverage/log", server_base, group_id);

            let batch_size = self.config.coverage_batch_size;
            let deltas = match self
                .coverage_replication_batch(ack_sequence, batch_size)
                .await
            {
                Ok(batch) => batch,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("coverage replication failed to read deltas: {}", err),
                        Some("coverage_replication_batch"),
                    );
                    throttle.register_failure(None).await;
                    continue;
                }
            };

            if deltas.is_empty() {
                break;
            }

            let payload = CoverageDeltaUploadRequest {
                device_id: device_id.clone(),
                deltas: deltas
                    .iter()
                    .map(|delta| CoverageDeltaUploadEntry {
                        sequence: delta.sequence,
                        file_id: delta.file_id.clone(),
                        epoch_id: delta.epoch_id,
                        updated_at: delta.updated_at,
                        action: delta.action.clone(),
                    })
                    .collect(),
            };

            throttle.wait_for_slot().await;

            let response = match http_client
                .post(&url)
                .header("Authorization", format!("Bearer {}", token))
                .json(&payload)
                .send()
                .await
            {
                Ok(resp) => resp,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("coverage replication request failed: {}", err),
                        Some("coverage_replication_request"),
                    );
                    throttle.register_failure(None).await;
                    continue;
                }
            };

            let status = response.status();
            let retry_after = if should_backoff(status) {
                retry_after_delay(response.headers())
            } else {
                None
            };

            if let Some(retention_err) = self
                .handle_retention_status(status, response.headers(), "coverage_replication")
                .await
            {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!(
                        "coverage replication blocked by retention policy: {}",
                        retention_err
                    ),
                    Some("coverage_replication_retention"),
                );
                break;
            }

            if status == StatusCode::UNAUTHORIZED {
                if let Err(err) = self.cleanup_conflicting_auth_state().await {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("failed to clean up auth state after 401: {}", err),
                        Some("coverage_replication_auth"),
                    );
                }
                break;
            }

            if !status.is_success() {
                let body = response
                    .text()
                    .await
                    .unwrap_or_else(|_| "<unavailable>".to_string());
                let classification = classify_coverage_upload_failure(status, &body, retry_after);

                match classification {
                    CoverageUploadFailure::Retryable { retry_after } => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "coverage replication received {} from server: {}",
                                status, body
                            ),
                            Some("coverage_replication_response"),
                        );
                        throttle.register_failure(retry_after).await;
                    }
                    CoverageUploadFailure::Terminal {
                        reason,
                        retry_after,
                    } => {
                        if let Some((failures, disabled)) = self
                            .record_coverage_terminal_failure(group_id, &reason)
                            .await
                        {
                            let message = format!(
                                "coverage replication received {} from server: {}; classified as terminal ({}); failure {}/{}",
                                status,
                                body,
                                reason,
                                failures,
                                COVERAGE_TERMINAL_FAILURE_LIMIT
                            );
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &message,
                                Some("coverage_replication_response"),
                            );

                            if disabled {
                                self.logger.log(
                                    crate::logging::LogLevel::Error,
                                    &format!(
                                        "coverage replication disabled for group {} after persistent terminal failures: {}",
                                        group_id, reason
                                    ),
                                    Some("coverage_replication_terminal"),
                                );
                                if let Err(err) = self.save_client_state().await {
                                    self.logger.log(
                                        crate::logging::LogLevel::Warn,
                                        &format!(
                                            "failed to persist coverage replication disablement: {}",
                                            err
                                        ),
                                        Some("coverage_replication_save"),
                                    );
                                }
                                break;
                            }
                        } else {
                            self.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "coverage replication received {} from server: {}; classified as terminal ({}), but no ledger found to update",
                                    status, body, reason
                                ),
                                Some("coverage_replication_response"),
                            );
                        }
                        throttle.register_failure(retry_after).await;
                    }
                }
                continue;
            }

            let ack: CoverageDeltaUploadResponse = match response.json().await {
                Ok(value) => value,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("coverage replication failed to decode response: {}", err),
                        Some("coverage_replication_decode"),
                    );
                    throttle.register_failure(None).await;
                    continue;
                }
            };

            self.update_coverage_ack_sequence(group_id, ack.acknowledged_sequence)
                .await;

            self.request_coverage_compaction(group_id, false).await;

            if let Err(err) = self.save_client_state().await {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    &format!("failed to persist coverage replication progress: {}", err),
                    Some("coverage_replication_save"),
                );
            }
            throttle.register_success().await;
        }

        let mut guard = control.lock().await;
        guard.running = false;
    }

    pub(in super::super) async fn run_parallel_coverage_uploads(
        &self,
        control: Arc<Mutex<CoverageReplicationState>>,
        http_client: reqwest::Client,
        parallel_count: usize,
        throttle: Arc<CoverageUploadThrottle>,
    ) {
        use tokio::sync::Semaphore;

        let semaphore = Arc::new(Semaphore::new(parallel_count));
        let mut tasks = Vec::new();

        loop {
            let (needs_work, group_id, ack_sequence) = {
                let state = self.state.read().await;
                let gid = state.active_group_id;
                let (needs, ack_seq) = gid
                    .and_then(|g| state.coverage_ledgers.get(&g))
                    .map(|ledger| {
                        (
                            ledger.loaded
                                && !ledger.permanently_disabled
                                && ledger.sequence > ledger.ack_sequence,
                            ledger.ack_sequence,
                        )
                    })
                    .unwrap_or((false, 0));
                (needs, gid, ack_seq)
            };

            if !needs_work {
                break;
            }

            let Some(group_id) = group_id else {
                break;
            };

            let session = match self.get_session_info().await {
                Ok(info) => info,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "coverage replication aborted: failed to fetch session info ({})",
                            err
                        ),
                        Some("coverage_replication_session"),
                    );
                    break;
                }
            };

            let Some(device_id) = session.device_id.clone() else {
                self.logger.log(
                    crate::logging::LogLevel::Warn,
                    "coverage replication aborted: session missing device identifier",
                    Some("coverage_replication_session"),
                );
                break;
            };

            let token = session.token.clone();
            let server_base = Self::resolve_server_base_url(session.server_url.clone());
            let url = format!("{}/api/v1/groups/{}/coverage/log", server_base, group_id);

            let batch_size = self.config.coverage_batch_size;
            let deltas = match self
                .coverage_replication_batch(ack_sequence, batch_size)
                .await
            {
                Ok(batch) => batch,
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("coverage replication failed to read deltas: {}", err),
                        Some("coverage_replication_batch"),
                    );
                    throttle.register_failure(None).await;
                    continue;
                }
            };

            if deltas.is_empty() {
                break;
            }

            // Spawn parallel upload task
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client_clone = self.clone();
            let http_client_clone = http_client.clone();
            let url_clone = url.clone();
            let token_clone = token.clone();
            let device_id_clone = device_id.clone();
            let deltas_clone = deltas.clone(); // Clone deltas to move into task
            let group_id_clone = group_id; // Clone group_id to move into task
            let throttle_clone = throttle.clone();

            let task = tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes

                let payload = CoverageDeltaUploadRequest {
                    device_id: device_id_clone.clone(),
                    deltas: deltas_clone
                        .iter()
                        .map(|delta| CoverageDeltaUploadEntry {
                            sequence: delta.sequence,
                            file_id: delta.file_id.clone(),
                            epoch_id: delta.epoch_id,
                            updated_at: delta.updated_at,
                            action: delta.action.clone(),
                        })
                        .collect(),
                };

                throttle_clone.wait_for_slot().await;

                let response = match http_client_clone
                    .post(&url_clone)
                    .header("Authorization", format!("Bearer {}", token_clone))
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) => resp,
                    Err(err) => {
                        client_clone.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!("coverage replication request failed: {}", err),
                            Some("coverage_replication_request"),
                        );
                        throttle_clone.register_failure(None).await;
                        return Err(());
                    }
                };

                let status = response.status();
                let retry_after = if should_backoff(status) {
                    retry_after_delay(response.headers())
                } else {
                    None
                };

                if let Some(retention_err) = client_clone
                    .handle_retention_status(status, response.headers(), "coverage_replication")
                    .await
                {
                    client_clone.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "coverage replication blocked by retention policy: {}",
                            retention_err
                        ),
                        Some("coverage_replication_retention"),
                    );
                    return Err(());
                }

                if status == StatusCode::UNAUTHORIZED {
                    if let Err(err) = client_clone.cleanup_conflicting_auth_state().await {
                        client_clone.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!("failed to clean up auth state after 401: {}", err),
                            Some("coverage_replication_auth"),
                        );
                    }
                    return Err(());
                }

                if !status.is_success() {
                    let body = response
                        .text()
                        .await
                        .unwrap_or_else(|_| "<unavailable>".to_string());
                    let classification =
                        classify_coverage_upload_failure(status, &body, retry_after);

                    match classification {
                        CoverageUploadFailure::Retryable { retry_after } => {
                            client_clone.logger.log(
                                crate::logging::LogLevel::Warn,
                                &format!(
                                    "coverage replication received {} from server: {}",
                                    status, body
                                ),
                                Some("coverage_replication_response"),
                            );
                            throttle_clone.register_failure(retry_after).await;
                        }
                        CoverageUploadFailure::Terminal {
                            reason,
                            retry_after,
                        } => {
                            if let Some((failures, disabled)) = client_clone
                                .record_coverage_terminal_failure(group_id_clone, &reason)
                                .await
                            {
                                let message = format!(
                                    "coverage replication received {} from server: {}; classified as terminal ({}); failure {}/{}",
                                    status,
                                    body,
                                    reason,
                                    failures,
                                    COVERAGE_TERMINAL_FAILURE_LIMIT
                                );
                                client_clone.logger.log(
                                    crate::logging::LogLevel::Warn,
                                    &message,
                                    Some("coverage_replication_response"),
                                );

                                if disabled {
                                    client_clone.logger.log(
                                        crate::logging::LogLevel::Error,
                                        &format!(
                                            "coverage replication disabled for group {} after persistent terminal failures: {}",
                                            group_id_clone, reason
                                        ),
                                        Some("coverage_replication_terminal"),
                                    );
                                    if let Err(err) = client_clone.save_client_state().await {
                                        client_clone.logger.log(
                                            crate::logging::LogLevel::Warn,
                                            &format!(
                                                "failed to persist coverage replication disablement: {}",
                                                err
                                            ),
                                            Some("coverage_replication_save"),
                                        );
                                    }
                                }
                            } else {
                                client_clone.logger.log(
                                    crate::logging::LogLevel::Warn,
                                    &format!(
                                        "coverage replication received {} from server: {}; classified as terminal ({}), but no ledger found to update",
                                        status, body, reason
                                    ),
                                    Some("coverage_replication_response"),
                                );
                            }
                            throttle_clone.register_failure(retry_after).await;
                        }
                    }
                    return Err(());
                }

                let ack: CoverageDeltaUploadResponse = match response.json().await {
                    Ok(value) => value,
                    Err(err) => {
                        client_clone.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!("coverage replication failed to decode response: {}", err),
                            Some("coverage_replication_decode"),
                        );
                        throttle_clone.register_failure(None).await;
                        return Err(());
                    }
                };

                client_clone
                    .update_coverage_ack_sequence(group_id_clone, ack.acknowledged_sequence)
                    .await;

                client_clone
                    .request_coverage_compaction(group_id_clone, false)
                    .await;

                if let Err(err) = client_clone.save_client_state().await {
                    client_clone.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!("failed to persist coverage replication progress: {}", err),
                        Some("coverage_replication_save"),
                    );
                }
                throttle_clone.register_success().await;

                Ok(())
            });

            tasks.push(task);

            // Limit in-flight tasks to avoid memory issues
            if tasks.len() >= parallel_count * 2 {
                if let Some(task) = tasks.pop() {
                    let _ = task.await;
                }
            }
        }

        // Wait for all remaining tasks
        for task in tasks {
            let _ = task.await;
        }

        let mut guard = control.lock().await;
        guard.running = false;
    }

    pub(in super::super) async fn has_active_roots(&self) -> bool {
        let locked_roots = self.coverage_enrollment_roots_snapshot().await;
        self.active_group_roots_map()
            .await
            .map(|(_, _, roots)| roots.keys().any(|root_id| !locked_roots.contains(root_id)))
            .unwrap_or(false)
    }

    pub(in super::super) async fn coverage_root_is_active(&self, root_id: Uuid) -> bool {
        if self.coverage_root_enrollment_in_progress(root_id).await {
            return false;
        }
        self.active_group_roots_map()
            .await
            .map(|(_, _, roots)| roots.contains_key(&root_id))
            .unwrap_or(false)
    }

    pub(in super::super) async fn active_coverage_roots_snapshot(&self) -> Vec<CoverageRoot> {
        let locked_roots = self.coverage_enrollment_roots_snapshot().await;
        self.active_group_roots_map()
            .await
            .map(|(_, _, roots)| {
                roots
                    .values()
                    .filter(|root| !locked_roots.contains(&root.root_id))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(in super::super) async fn coverage_enrollment_roots_snapshot(&self) -> HashSet<Uuid> {
        let state = self.coverage_enrollment.lock().await;
        state.in_progress_roots.clone()
    }

    pub(in super::super) async fn coverage_root_enrollment_in_progress(
        &self,
        root_id: Uuid,
    ) -> bool {
        let state = self.coverage_enrollment.lock().await;
        state.in_progress_roots.contains(&root_id)
    }

    pub(in super::super) async fn path_is_under_enrollment_lock(&self, path: &Path) -> bool {
        let locked_roots = self.coverage_enrollment_roots_snapshot().await;
        if locked_roots.is_empty() {
            return false;
        }

        let state = self.state.read().await;
        state.coverage_roots.iter().any(|(root_id, root)| {
            if !locked_roots.contains(root_id) {
                return false;
            }
            match root.kind {
                CoverageRootKind::SingleFile => root.path == path,
                CoverageRootKind::Folder => path.starts_with(&root.path),
            }
        })
    }

    pub async fn mark_coverage_enrollment_in_progress(&self, root_id: Uuid) {
        let mut state = self.coverage_enrollment.lock().await;
        state.in_progress_roots.insert(root_id);
    }

    pub async fn clear_coverage_enrollment_in_progress(&self, root_id: Uuid) {
        let mut state = self.coverage_enrollment.lock().await;
        state.in_progress_roots.remove(&root_id);
    }

    pub(in super::super) async fn flush_dirty_coverage_roots(
        &self,
        dirty_roots: &mut HashSet<Uuid>,
        root_paths: &HashMap<Uuid, PathBuf>,
        last_scanned: &mut HashMap<Uuid, Instant>,
    ) {
        if self.migration_active().await {
            // Skip rescans during migration to avoid heavy filesystem churn.
            return;
        }
        if dirty_roots.is_empty() {
            return;
        }

        let locked_roots = self.coverage_enrollment_roots_snapshot().await;
        let pending: Vec<Uuid> = dirty_roots
            .drain()
            .filter(|root_id| !locked_roots.contains(root_id))
            .collect();
        for root_id in pending {
            if let Some(last) = last_scanned.get(&root_id) {
                if last.elapsed() < std::time::Duration::from_secs(COVERAGE_WATCHER_MIN_RESCAN_SECS)
                {
                    continue;
                }
            }

            let Some(root_path) = root_paths.get(&root_id).cloned() else {
                continue;
            };

            match self.coverage_rescan(Some(root_path.clone())).await {
                Ok(summary) => {
                    last_scanned.insert(root_id, Instant::now());
                    self.logger.log(
                        crate::logging::LogLevel::Debug,
                        &format!(
                            "Filesystem change refreshed coverage root {} (tracked: {}, orphaned: {})",
                            root_path.display(),
                            summary.files_indexed,
                            summary.orphaned_files
                        ),
                        Some("coverage_watcher_rescan"),
                    );
                }
                Err(err) => {
                    self.logger.log(
                        crate::logging::LogLevel::Warn,
                        &format!(
                            "Filesystem-triggered coverage scan for {} failed: {}",
                            root_path.display(),
                            err
                        ),
                        Some("coverage_watcher_scan_error"),
                    );
                }
            }
        }
    }

    pub(in super::super) async fn handle_new_file_event(
        &self,
        root_id: Uuid,
        root_path: PathBuf,
        candidate_path: PathBuf,
    ) -> Result<(), ClientError> {
        if self.coverage_root_enrollment_in_progress(root_id).await {
            return Ok(());
        }

        let canonical_candidate = match fs::canonicalize(&candidate_path).await {
            Ok(path) => path,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                return Err(ClientError::file_error(
                    ErrorCode::FileAccessDenied,
                    format!(
                        "Failed to canonicalize '{}' for auto-encryption: {}",
                        candidate_path.display(),
                        err
                    ),
                    "coverage_auto_encrypt_canonicalize".to_string(),
                    candidate_path.display().to_string(),
                    None,
                ))
            }
        };

        if !canonical_candidate.starts_with(&root_path) {
            return Ok(());
        }

        if self.is_path_excluded(&canonical_candidate) {
            return Ok(());
        }

        if Self::path_has_encrypted_suffix(&canonical_candidate) {
            return Ok(());
        }

        match self.auto_encrypt_plaintext_file(&canonical_candidate).await {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }
}
