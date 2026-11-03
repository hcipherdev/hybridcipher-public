use super::*;

/// Files on this device still encrypted with a key version other than the one they should be on.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverKeyFiles {
    /// The rotation target while a migration runs, otherwise the current key version.
    pub target_version: u64,
    pub files: usize,
    /// Oldest key version among them, when the file index records it.
    pub oldest_version: Option<u64>,
    /// Folder records (`.hybridcipher_dir.encrypted`: a folder's ID and details) still on another key.
    #[serde(default)]
    pub folders: usize,
}

/// Outcome of moving leftover files to the current key.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverKeyMigration {
    pub migrated: usize,
    pub failed: usize,
    /// What could not be moved and why, so the app can say more than a count.
    #[serde(default)]
    pub failures: Vec<CoverageMigrationFailure>,
    /// Nothing was moved because a rotation is still running; its files move once it finishes.
    #[serde(default)]
    pub rotation_running: bool,
}

/// Whether a file index entry is on a key it should be moved off: wrong-epoch orphans, tracked
/// files on any other key during a migration, and tracked files on an older key otherwise.
/// Files another device encrypted (`[adopt]`: ciphertext without a local record here) follow
/// the tracked rule from their header's key, so a rotation no device "owns" still moves them.
pub(super) fn needs_key_migration(
    entry: &FileIndexEntry,
    target_epoch: u64,
    has_active_migration: bool,
) -> bool {
    match (&entry.state, &entry.orphan_kind) {
        (FileCoverageState::Orphaned, Some(FileOrphanKind::WrongEpoch)) => true,
        (FileCoverageState::Orphaned, Some(FileOrphanKind::MissingMetadata)) => {
            entry.last_epoch > 0 && on_other_key(entry.last_epoch, target_epoch, has_active_migration)
        }
        (FileCoverageState::Tracked, _) if has_active_migration => entry.last_epoch != target_epoch,
        // A device that missed the rotation's migration keeps its files on the older key.
        (FileCoverageState::Tracked, _) => entry.last_epoch > 0 && entry.last_epoch < target_epoch,
        _ => false,
    }
}

/// A read-only summary of this device's keys and indexed files for one group, for support.
/// It names no files or folders, only counts and key versions.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStateReport {
    pub group_id: Option<Uuid>,
    pub current_version: u64,
    /// The rotation this device keeps a record of, as (from, to) versions.
    pub local_rotation: Option<(u64, u64)>,
    /// Key versions of this group that this device can use.
    pub held_versions: Vec<u64>,
    pub folders: Vec<KeyStateFolder>,
    pub leftovers: LeftoverKeyFiles,
}

/// One protected folder in a [`KeyStateReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStateFolder {
    pub root_id: Uuid,
    pub kind: String,
    pub state: String,
    pub tracked: usize,
    pub orphaned: usize,
    pub unmanaged: usize,
    pub keys: CoverageKeyCounts,
    /// Index entries by the key version they record (0: not recorded).
    pub by_version: std::collections::BTreeMap<u64, usize>,
}

/// The server's view of a group's keys, read without changing anything on this device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ServerKeyView {
    /// A rotation has started and not yet finished, failed or been cancelled.
    pub rotation_running: bool,
    /// The key version the server treats as current, when it reports one.
    pub current_version: Option<u64>,
}

/// Whether leftover files may move now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LeftoverMoveDecision {
    /// A rotation is running; its files move once it finishes.
    WaitForRotation,
    /// This device and the server name different current keys (the device lacks the server's,
    /// or kept a cancelled rotation's key). Nothing moves, and the server's word alone never
    /// switches this device's key: that would let a server roll it back to an old one.
    KeysDisagree { server: u64 },
    Proceed,
}

pub(super) fn leftover_move_decision(view: ServerKeyView, local_current: u64) -> LeftoverMoveDecision {
    if view.rotation_running {
        return LeftoverMoveDecision::WaitForRotation;
    }
    match view.current_version {
        Some(server) if server != local_current => LeftoverMoveDecision::KeysDisagree { server },
        _ => LeftoverMoveDecision::Proceed,
    }
}

/// During a migration everything moves to its target; afterwards only older keys move (a newer
/// one means this device is behind the file).
pub(super) fn on_other_key(epoch: u64, target_epoch: u64, has_active_migration: bool) -> bool {
    if has_active_migration {
        epoch != target_epoch
    } else {
        epoch < target_epoch
    }
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Count this device's enrolled files that are not on the key they should be on.
    pub async fn leftover_key_files(&self) -> Result<LeftoverKeyFiles, ClientError> {
        self.ensure_state_loaded().await?;
        let (_, _, roots) = self.active_group_roots_map().await?;
        let (target_epoch, has_active_migration) = {
            let state = self.state.read().await;
            (
                state
                    .migration
                    .as_ref()
                    .map(|m| m.to_epoch)
                    .unwrap_or(state.current_epoch),
                state.migration.is_some(),
            )
        };

        let mut leftovers = LeftoverKeyFiles {
            target_version: target_epoch,
            folders: self
                .directory_sidecars_on_other_key(&roots, None, target_epoch, has_active_migration)
                .await
                .len(),
            ..Default::default()
        };
        for (root_id, root) in roots.iter() {
            for entry in self.list_file_index_entries_for_root(*root_id).await? {
                if !needs_key_migration(&entry, target_epoch, has_active_migration) {
                    continue;
                }
                let path = match root.kind {
                    CoverageRootKind::SingleFile => root.path.clone(),
                    CoverageRootKind::Folder => root.path.join(&entry.relative_path),
                };
                if self.is_path_excluded(&path) {
                    continue;
                }
                leftovers.files += 1;
                if entry.last_epoch > 0 && entry.last_epoch != target_epoch {
                    leftovers.oldest_version = Some(
                        leftovers
                            .oldest_version
                            .map_or(entry.last_epoch, |oldest| oldest.min(entry.last_epoch)),
                    );
                }
            }
        }
        Ok(leftovers)
    }

    /// Move this device's files to the current key once no rotation is running. Rotations finish
    /// as they start, so this only waits out that moment, or an older server that keeps a
    /// rotation running (and could still have it cancelled) until it is cut over.
    pub async fn migrate_leftover_key_files(&self) -> Result<LeftoverKeyMigration, ClientError> {
        self.migrate_leftover_key_files_with(false).await
    }

    /// As [`Self::migrate_leftover_key_files`]; `rescan` first refreshes the file index from disk
    /// so files it has not recorded yet (or recorded on the wrong key) are moved too.
    pub async fn migrate_leftover_key_files_with(
        &self,
        rescan: bool,
    ) -> Result<LeftoverKeyMigration, ClientError> {
        self.migrate_leftover_key_files_with_progress(rescan, |_| {})
            .await
    }

    /// As [`Self::migrate_leftover_key_files_with`], reporting moved and failed counts against
    /// the total while files move, so the app can show a progress bar.
    pub async fn migrate_leftover_key_files_with_progress<F>(
        &self,
        rescan: bool,
        on_progress: F,
    ) -> Result<LeftoverKeyMigration, ClientError>
    where
        F: FnMut(CoverageMigrationProgress) + Send,
    {
        self.ensure_state_loaded().await?;
        let waiting = LeftoverKeyMigration {
            rotation_running: true,
            ..Default::default()
        };
        match self.server_key_view().await? {
            // Not signed in (a local vault): only this device's own record can tell.
            None => {
                if self.is_migrating().await {
                    return Ok(waiting);
                }
            }
            Some(view) => {
                // Members that installed a rotation's key while it rolled out have no local
                // record of the rotation, so the server is asked rather than that record.
                let local_current = self.state.read().await.current_epoch;
                match leftover_move_decision(view, local_current) {
                    LeftoverMoveDecision::WaitForRotation => return Ok(waiting),
                    LeftoverMoveDecision::KeysDisagree { server } => {
                        self.logger.log(
                            crate::logging::LogLevel::Warn,
                            &format!(
                                "Not moving files: this device's current key is v{} but the server's is v{}",
                                local_current, server
                            ),
                            Some("leftover_key_files"),
                        );
                        return Ok(LeftoverKeyMigration::default());
                    }
                    LeftoverMoveDecision::Proceed => {}
                }
                if self.is_migrating().await {
                    // Finished, but the heartbeat that normally clears the record never saw it end.
                    let mut state = self.state.write().await;
                    state.migration = None;
                    state.active_rekey = None;
                    drop(state);
                    self.save_client_state().await?;
                }
            }
        }

        if rescan {
            self.coverage_rescan(None).await?;
        }
        let leftovers = self.leftover_key_files().await?;
        if leftovers.files == 0 && leftovers.folders == 0 {
            return Ok(LeftoverKeyMigration::default());
        }
        let (progress, failures) = self
            .coverage_migrate_orphans_detailed(None, None, true, on_progress)
            .await?;
        Ok(LeftoverKeyMigration {
            migrated: progress.migrated_files,
            failed: progress.failed_files,
            failures,
            rotation_running: false,
        })
    }

    /// What this device knows about the active group's keys and files (see [`KeyStateReport`]).
    pub async fn key_state_report(&self) -> Result<KeyStateReport, ClientError> {
        self.ensure_state_loaded().await?;
        let group_id = self.active_group_id_opt().await;
        let (current_version, local_rotation, held_versions) = {
            let state = self.state.read().await;
            let mut held: Vec<u64> = state
                .epochs
                .keys()
                .copied()
                .filter(|epoch_id| {
                    group_id.is_some_and(|group| {
                        Self::get_epoch_state(&state, group, *epoch_id)
                            .is_some_and(|epoch| epoch.key_source.is_locally_usable())
                    })
                })
                .collect();
            held.sort_unstable();
            (
                state.current_epoch,
                state.migration.as_ref().map(|m| (m.from_epoch, m.to_epoch)),
                held,
            )
        };
        if group_id.is_none() {
            // Nothing to count without a group; still say what this device holds.
            return Ok(KeyStateReport {
                current_version,
                local_rotation,
                ..Default::default()
            });
        }
        let mut folders = Vec::new();
        for stats in self.coverage_root_stats().await? {
            let mut by_version = std::collections::BTreeMap::new();
            for entry in self.list_file_index_entries_for_root(stats.root.root_id).await? {
                *by_version.entry(entry.last_epoch).or_insert(0) += 1;
            }
            folders.push(KeyStateFolder {
                root_id: stats.root.root_id,
                kind: format!("{:?}", stats.root.kind).to_lowercase(),
                state: format!("{:?}", stats.root.state).to_lowercase(),
                tracked: stats.tracked_files,
                orphaned: stats.orphaned_files,
                unmanaged: stats.unmanaged_files,
                keys: stats.keys,
                by_version,
            });
        }
        Ok(KeyStateReport {
            group_id,
            current_version,
            local_rotation,
            held_versions,
            folders,
            leftovers: self.leftover_key_files().await?,
        })
    }

    /// Ask the server whether the active group's rotation is still running and which key is
    /// current, without the side effects of a rekey status refresh (which would adopt a
    /// cancelled rotation's key). `None` when this device has no account session.
    async fn server_key_view(&self) -> Result<Option<ServerKeyView>, ClientError> {
        let Ok(token) = self.get_auth_token().await else {
            return Ok(None);
        };
        let group_id = self.active_group_required().await?;
        let base = self.active_server_base_url().await;
        let request_failed = |error: String| {
            ClientError::network_error(
                ErrorCode::NetworkConnection,
                error,
                "server_key_view".to_string(),
                0,
                "request_failed".to_string(),
            )
        };

        let response = reqwest::Client::new()
            .get(format!("{}/api/v1/groups/{}/rekey/status", base, group_id))
            .bearer_auth(&token)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|error| request_failed(format!("Failed to check the rotation: {error}")))?;
        let rotation_running = match response.status() {
            StatusCode::NOT_FOUND => false,
            status if status.is_success() => {
                let body: serde_json::Value = response.json().await.map_err(|error| {
                    request_failed(format!("Unreadable rotation status: {error}"))
                })?;
                let rotation: RekeyStatus = serde_json::from_value(body["status"].clone())
                    .map_err(|error| request_failed(format!("Unknown rotation status: {error}")))?;
                !matches!(
                    rotation,
                    RekeyStatus::Completed | RekeyStatus::Failed | RekeyStatus::Cancelled
                )
            }
            status => {
                return Err(request_failed(format!(
                    "Rotation status unavailable ({status})"
                )))
            }
        };

        let current_version = self
            .fetch_group_list(&token)
            .await?
            .into_iter()
            .find(|group| group.id == group_id)
            .and_then(|group| group.current_epoch)
            .and_then(|epoch| Uuid::parse_str(&epoch).ok())
            .and_then(|epoch| EpochIdMapper::uuid_to_u64(epoch, group_id.as_bytes()));
        Ok(Some(ServerKeyView {
            rotation_running,
            current_version,
        }))
    }

    /// Folder records (`.hybridcipher_dir.encrypted`) under this group's active protected
    /// folders whose key should move to `target_epoch`, with their current key. The file index
    /// leaves these records out, so they are found on disk; `only_root` limits the search.
    pub(super) async fn directory_sidecars_on_other_key(
        &self,
        roots: &HashMap<Uuid, CoverageRoot>,
        only_root: Option<&Path>,
        target_epoch: u64,
        has_active_migration: bool,
    ) -> Vec<(PathBuf, u64)> {
        let Some(group_id) = self.active_group_id_opt().await else {
            return Vec::new();
        };
        let folders: Vec<PathBuf> = roots
            .values()
            .filter(|root| root.state == CoverageRootState::Active)
            .filter(|root| root.kind == CoverageRootKind::Folder)
            .filter(|root| only_root.map_or(true, |only| root.path == only))
            .map(|root| root.path.clone())
            .collect();
        let sidecars = tokio::task::spawn_blocking(move || {
            folders
                .iter()
                .flat_map(|folder| {
                    walkdir::WalkDir::new(folder)
                        .follow_links(false)
                        .into_iter()
                        .filter_map(Result::ok)
                        .filter(|entry| entry.file_type().is_file())
                        .filter(|entry| ciphertext::classify(entry.path()) == CiphertextKind::FolderRecord)
                        .map(|entry| entry.into_path())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .await
        .unwrap_or_default();
        sidecars
            .into_iter()
            .filter(|path| !self.is_path_excluded(path))
            .filter_map(|path| {
                let header = Self::parse_encrypted_file_metadata(&path)?;
                let same_group = header.group_id.map_or(true, |group| group == group_id);
                (same_group
                    && header.epoch_id > 0
                    && on_other_key(header.epoch_id, target_epoch, has_active_migration))
                .then_some((path, header.epoch_id))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "../../../tests/rekey/test_leftover_key_files.rs"]
mod leftover_key_files_tests;
