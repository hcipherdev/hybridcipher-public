use super::*;

impl<S: Storage, N: Network> Client<S, N> {
    /// The active root that a folder at `path` was protected as before it was
    /// renamed or moved: its marker names a root whose saved path is gone.
    pub async fn coverage_moved_root_for_path<P>(
        &self,
        path: P,
    ) -> Result<Option<CoverageRoot>, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.ensure_state_loaded().await?;
        let group_id = self.active_group_required().await?;
        let canonical = canonicalize_existing_path(path.as_ref().to_path_buf()).await?;
        if !canonical.is_dir() {
            return Ok(None);
        }

        let markers = folder_markers_in_dir(&canonical, group_id);
        let state = self.state.read().await;
        Ok(markers.into_iter().find_map(|marker| {
            state
                .coverage_roots
                .get(&marker.root_id)
                .filter(|root| {
                    root.state == CoverageRootState::Active
                        && root.group_id == Some(group_id)
                        && root.path != canonical
                        && !root.path.exists()
                })
                .cloned()
        }))
    }

    /// Point an active root whose folder was renamed or moved at its new
    /// location. File records move with it, so nothing needs re-protecting.
    pub async fn coverage_relocate_root<P>(
        &self,
        root_id: Uuid,
        new_path: P,
    ) -> Result<CoverageRoot, ClientError>
    where
        P: AsRef<Path> + Send,
    {
        self.require_local_write().await?;
        self.ensure_state_loaded().await?;
        let group_id = self.active_group_required().await?;

        let root = {
            let state = self.state.read().await;
            state.coverage_roots.get(&root_id).cloned()
        }
        .filter(|root| root.state == CoverageRootState::Active && root.group_id == Some(group_id))
        .ok_or_else(|| {
            ClientError::InvalidInput(
                "This protected folder is not in the selected workspace".to_string(),
            )
        })?;

        let canonical = canonicalize_existing_path(new_path.as_ref().to_path_buf()).await?;
        let display_path = canonical.display().to_string();
        if canonical == root.path {
            return Ok(root);
        }
        if root.path.exists() {
            return Err(ClientError::InvalidInput(format!(
                "'{}' is still at its saved location '{}'. '{}' may be a copy of it.",
                root_display_name(&root),
                root.path.display(),
                display_path
            )));
        }
        let kind_matches = match root.kind {
            CoverageRootKind::Folder => canonical.is_dir(),
            CoverageRootKind::SingleFile => canonical.is_file(),
        };
        if !kind_matches || self.is_path_excluded(&canonical) {
            return Err(ClientError::InvalidInput(format!(
                "'{}' cannot replace protected {} '{}'",
                display_path,
                match root.kind {
                    CoverageRootKind::Folder => "folder",
                    CoverageRootKind::SingleFile => "file",
                },
                root_display_name(&root)
            )));
        }

        let marker_dir = match root.kind {
            CoverageRootKind::Folder => Some(canonical.as_path()),
            CoverageRootKind::SingleFile => canonical.parent(),
        };
        if marker_dir
            .and_then(|dir| find_marker_for_root_id(dir, root_id, group_id))
            .is_none()
        {
            return Err(ClientError::InvalidInput(format!(
                "'{}' doesn't look like '{}'. Choose the folder that was protected.",
                display_path,
                root_display_name(&root)
            )));
        }

        self.assert_no_cross_group_conflict(&canonical, group_id)
            .await?;
        {
            let state = self.state.read().await;
            if let Some(other) = state.coverage_roots.values().find(|other| {
                other.root_id != root_id
                    && other.state == CoverageRootState::Active
                    && paths_overlap(&other.path, &canonical)
            }) {
                return Err(ClientError::InvalidInput(format!(
                    "'{}' overlaps protected folder '{}'",
                    display_path,
                    other.path.display()
                )));
            }
        }

        // Copy file records to the new paths before switching the root, so a
        // crash leaves either the old root intact or the new one complete.
        let entries = self.list_file_index_entries_for_root(root_id).await?;
        let mut stale_keys = Vec::new();
        for entry in &entries {
            let old_path = file_path_in_root(&root.path, root.kind, &entry.relative_path);
            let new_path = file_path_in_root(&canonical, root.kind, &entry.relative_path);
            for (old_key, new_key) in Self::metadata_key_pairs(&old_path, &new_path) {
                let Some(mut metadata) = self
                    .storage
                    .load_file_metadata(&old_key)
                    .await
                    .map_err(ClientError::from)?
                else {
                    continue;
                };
                metadata.file_path = new_key.clone();
                self.storage
                    .store_file_metadata(&new_key, &metadata)
                    .await
                    .map_err(ClientError::from)?;
                stale_keys.push(old_key);
            }
        }

        let relocated = {
            let mut state = self.state.write().await;
            let entry = state
                .coverage_roots
                .get_mut(&root_id)
                .expect("coverage root should exist");
            entry.path = canonical.clone();
            entry.updated_at = Utc::now();
            entry.clone()
        };
        self.remove_root_registry_entry(&root.path).await?;
        self.upsert_root_registry_entry(&canonical, group_id, root_id)
            .await?;
        self.save_client_state().await?;
        self.logger.log(
            crate::logging::LogLevel::Info,
            &format!(
                "Relocated coverage root {} from {} to {}",
                root_id,
                root.path.display(),
                canonical.display()
            ),
            Some("coverage_relocate"),
        );

        for key in stale_keys {
            if let Err(err) = self.storage.delete_file(&key).await {
                log::warn!("Failed to remove old file record {}: {}", key, err);
            }
        }
        if let Err(err) = write_marker_for_root(&relocated, group_id).await {
            log::warn!(
                "Failed to update coverage marker for {}: {}",
                canonical.display(),
                err
            );
        }
        self.coverage_watcher.lock().await.wake.notify_one();
        self.coverage_rescan(Some(canonical)).await?;
        Ok(relocated)
    }

    /// Records may be stored under the plain or the normalized path, as unenroll
    /// assumes; move whichever exist.
    fn metadata_key_pairs(old_path: &Path, new_path: &Path) -> Vec<(String, String)> {
        let old_key = old_path.to_string_lossy().to_string();
        let new_key = new_path.to_string_lossy().to_string();
        let old_normalized = Self::normalize_storage_path(&old_key);
        let mut pairs = vec![(old_key.clone(), new_key.clone())];
        if old_normalized != old_key {
            pairs.push((old_normalized, Self::normalize_storage_path(&new_key)));
        }
        pairs
    }
}

fn root_display_name(root: &CoverageRoot) -> String {
    root.path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| root.path.display().to_string())
}

fn file_path_in_root(root_path: &Path, kind: CoverageRootKind, relative_path: &str) -> PathBuf {
    match kind {
        CoverageRootKind::SingleFile => root_path.to_path_buf(),
        CoverageRootKind::Folder => root_path.join(relative_path),
    }
}
