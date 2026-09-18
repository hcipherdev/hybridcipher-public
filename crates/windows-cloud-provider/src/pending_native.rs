// Included inside the Windows platform module so recovery uses the same locks,
// identities and placeholder bookkeeping as callbacks and ingestion.
impl CallbackContext {
    fn retain_failed_write(
        &self,
        path: &Path,
        relative: &str,
        identity: Option<FileIdentityV1>,
        expected: &ExpectedProviderVersion,
        error: CloudProviderError,
    ) -> Result<()> {
        let mut journal = self.read_journal()?;
        let mut record = CloudMutationRecord::new(
            CloudMutationKind::Writeback,
            self.registration.root_id,
            relative,
            identity,
        );
        record.plaintext_path = Some(path.to_owned());
        record.expected_version = match expected {
            ExpectedProviderVersion::Exact(version) => Some(version.clone()),
            _ => None,
        };
        let existing = journal
            .records
            .iter()
            .find(|r| {
                r.kind == record.kind
                    && r.relative_path == record.relative_path
                    && r.identity == record.identity
                    && r.expected_version == record.expected_version
                    && r.plaintext_path == record.plaintext_path
            })
            .map(|r| r.id);
        let id = if let Some(id) = existing {
            id
        } else {
            journal.next_sequence = journal.next_sequence.saturating_add(1);
            record.sequence = journal.next_sequence;
            let id = record.id;
            journal.records.push(record);
            self.write_journal(&journal)?;
            id
        };
        self.finish_pending_attempt(id, Err(error))
    }
    async fn replay_pending_locked(&self, force: bool) -> Result<()> {
        let records = self.read_journal()?.records;
        for record in records {
            if !force && !super::pending::ready(&record) {
                continue;
            }
            let result = if record.kind == CloudMutationKind::Rename {
                self.execute_pending_rename(&record, false).await
            } else {
                self.execute_pending_content(&record).await
            };
            self.finish_pending_attempt(record.id, result)?;
        }
        Ok(())
    }

    fn finish_pending_attempt(&self, id: Uuid, result: Result<()>) -> Result<()> {
        let mut journal = self.read_journal()?;
        match result {
            Ok(()) => journal.records.retain(|r| r.id != id),
            Err(error) => {
                if let Some(record) = journal.records.iter_mut().find(|r| r.id == id) {
                    super::pending::failed(record, &error);
                }
            }
        }
        journal.updated_at = Utc::now();
        self.write_journal(&journal)
    }

    async fn execute_pending_content(&self, record: &CloudMutationRecord) -> Result<()> {
        let expected = super::replay_expected_version(record, self.registration.root_id)?;
        super::validate_replay_plaintext_paths(record, &self.registration.sync_root_path)?;
        match record.kind {
            CloudMutationKind::Writeback => {
                let path = record.plaintext_path.as_ref().ok_or_else(|| {
                    super::unsafe_replay_error(record, "Writeback source is missing")
                })?;
                if fs::symlink_metadata(path)?.file_attributes() & FILE_ATTRIBUTE_OFFLINE.0 != 0 {
                    return Err(super::unsafe_replay_error(
                        record,
                        "Local edits are not fully available; open the file before retrying",
                    ));
                }
                let entry = self
                    .bridge
                    .writeback_file_checked(
                        self.registration.root_id,
                        &self.registration.encrypted_root,
                        &record.relative_path,
                        path,
                        record.identity.as_ref(),
                        &expected,
                    )
                    .await?;
                let identity = self.upsert_committed_entry(entry.clone())?;
                apply_local_placeholder_commit(
                    &self.registration.sync_root_path,
                    path,
                    &entry,
                    &identity,
                    None,
                )?;
            }
            CloudMutationKind::Delete => {
                let identity = record.identity.as_ref().ok_or_else(|| {
                    super::unsafe_replay_error(record, "Delete identity is missing")
                })?;
                self.bridge
                    .delete_entry_checked(
                        self.registration.root_id,
                        &self.registration.encrypted_root,
                        identity,
                        &expected,
                    )
                    .await?;
            }
            CloudMutationKind::Rename => unreachable!(),
        }
        Ok(())
    }

    async fn resolve_pending_locked(
        &self,
        id: Uuid,
        action: super::PendingOperationResolution,
    ) -> Result<()> {
        let journal = self.read_journal()?;
        let record = journal
            .records
            .iter()
            .find(|r| r.id == id)
            .cloned()
            .ok_or_else(|| {
                CloudProviderError::Callback(
                    "This operation has already been resolved. Refresh folder details.".into(),
                )
            })?;
        if record.kind != CloudMutationKind::Rename {
            return Err(super::unsafe_replay_error(
                &record,
                "Only rename operations support this action",
            ));
        }
        let result = match action {
            super::PendingOperationResolution::RetryRename => {
                self.execute_pending_rename(&record, true).await
            }
            super::PendingOperationResolution::KeepOriginalName => {
                if journal
                    .records
                    .iter()
                    .any(|other| other.id != id && super::pending::touches(other, &record))
                {
                    return Err(super::unsafe_replay_error(
                        &record,
                        "Other pending work depends on this rename; resolve that work first",
                    ));
                }
                self.validate_original_name(&record).await
            }
        };
        let error = result.as_ref().err().map(ToString::to_string);
        self.finish_pending_attempt(id, result)?;
        if let Some(error) = error {
            return Err(CloudProviderError::Callback(error));
        }
        Ok(())
    }

    async fn validate_original_name(&self, record: &CloudMutationRecord) -> Result<()> {
        super::replay_expected_version(record, self.registration.root_id)?;
        let target = record
            .target_relative_path
            .as_deref()
            .ok_or_else(|| super::unsafe_replay_error(record, "Rename destination is missing"))?;
        let original_path = self.registration.sync_root_path.join(&record.relative_path);
        if !original_path.exists() || self.registration.sync_root_path.join(target).exists() {
            return Err(super::unsafe_replay_error(record, "Keep original name requires the original file to be present and the destination to be absent"));
        }
        let identity = self
            .known_local_placeholder_identity(&original_path)?
            .ok_or_else(|| {
                super::unsafe_replay_error(record, "Original file identity cannot be verified")
            })?;
        let state = self.state_store.load()?;
        if state
            .items
            .get(&identity.object_id)
            .is_none_or(|item| item.dirty)
        {
            return Err(super::unsafe_replay_error(
                record,
                "Original file has unresolved local work",
            ));
        }
        let entries = self
            .bridge
            .inventory(self.registration.root_id, &self.registration.encrypted_root)
            .await?;
        let source = entries
            .iter()
            .find(|e| e.relative_path == record.relative_path)
            .ok_or_else(|| super::unsafe_replay_error(record, "Encrypted original is missing"))?;
        super::pending::validate_source(record, source)?;
        if self.entry_for_identity(&identity)?.identity.file_id != source.identity.file_id
            || entries.iter().any(|e| e.relative_path == target)
        {
            return Err(super::unsafe_replay_error(
                record,
                "Original or destination identity changed",
            ));
        }
        // This action changes only the journal. It never renames, deletes or overwrites content.
        Ok(())
    }

    async fn execute_pending_rename(
        &self,
        record: &CloudMutationRecord,
        explicit_retry: bool,
    ) -> Result<()> {
        let expected = super::replay_expected_version(record, self.registration.root_id)?;
        let target = record
            .target_relative_path
            .as_deref()
            .ok_or_else(|| super::unsafe_replay_error(record, "Rename destination is missing"))?;
        let entries = self
            .bridge
            .inventory(self.registration.root_id, &self.registration.encrypted_root)
            .await?;
        let source = entries
            .iter()
            .find(|e| e.relative_path == record.relative_path);
        let destination = entries.iter().find(|e| e.relative_path == target);
        let source_path = self.registration.sync_root_path.join(&record.relative_path);
        let target_path = self.registration.sync_root_path.join(target);
        if let Some(destination) = destination {
            let same_identity = record
                .identity
                .as_ref()
                .and_then(|i| i.file_id.as_ref())
                .is_some_and(|id| destination.identity.file_id.as_ref() == Some(id));
            let version = record
                .committed_version
                .as_ref()
                .or(record.expected_version.as_ref());
            if source.is_none()
                && same_identity
                && destination.content_version().as_ref() == version
            {
                if !target_path.exists() {
                    return Err(super::unsafe_replay_error(record, "Encrypted rename is committed but the local destination is missing; preserve pending bookkeeping"));
                }
                let identity = self
                    .known_local_placeholder_identity(&target_path)?
                    .ok_or_else(|| {
                        super::unsafe_replay_error(
                            record,
                            "Local destination identity cannot be verified",
                        )
                    })?;
                if self.entry_for_identity(&identity)?.identity.file_id
                    != destination.identity.file_id
                {
                    return Err(super::unsafe_replay_error(
                        record,
                        "Local destination belongs to another file",
                    ));
                }
                self.remove_identity(&identity)?;
                let committed_identity = self.upsert_committed_entry(destination.clone())?;
                apply_local_placeholder_commit(
                    &self.registration.sync_root_path,
                    &target_path,
                    destination,
                    &committed_identity,
                    None,
                )?;
                return Ok(());
            }
            return Err(super::unsafe_replay_error(
                record,
                "Destination is occupied or has a conflicting content version",
            ));
        }
        let source = source.ok_or_else(|| {
            super::unsafe_replay_error(
                record,
                "Neither a verified original nor a committed destination is available",
            )
        })?;
        super::pending::validate_source(record, source)?;
        let case_only = record.relative_path.eq_ignore_ascii_case(target);
        if !target_path.exists() || (case_only && explicit_retry) {
            if !source_path.exists() {
                return Err(super::unsafe_replay_error(
                    record,
                    "Both local rename paths are missing",
                ));
            }
            if !explicit_retry {
                return Err(super::unsafe_replay_error(
                    record,
                    "Only the original file exists. Choose Retry rename or Keep original name.",
                ));
            }
            let identity = self
                .known_local_placeholder_identity(&source_path)?
                .ok_or_else(|| {
                    super::unsafe_replay_error(record, "Original file identity cannot be verified")
                })?;
            if self.entry_for_identity(&identity)?.identity.file_id != source.identity.file_id {
                return Err(super::unsafe_replay_error(
                    record,
                    "Original file identity changed",
                ));
            }
            super::validate_replay_plaintext_path(
                record,
                &self.registration.sync_root_path,
                &source_path,
                &record.relative_path,
            )?;
            if target_path.exists() && !case_only {
                return Err(super::unsafe_replay_error(
                    record,
                    "Destination was created by another writer",
                ));
            }
            self.suppress(&record.relative_path)?;
            self.suppress(target)?;
            let moved = fs::rename(&source_path, &target_path);
            self.unsuppress(&record.relative_path)?;
            self.unsuppress(target)?;
            moved?;
        } else if source_path.exists() && !case_only {
            return Err(super::unsafe_replay_error(
                record,
                "Both local paths exist; preserve both files and resolve the conflict",
            ));
        }

        super::validate_replay_plaintext_path(
            record,
            &self.registration.sync_root_path,
            &target_path,
            target,
        )?;
        let identity = self
            .known_local_placeholder_identity(&target_path)?
            .ok_or_else(|| {
                super::unsafe_replay_error(record, "Renamed file identity cannot be verified")
            })?;
        if self.entry_for_identity(&identity)?.identity.file_id != source.identity.file_id {
            return Err(super::unsafe_replay_error(
                record,
                "Renamed file belongs to another object",
            ));
        }
        let mut temporary = None;
        let mut guard = None;
        let plaintext = if source.kind == ProviderEntryKind::File {
            let locked = CloudFileOplock::acquire_exclusive(&target_path)?;
            let residency = locked.data_residency()?;
            let offline = fs::symlink_metadata(&target_path)?.file_attributes()
                & FILE_ATTRIBUTE_OFFLINE.0
                != 0;
            if offline {
                let state = self.state_store.load()?;
                if residency.modified_data_size != 0
                    || state
                        .items
                        .get(&identity.object_id)
                        .is_none_or(|item| item.dirty)
                    || fs::metadata(&target_path)?.len()
                        != source
                            .metadata
                            .as_ref()
                            .map(|m| m.content_size)
                            .unwrap_or(0)
                {
                    return Err(super::unsafe_replay_error(record, "Offline file has dirty or uncertain local content; open and resolve that content before retrying"));
                }
                // Never read our own offline placeholder: use the authorized decoder.
                let path = self
                    .runtime_paths
                    .cache_dir
                    .join(format!(".rename-{}.plain", Uuid::new_v4()));
                temporary = Some(PendingPlaintext(path.clone()));
                self.bridge.hydrate_file_to_path(source, &path).await?;
                guard = Some(locked);
                Some(path)
            } else {
                let path = self
                    .runtime_paths
                    .cache_dir
                    .join(format!(".rename-{}.plain", Uuid::new_v4()));
                temporary = Some(PendingPlaintext(path.clone()));
                snapshot_plain_file_to_path(&target_path, &path)?;
                guard = Some(locked);
                Some(path)
            }
        } else {
            None
        };
        let result = self
            .bridge
            .rename_entry_checked(
                self.registration.root_id,
                &self.registration.encrypted_root,
                &source.identity,
                target,
                plaintext.as_deref(),
                &expected,
            )
            .await?;
        drop(guard);
        drop(temporary);
        if let Some(entry) = result {
            // Persist the committed version before placeholder bookkeeping. Recovery can
            // complete this phase without re-encrypting or guessing from the filename.
            let mut journal = self.read_journal()?;
            if let Some(current) = journal.records.iter_mut().find(|r| r.id == record.id) {
                current.committed_version = entry.content_version();
            }
            self.write_journal(&journal)?;
            self.remove_identity(&identity)?;
            let committed_identity = self.upsert_committed_entry(entry.clone())?;
            apply_local_placeholder_commit(
                &self.registration.sync_root_path,
                &target_path,
                &entry,
                &committed_identity,
                None,
            )?;
        } else {
            self.state_store
                .transaction(|state| state.migrate_directory_path(&record.relative_path, target))?;
            CloudFileOplock::acquire_exclusive(&target_path)?.mark_in_sync()?;
        }
        Ok(())
    }
}

struct PendingPlaintext(PathBuf);
impl Drop for PendingPlaintext {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
