use super::*;
use hybridcipher_provider_core::normalize_relative_path;

// Dropbox can temporarily deny replacement while its existing Cloud Files target
// is out of sync. Keep retries bounded so a persistent permission error surfaces.
const MAX_WRITEBACK_ACCESS_DENIED_ATTEMPTS: u32 = 8;
const LEGACY_WRITEBACK_ACCESS_DENIED: &str =
    "provider-core error: I/O error: Access is denied. (os error 5)";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingOperationState {
    #[default]
    Ready,
    Retryable,
    NeedsAttention,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingOperationResolution {
    RetryRename,
    KeepOriginalName,
    KeepRenamedFile,
}

/// A pending rename owns both namespace locations, including directory descendants.
/// An editor replacement must not be imported as an unrelated new file at its target.
pub(super) fn reserves_path(records: &[CloudMutationRecord], path: &str) -> bool {
    records.iter().any(|record| {
        record.kind == CloudMutationKind::Rename
            && [
                &record.relative_path,
                record
                    .target_relative_path
                    .as_ref()
                    .unwrap_or(&record.relative_path),
            ]
            .iter()
            .any(|reserved| paths_overlap(reserved, path))
    })
}

fn paths_overlap(a: &str, b: &str) -> bool {
    let a = normalize_relative_path(a.to_owned()).to_lowercase();
    let b = normalize_relative_path(b.to_owned()).to_lowercase();
    a == b || a.starts_with(&(b.clone() + "/")) || b.starts_with(&(a + "/"))
}

pub(super) fn touches(a: &CloudMutationRecord, b: &CloudMutationRecord) -> bool {
    if a.root_id != b.root_id {
        return false;
    }
    if a.identity
        .as_ref()
        .and_then(|id| id.file_id.as_ref())
        .zip(b.identity.as_ref().and_then(|id| id.file_id.as_ref()))
        .is_some_and(|(a, b)| a == b)
    {
        return true;
    }
    [
        &a.relative_path,
        a.target_relative_path.as_ref().unwrap_or(&a.relative_path),
    ]
    .iter()
    .any(|a| {
        [
            &b.relative_path,
            b.target_relative_path.as_ref().unwrap_or(&b.relative_path),
        ]
        .iter()
        .any(|b| {
            let a = a.to_lowercase();
            let b = b.to_lowercase();
            a == b || a.starts_with(&(b.clone() + "/")) || b.starts_with(&(a + "/"))
        })
    })
}

pub(super) fn ready(record: &CloudMutationRecord) -> bool {
    if record
        .observed_local_state
        .as_ref()
        .is_some_and(|previous| *previous != local_revision(record))
    {
        return true;
    }
    (record.state != PendingOperationState::NeedsAttention
        || (record.kind == CloudMutationKind::Writeback
            && record.attempts < MAX_WRITEBACK_ACCESS_DENIED_ATTEMPTS
            && record.last_error.as_deref() == Some(LEGACY_WRITEBACK_ACCESS_DENIED)))
        && record.retry_after.is_none_or(|time| time <= Utc::now())
}

pub(super) fn validate_source(record: &CloudMutationRecord, entry: &ProviderEntry) -> Result<()> {
    let identity_matches = record.identity.as_ref().is_some_and(|id| {
        id.root_id == entry.root_id
            && id.kind == entry.kind
            && id.file_id.is_some()
            && id.file_id == entry.identity.file_id
    });
    if !identity_matches
        || (entry.kind == ProviderEntryKind::File
            && (record.expected_version.is_none()
                || record.expected_version != entry.content_version()))
    {
        return Err(unsafe_replay_error(record, "Original identity or content version changed; preserve local changes and resolve the conflict"));
    }
    Ok(())
}

pub(super) fn matching_operation(
    records: &[CloudMutationRecord],
    candidate: &CloudMutationRecord,
) -> Option<usize> {
    // An intervening operation touching either path or object is a barrier.
    for (index, previous) in records.iter().enumerate().rev() {
        if touches(previous, candidate) {
            return same_pending_rename(previous, candidate).then_some(index);
        }
    }
    None
}

pub(super) fn compact(records: &mut Vec<CloudMutationRecord>) -> bool {
    let original_len = records.len();
    records.sort_by_key(|r| r.sequence);
    let mut result: Vec<CloudMutationRecord> = Vec::with_capacity(original_len);
    for record in std::mem::take(records) {
        if let Some(index) = matching_operation(&result, &record) {
            let first = &mut result[index];
            first.attempts = first.attempts.saturating_add(record.attempts);
            first.merged_records = first
                .merged_records
                .saturating_add(record.merged_records)
                .saturating_add(1);
            if record.updated_at >= first.updated_at {
                if record.last_error.is_some() {
                    first.last_error = record.last_error;
                    first.error_code = record.error_code;
                }
                first.updated_at = record.updated_at;
                first.state = record.state;
                first.retry_after = record.retry_after;
                first.observed_local_state = record.observed_local_state;
                if record.committed_version.is_some() {
                    first.committed_version = record.committed_version;
                }
            }
        } else {
            result.push(record);
        }
    }
    *records = result;
    original_len != records.len()
}

pub(super) fn failed(record: &mut CloudMutationRecord, error: &CloudProviderError) {
    record.attempts = record.attempts.saturating_add(1);
    record.updated_at = Utc::now();
    record.last_error = Some(error.to_string());
    use hybridcipher_provider_core::ProviderFileErrorCode;
    record.error_code = match error {
        CloudProviderError::ProviderCore(e) if e.is_legacy_consent_required() => {
            Some(ProviderFileErrorCode::LegacyConsentRequired)
        }
        CloudProviderError::ProviderCore(e) if e.is_integrity_failure() => {
            Some(ProviderFileErrorCode::IntegrityFailure)
        }
        _ => None,
    };
    record.observed_local_state = Some(local_revision(record));
    let transient = match error {
        CloudProviderError::Io(e) => {
            matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
            ) || matches!(e.raw_os_error(), Some(32 | 33 | 112))
        }
        #[cfg(windows)]
        CloudProviderError::Windows(error) => {
            matches!(
                error.code().0 as u32,
                0x8007_0020 | 0x8007_0021 | 0x8007_0070
            )
        }
        CloudProviderError::ProviderCore(ProviderCoreError::Io(e)) => {
            matches!(e.raw_os_error(), Some(32 | 33 | 112))
                || (record.kind == CloudMutationKind::Writeback
                    && e.raw_os_error() == Some(5)
                    && record.attempts < MAX_WRITEBACK_ACCESS_DENIED_ATTEMPTS)
        }
        _ => false,
    };
    record.state = if transient {
        PendingOperationState::Retryable
    } else {
        PendingOperationState::NeedsAttention
    };
    record.retry_after = transient
        .then(|| Utc::now() + chrono::Duration::seconds((1i64 << record.attempts.min(8)).min(300)));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rename_reserves_both_paths_and_descendants_but_not_similar_names() {
        let record = rename(Uuid::new_v4(), 1);
        assert!(reserves_path(
            &[record.clone()],
            "API_keys/GITHUB BACKUP CODES.md"
        ));
        assert!(reserves_path(
            &[record.clone()],
            "API_keys\\github backup-codes.md"
        ));
        assert!(!reserves_path(
            &[record.clone()],
            "API_keys/github backup-codes.md.other"
        ));
        assert!(!reserves_path(&[record.clone()], "unrelated.md"));
        let mut directory = record;
        directory.relative_path = "old-dir".into();
        directory.target_relative_path = Some("new-dir".into());
        assert!(reserves_path(
            &[directory.clone()],
            "new-dir/editor-save.md"
        ));
        directory.kind = CloudMutationKind::Writeback;
        assert!(!reserves_path(&[directory], "new-dir/editor-save.md"));
    }
    #[test]
    fn deterministic_errors_wait_and_transient_attempts_back_off_on_the_same_id() {
        let mut record = rename(Uuid::new_v4(), 1);
        let id = record.id;
        failed(
            &mut record,
            &CloudProviderError::ProviderCore(ProviderCoreError::Crypto(
                hybridcipher_mount_sync::MountSyncError::LegacyCompatibilityRequired,
            )),
        );
        assert_eq!(record.state, PendingOperationState::NeedsAttention);
        assert_eq!(
            record.error_code,
            Some(hybridcipher_provider_core::ProviderFileErrorCode::LegacyConsentRequired)
        );
        assert!(!ready(&record));
        for _ in 0..20 {
            failed(
                &mut record,
                &CloudProviderError::Io(std::io::Error::from_raw_os_error(32)),
            );
        }
        #[cfg(windows)]
        failed(
            &mut record,
            &CloudProviderError::Windows(windows::core::Error::from_hresult(
                windows::core::HRESULT(0x8007_0020u32 as i32),
            )),
        );
        assert_eq!(record.id, id);
        assert_eq!(record.state, PendingOperationState::Retryable);
        assert!(record.retry_after.unwrap() <= Utc::now() + chrono::Duration::seconds(300));
        assert!(!ready(&record));
        let mut duplicate = record.clone();
        duplicate.id = Uuid::new_v4();
        duplicate.sequence = 2;
        duplicate.target_plaintext_path = Some(PathBuf::from("C:/different-binding.md"));
        let mut distinct_bindings = vec![record, duplicate];
        assert!(!compact(&mut distinct_bindings));
    }

    #[test]
    fn writeback_access_denied_retries_with_a_limit_and_recovers_existing_records() {
        let mut record = rename(Uuid::new_v4(), 1);
        record.kind = CloudMutationKind::Writeback;
        record.state = PendingOperationState::NeedsAttention;
        record.last_error = Some(LEGACY_WRITEBACK_ACCESS_DENIED.into());
        assert!(ready(&record));

        let error = CloudProviderError::ProviderCore(ProviderCoreError::Io(
            std::io::Error::from_raw_os_error(5),
        ));
        assert_eq!(error.to_string(), LEGACY_WRITEBACK_ACCESS_DENIED);
        while record.attempts < MAX_WRITEBACK_ACCESS_DENIED_ATTEMPTS - 1 {
            failed(&mut record, &error);
            assert_eq!(record.state, PendingOperationState::Retryable);
            assert!(record.retry_after.is_some());
        }
        failed(&mut record, &error);
        assert_eq!(record.state, PendingOperationState::NeedsAttention);
        assert_eq!(record.retry_after, None);
        assert!(!ready(&record));

        let mut rename_record = rename(Uuid::new_v4(), 1);
        failed(&mut rename_record, &error);
        assert_eq!(rename_record.state, PendingOperationState::NeedsAttention);
        assert!(!ready(&rename_record));
    }
    fn rename(root: Uuid, sequence: u64) -> CloudMutationRecord {
        let mut r = CloudMutationRecord::new(
            CloudMutationKind::Rename,
            root,
            "API_keys/github backup codes.md",
            Some(FileIdentityV1::new(
                root,
                ProviderEntryKind::File,
                "API_keys/github backup codes.md",
                Some("fixture-id".into()),
                Some(1),
            )),
        );
        r.sequence = sequence;
        r.target_relative_path = Some("API_keys/github backup-codes.md".into());
        r.target_plaintext_path = Some(PathBuf::from("C:/fixture/API_keys/github backup-codes.md"));
        r.attempts = 1;
        r
    }
    #[test]
    fn backlog_compacts_and_preserves_intent_history_and_barriers() {
        let root = Uuid::new_v4();
        let mut rows: Vec<_> = (1..=122).map(|seq| rename(root, seq)).collect();
        let first = rows[0].clone();
        rows[121].last_error = Some("latest failure".into());
        assert!(compact(&mut rows));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, first.id);
        assert_eq!(rows[0].created_at, first.created_at);
        assert_eq!(rows[0].sequence, 1);
        assert_eq!(rows[0].attempts, 122);
        assert_eq!(rows[0].merged_records, 121);
        assert_eq!(rows[0].last_error.as_deref(), Some("latest failure"));
        assert!(!compact(&mut rows));
        for kind in [
            CloudMutationKind::Writeback,
            CloudMutationKind::Delete,
            CloudMutationKind::Rename,
        ] {
            let mut intervening = rename(root, 2);
            intervening.kind = kind;
            intervening.target_relative_path = Some("another.md".into());
            let mut chain = vec![rename(root, 1), intervening, rename(root, 3)];
            assert!(!compact(&mut chain));
            assert_eq!(chain.len(), 3);
        }
        let mut different_case = rename(root, 2);
        different_case.target_relative_path = Some("API_keys/GITHUB backup-codes.md".into());
        assert!(!compact(&mut vec![rename(root, 1), different_case]));
    }

    #[test]
    fn schema2_backlog_migrates_atomically_and_recovers_primary_or_backup() {
        for backup_only in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let root = Uuid::new_v4();
            let path = dir.path().join("journal.json");
            let backup = dir.path().join("journal.json.bak");
            let mut old = CloudMutationJournal::empty(root);
            old.generation = 8;
            old.records = (1..=122).map(|seq| rename(root, seq)).collect();
            let bytes = journal_schema2::fixture(&old);
            fs::write(if backup_only { &backup } else { &path }, &bytes).unwrap();
            if backup_only {
                fs::write(&path, b"interrupted publication").unwrap();
            }
            let migrated = recover_mutation_journal_for_writer(&path, root).unwrap();
            assert_eq!(migrated.records.len(), 1);
            assert_eq!(migrated.records[0].id, old.records[0].id);
            assert_eq!(migrated.next_sequence, 122);
            assert_eq!(migrated.records[0].attempts, 122);
            let snapshot =
                path.with_extension(format!("recovery-{:x}.json", Sha256::digest(&bytes)));
            assert_eq!(fs::read(snapshot).unwrap(), bytes);
            for _ in 0..3 {
                let reopened = recover_mutation_journal_for_writer(&path, root).unwrap();
                assert_eq!(reopened.records.len(), 1);
                assert_eq!(reopened.records[0].attempts, 122);
                assert_eq!(reopened.next_sequence, 122);
            }
            let status = CloudProviderHost::status_from_journal(root, &migrated, None);
            assert_eq!(status.pending_operation_count, 1);
            assert_eq!(status.affected_file_count, 1);
            assert_eq!(status.pending_operation_counts["rename"], 1);
            assert!(!status.safe_to_unmount);
        }
    }

    #[test]
    fn schema2_checksum_is_checked_before_conversion_and_interrupted_migration_is_recoverable() {
        let dir = tempfile::tempdir().unwrap();
        let root = Uuid::new_v4();
        let path = dir.path().join("journal.json");
        let mut journal = CloudMutationJournal::empty(root);
        journal.records = vec![rename(root, 1), rename(root, 2)];
        let bytes = journal_schema2::fixture(&journal);
        let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        tampered["journal"]["records"][0]["attempts"] = 100.into();
        assert!(
            parse_checked_mutation_journal(&serde_json::to_vec(&tampered).unwrap(), root).is_err()
        );
        fs::write(&path, &bytes).unwrap();
        // Crash after a durable snapshot, before atomic replacement: replay migration safely.
        let snapshot = path.with_extension(format!("recovery-{:x}.json", Sha256::digest(&bytes)));
        fs::write(snapshot, &bytes).unwrap();
        fs::write(
            dir.path().join("abandoned-migration.tmp"),
            b"partial output",
        )
        .unwrap();
        let migrated = recover_mutation_journal_for_writer(&path, root).unwrap();
        assert_eq!(migrated.records.len(), 1);
    }
}

pub(super) fn local_revision(record: &CloudMutationRecord) -> String {
    [
        record.plaintext_path.as_ref(),
        record.target_plaintext_path.as_ref(),
    ]
    .into_iter()
    .map(|path| {
        path.and_then(|path| fs::metadata(path).ok())
            .map(|metadata| {
                let modified = metadata
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos())
                    .unwrap_or(0);
                format!("{}:{modified}", metadata.len())
            })
            .unwrap_or_else(|| "missing".into())
    })
    .collect::<Vec<_>>()
    .join("|")
}
