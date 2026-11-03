//! Explicit, user-requested rewrite of older-format files in the current format.
//!
//! An upgrade decrypts from the encrypted original (never from a plaintext
//! cache that may hold unsynced edits), preserves that original ciphertext, and
//! replaces it only if it is still the version that was read.
use crate::{
    normalize_relative_path, writeback_plaintext_file_checked, ExpectedProviderVersion,
    ProviderCoreError, ProviderEntry, ProviderEntryKind, Result, VaultCompatibility,
};
use hybridcipher_client::file::content_manifest::LegacyReadPolicy;
use hybridcipher_mount_sync::{MountCrypto, MountSyncError};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fs, path::Path};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyFileSummary {
    pub relative_path: String,
    pub content_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyUpgradeFailure {
    pub relative_path: String,
    pub error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegacyUpgradeReport {
    pub upgraded: Vec<String>,
    pub failed: Vec<LegacyUpgradeFailure>,
}

impl LegacyUpgradeReport {
    pub fn map_paths(self, mut map: impl FnMut(String) -> String) -> Self {
        Self {
            upgraded: self.upgraded.into_iter().map(&mut map).collect(),
            failed: self
                .failed
                .into_iter()
                .map(|failure| LegacyUpgradeFailure {
                    relative_path: map(failure.relative_path),
                    error: failure.error,
                })
                .collect(),
        }
    }
}

/// What an upgrade runs against: the folder's crypto and explicit legacy policy,
/// its encrypted root, and a private directory for transient plaintext.
#[derive(Clone, Copy)]
pub struct LegacyUpgradeContext<'a> {
    pub crypto: &'a dyn MountCrypto,
    pub compatibility: &'a VaultCompatibility,
    pub root_id: Uuid,
    pub encrypted_root: &'a Path,
    pub plaintext_staging_dir: &'a Path,
}

fn is_legacy_file(entry: &ProviderEntry) -> bool {
    entry.kind == ProviderEntryKind::File && entry.requires_legacy_compatibility()
}

pub fn legacy_file_summaries(entries: &[ProviderEntry]) -> Vec<LegacyFileSummary> {
    let mut files: Vec<_> = entries
        .iter()
        .filter(|entry| is_legacy_file(entry))
        .map(|entry| LegacyFileSummary {
            relative_path: entry.relative_path.clone(),
            content_size: entry.metadata.as_ref().map_or(0, |m| m.content_size),
        })
        .collect();
    files.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    files
}

/// Rewrites one older-format file in the current format under its existing file id.
/// The folder's explicit legacy access is required because the contents cannot be
/// proven complete; the encrypted original is preserved before replacement.
pub async fn upgrade_legacy_file(
    context: &LegacyUpgradeContext<'_>,
    entry: &ProviderEntry,
) -> Result<ProviderEntry> {
    let LegacyUpgradeContext {
        crypto,
        compatibility,
        root_id,
        encrypted_root,
        plaintext_staging_dir,
    } = *context;
    if !is_legacy_file(entry) {
        return Err(ProviderCoreError::InvalidIdentity(format!(
            "{} is not an older-format file",
            entry.relative_path
        )));
    }
    if compatibility.policy() == LegacyReadPolicy::Strict {
        return Err(ProviderCoreError::Crypto(
            MountSyncError::LegacyCompatibilityRequired,
        ));
    }
    let metadata = entry.metadata.as_ref().ok_or_else(|| {
        ProviderCoreError::InvalidIdentity(format!("{} has no metadata", entry.relative_path))
    })?;
    let expected = ExpectedProviderVersion::Exact(entry.content_version().ok_or_else(|| {
        ProviderCoreError::InvalidIdentity(format!(
            "{} has no content version",
            entry.relative_path
        ))
    })?);
    crypto.check_write_access().await?;

    fs::create_dir_all(plaintext_staging_dir)?;
    let plaintext = tempfile::Builder::new()
        .prefix("legacy-upgrade-")
        .tempfile_in(plaintext_staging_dir)?;
    let read = crypto
        .decrypt_file_streaming(&entry.encrypted_path, plaintext.path(), metadata)
        .await;
    compatibility.record_read_result(&read);
    read?;

    writeback_plaintext_file_checked(
        crypto,
        Some(compatibility),
        root_id,
        encrypted_root,
        &entry.relative_path,
        plaintext.path(),
        Some(&entry.identity),
        &expected,
    )
    .await
}

/// Upgrades the requested older-format files (all of them when `relative_paths`
/// is `None`). Files listed in `busy_paths` still have local work in flight and
/// are skipped; every other per-file failure is reported without stopping the run.
pub async fn upgrade_legacy_entries(
    context: &LegacyUpgradeContext<'_>,
    entries: &[ProviderEntry],
    relative_paths: Option<&[String]>,
    busy_paths: &HashSet<String>,
) -> Result<LegacyUpgradeReport> {
    if context.compatibility.policy() == LegacyReadPolicy::Strict {
        return Err(ProviderCoreError::Crypto(
            MountSyncError::LegacyCompatibilityRequired,
        ));
    }
    let mut report = LegacyUpgradeReport::default();
    let selected: Vec<&ProviderEntry> = match relative_paths {
        None => entries
            .iter()
            .filter(|entry| is_legacy_file(entry))
            .collect(),
        Some(paths) => {
            let mut selected = Vec::new();
            for path in paths {
                let normalized = normalize_relative_path(path.as_str());
                match entries
                    .iter()
                    .find(|entry| entry.relative_path == normalized && is_legacy_file(entry))
                {
                    Some(entry) => selected.push(entry),
                    None => report.failed.push(LegacyUpgradeFailure {
                        relative_path: normalized,
                        error: "No older-format file was found at this path.".into(),
                    }),
                }
            }
            selected
        }
    };

    for entry in selected {
        if busy_paths.contains(&entry.relative_path) {
            report.failed.push(LegacyUpgradeFailure {
                relative_path: entry.relative_path.clone(),
                error: "This file has changes that are still syncing. Try again after they finish."
                    .into(),
            });
            continue;
        }
        match upgrade_legacy_file(context, entry).await {
            Ok(_) => report.upgraded.push(entry.relative_path.clone()),
            Err(error) => report.failed.push(LegacyUpgradeFailure {
                relative_path: entry.relative_path.clone(),
                error: error.to_string(),
            }),
        }
    }
    Ok(report)
}
