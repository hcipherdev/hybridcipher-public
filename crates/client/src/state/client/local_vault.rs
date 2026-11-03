//! Accountless vault: one Personal group whose epoch key exists only on this device.
//!
//! Keys created here carry `EpochKeySource::LocalVault`, which never satisfies
//! account readiness. Creating an account later commits the same key as the
//! server genesis epoch, which relabels it as a Welcome key.

use super::*;
use crate::file::group_transfer::{
    encrypted_file_owner, transfer_file_to_group, EncryptedFileOwner, GroupEpochKey,
    GroupTransferOutcome, TRANSFER_TEMP_SUFFIX,
};
use crate::local_recovery_kit::LocalKitContents;
use crate::saved_code_recovery::BackupEntryPlain;
use zeroize::Zeroizing;

pub const LOCAL_VAULT_CONFIG_KEY: &str = "local_vault";
const LOCAL_VAULT_GROUP_NAME: &str = "Personal";
const LOCAL_VAULT_GROUP_DESCRIPTION: &str = "On this device only";
/// How many files a folder transfer handles between progress reports.
const TRANSFER_PROGRESS_EVERY: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocalVaultInfo {
    pub group_id: Uuid,
    pub created_at: DateTime<Utc>,
}

/// Files handled so far while a folder moves to another group.
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct GroupTransferProgress {
    pub total_files: usize,
    pub processed_files: usize,
    pub moved_files: usize,
}

impl<S: Storage, N: Network> Client<S, N> {
    /// Stop this client (and its clones) from reading any login session. The
    /// machine-wide active account must never authorize a local vault's requests.
    pub fn set_local_only(&self, local_only: bool) {
        self.local_only
            .store(local_only, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn is_local_only(&self) -> bool {
        self.local_only.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The vault recorded in this storage, if it was created as accountless.
    pub async fn local_vault_info(&self) -> Result<Option<LocalVaultInfo>, ClientError> {
        let Some(raw) = self
            .storage
            .load_config_fresh(LOCAL_VAULT_CONFIG_KEY)
            .await?
        else {
            return Ok(None);
        };
        serde_json::from_str(&raw).map(Some).map_err(|_| {
            initialization::setup_error(
                ErrorCode::StorageCorruption,
                "Saved local vault details cannot be read",
            )
        })
    }

    /// Create the vault's Personal group and epoch-1 key. Idempotent: a second
    /// call returns the existing vault rather than inventing another key.
    pub async fn create_local_vault(&self) -> Result<LocalVaultInfo, ClientError> {
        self.ensure_state_loaded().await?;
        if let Some(info) = self.local_vault_info().await? {
            return Ok(info);
        }
        self.refuse_account_storage().await?;
        let mut epoch_key = Zeroizing::new([0u8; 32]);
        rand::rngs::OsRng.fill_bytes(epoch_key.as_mut());
        let info = LocalVaultInfo {
            group_id: Uuid::new_v4(),
            created_at: Utc::now(),
        };
        let epoch = LocalVaultEpoch {
            number: 1,
            created_at: info.created_at,
            is_active: true,
            key: epoch_key,
        };
        self.install_local_vault(&info, std::slice::from_ref(&epoch))
            .await?;
        Ok(info)
    }

    /// Restore a vault on a new device from an authenticated recovery kit.
    pub async fn import_local_recovery_kit(
        &self,
        contents: &LocalKitContents,
    ) -> Result<LocalVaultInfo, ClientError> {
        self.ensure_state_loaded().await?;
        if let Some(info) = self.local_vault_info().await? {
            if info.group_id != contents.group_id {
                return Err(ClientError::InvalidState(
                    "This device already holds a different local vault".into(),
                ));
            }
        } else {
            self.refuse_account_storage().await?;
        }
        let epochs = contents
            .epochs
            .iter()
            .map(|epoch| LocalVaultEpoch {
                number: epoch.number,
                created_at: epoch.created_at,
                is_active: epoch.is_active,
                key: epoch.key.clone(),
            })
            .collect::<Vec<_>>();
        let created_at = epochs
            .iter()
            .map(|epoch| epoch.created_at)
            .min()
            .unwrap_or_else(Utc::now);
        let info = LocalVaultInfo {
            group_id: contents.group_id,
            created_at,
        };
        self.install_local_vault(&info, &epochs).await?;
        Ok(info)
    }

    /// Whether the vault's current epoch key is present and usable locally.
    pub async fn has_local_vault_key(&self, group_id: Uuid) -> Result<bool, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        let Some(current) = state
            .group_memberships
            .get(&group_id)
            .and_then(|membership| membership.current_epoch_id)
        else {
            return Ok(false);
        };
        Ok(Self::get_epoch_state(&state, group_id, current)
            .is_some_and(|epoch| epoch.is_active && epoch.key_source.is_locally_usable()))
    }

    /// Epoch keys to seal into a recovery kit or an account backup.
    pub async fn export_local_vault_entries(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<BackupEntryPlain>, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        let mut entries = Vec::new();
        for (number, epochs) in &state.epochs {
            for epoch in epochs.iter().filter(|epoch| {
                epoch.group_id == Some(group_id) && epoch.key_source.is_locally_usable()
            }) {
                entries.push(BackupEntryPlain {
                    group_id,
                    epoch_number: *number,
                    epoch_uuid: EpochIdMapper::u64_to_uuid(*number, group_id.as_bytes()),
                    created_at: epoch.created_at,
                    is_active: epoch.is_active,
                    encryption_key_b64: general_purpose::STANDARD.encode(epoch.encryption_key),
                });
            }
        }
        if entries.is_empty() {
            return Err(ClientError::InvalidState(
                "This vault has no encryption keys to back up".into(),
            ));
        }
        entries.sort_by_key(|entry| entry.epoch_number);
        Ok(entries)
    }

    /// The vault's genesis key, committed to the server when an account is created.
    pub async fn local_vault_genesis_key(
        &self,
        group_id: Uuid,
    ) -> Result<Zeroizing<[u8; 32]>, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        let epoch = Self::get_epoch_state(&state, group_id, 1)
            .filter(|epoch| epoch.key_source.is_locally_usable())
            .ok_or_else(|| {
                initialization::setup_error(
                    ErrorCode::GroupStateMissing,
                    "The local vault key is not available on this device",
                )
            })?;
        Ok(Zeroizing::new(epoch.encryption_key))
    }

    /// The vault's key as the source of a transfer. A vault never rekeys, so
    /// epoch 1 holds every one of its files.
    pub async fn local_vault_transfer_key(
        &self,
        group_id: Uuid,
    ) -> Result<GroupEpochKey, ClientError> {
        Ok(GroupEpochKey {
            group_id,
            epoch_id: 1,
            key: self.local_vault_genesis_key(group_id).await?,
        })
    }

    /// The key a transfer into `group_id` wraps with: its current epoch, confirmed
    /// by the account (never a local vault key) and not in the middle of a rekey.
    pub async fn current_group_transfer_key(
        &self,
        group_id: Uuid,
    ) -> Result<GroupEpochKey, ClientError> {
        self.ensure_state_loaded().await?;
        let state = self.state.read().await;
        if state
            .active_rekey
            .as_ref()
            .is_some_and(|operation| operation.group_id == group_id)
        {
            return Err(ClientError::InvalidState(
                "Your Personal workspace is changing its keys. Try again when that finishes."
                    .into(),
            ));
        }
        let missing = || {
            initialization::setup_error(
                ErrorCode::GroupStateMissing,
                "This device doesn't have your Personal workspace key yet",
            )
        };
        let epoch_id = state
            .group_memberships
            .get(&group_id)
            .and_then(|membership| membership.current_epoch_id)
            .ok_or_else(missing)?;
        let epoch = Self::get_epoch_state(&state, group_id, epoch_id)
            .filter(|epoch| epoch.key_source.is_verified())
            .ok_or_else(missing)?;
        Ok(GroupEpochKey {
            group_id,
            epoch_id,
            key: Zeroizing::new(epoch.encryption_key),
        })
    }

    /// Move every file under `path` that belongs to `from`'s group into `to`'s
    /// group by rewriting its header (see `file::group_transfer`). Running it again
    /// after an interruption skips moved files and removes unfinished copies.
    pub async fn transfer_folder_to_group(
        &self,
        path: &Path,
        from: GroupEpochKey,
        to: GroupEpochKey,
        mut on_progress: impl FnMut(GroupTransferProgress) + Send + 'static,
    ) -> Result<GroupTransferProgress, ClientError> {
        let client = self.clone();
        let path = path.to_path_buf();
        task::spawn_blocking(move || {
            let mut files = Vec::new();
            for entry in WalkDir::new(&path)
                .follow_links(false)
                .into_iter()
                .filter_entry(|entry| !client.is_path_excluded(entry.path()))
            {
                let entry = entry.map_err(|err| {
                    ClientError::InvalidInput(format!("Cannot read '{}': {}", path.display(), err))
                })?;
                if !entry.file_type().is_file() {
                    continue;
                }
                let unfinished = entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.ends_with(TRANSFER_TEMP_SUFFIX));
                if unfinished {
                    std::fs::remove_file(entry.path())
                        .map_err(|err| ClientError::from(StorageError::Io(err)))?;
                    continue;
                }
                files.push(entry.into_path());
            }

            let mut progress = GroupTransferProgress {
                total_files: files.len(),
                ..GroupTransferProgress::default()
            };
            on_progress(progress);
            for file in files {
                let owner = encrypted_file_owner(&file)
                    .map_err(|err| ClientError::from(StorageError::Io(err)))?;
                let foreign = match owner {
                    EncryptedFileOwner::NotEncrypted => false,
                    EncryptedFileOwner::Group(owner) if owner == to.group_id => false,
                    EncryptedFileOwner::Group(owner) if owner == from.group_id => {
                        if transfer_file_to_group(&file, &from, &to)? == GroupTransferOutcome::Moved
                        {
                            progress.moved_files += 1;
                        }
                        false
                    }
                    EncryptedFileOwner::Group(_) | EncryptedFileOwner::Unknown => true,
                };
                if foreign {
                    return Err(ClientError::InvalidInput(format!(
                        "'{}' was encrypted by another workspace, so it can't be moved. Move it out of this folder and try again.",
                        file.display()
                    )));
                }
                progress.processed_files += 1;
                if progress.processed_files % TRANSFER_PROGRESS_EVERY == 0 {
                    on_progress(progress);
                }
            }
            on_progress(progress);
            Ok(progress)
        })
        .await
        .map_err(|err| ClientError::InvalidState(format!("Moving files stopped: {err}")))?
    }

    /// Folders that still depend on this vault's key: every protected folder, and
    /// every folder that was unprotected but still holds files encrypted by
    /// `group_id`. A vault with none can be discarded without losing data.
    pub async fn local_vault_folders_in_use(
        &self,
        group_id: Uuid,
    ) -> Result<Vec<PathBuf>, ClientError> {
        self.ensure_state_loaded().await?;
        let roots = {
            let state = self.state.read().await;
            state.coverage_roots.values().cloned().collect::<Vec<_>>()
        };
        let client = self.clone();
        task::spawn_blocking(move || {
            let mut in_use = Vec::new();
            for root in roots {
                if !root.path.exists() {
                    continue;
                }
                let holds_vault_files = root.state == CoverageRootState::Active
                    || WalkDir::new(&root.path)
                        .follow_links(false)
                        .into_iter()
                        .filter_entry(|entry| !client.is_path_excluded(entry.path()))
                        .filter_map(Result::ok)
                        .filter(|entry| entry.file_type().is_file())
                        .any(|entry| {
                            // An unreadable file might be the vault's, so it counts.
                            encrypted_file_owner(entry.path()).map_or(true, |owner| {
                                owner == EncryptedFileOwner::Group(group_id)
                            })
                        });
                if holds_vault_files && !in_use.contains(&root.path) {
                    in_use.push(root.path);
                }
            }
            in_use.sort();
            in_use
        })
        .await
        .map_err(|err| ClientError::InvalidState(format!("Checking folders stopped: {err}")))
    }

    /// Forget the accountless marker once the group belongs to an account.
    pub async fn clear_local_vault_marker(&self) -> Result<(), ClientError> {
        Ok(self.storage.delete_config(LOCAL_VAULT_CONFIG_KEY).await?)
    }

    /// A vault is only created by a local-only client, in storage that has never
    /// joined an account group.
    async fn refuse_account_storage(&self) -> Result<(), ClientError> {
        if !self.is_local_only() {
            return Err(ClientError::InvalidState(
                "A local vault needs a client that never uses an account session".into(),
            ));
        }
        if !self.state.read().await.group_memberships.is_empty() {
            return Err(ClientError::InvalidState(
                "A local vault cannot be created in storage that belongs to an account".into(),
            ));
        }
        Ok(())
    }

    async fn install_local_vault(
        &self,
        info: &LocalVaultInfo,
        epochs: &[LocalVaultEpoch],
    ) -> Result<(), ClientError> {
        let current = epochs
            .iter()
            .filter(|epoch| epoch.is_active)
            .map(|epoch| epoch.number)
            .max()
            .or_else(|| epochs.iter().map(|epoch| epoch.number).max())
            .ok_or_else(|| ClientError::InvalidState("A local vault needs a key".into()))?;
        let membership = {
            let mut state = self.state.write().await;
            for epoch in epochs {
                if Self::get_epoch_state(&state, info.group_id, epoch.number).is_some_and(
                    |existing| {
                        existing.key_source.is_locally_usable()
                            && existing.encryption_key != *epoch.key
                    },
                ) {
                    return Err(initialization::setup_error(
                        ErrorCode::SecurityTampering,
                        "Recovery kit key conflicts with this device's vault key",
                    ));
                }
            }
            for epoch in epochs {
                Self::upsert_epoch_state(
                    &mut state,
                    info.group_id,
                    EpochState {
                        group_id: Some(info.group_id),
                        epoch_id: epoch.number,
                        encryption_key: *epoch.key,
                        key_source: EpochKeySource::LocalVault,
                        members: Vec::new(),
                        created_at: epoch.created_at,
                        is_active: epoch.number == current,
                        file_count: 0,
                        marked_for_removal: false,
                        removal_eligible_at: None,
                    },
                );
            }
            let membership = state
                .group_memberships
                .entry(info.group_id)
                .or_insert_with(|| GroupMembership {
                    group_id: info.group_id,
                    group_name: LOCAL_VAULT_GROUP_NAME.into(),
                    group_description: Some(LOCAL_VAULT_GROUP_DESCRIPTION.into()),
                    user_role: GroupRole::Admin,
                    joined_at: info.created_at,
                    current_epoch_id: Some(current),
                    last_sync: Utc::now(),
                    members: Vec::new(),
                });
            membership.current_epoch_id = Some(current);
            let membership = membership.clone();
            state.active_group_id = Some(info.group_id);
            state.current_epoch = current;
            membership
        };
        self.save_group_membership(&membership).await?;
        self.save_client_state_now().await?;
        let encoded = serde_json::to_string(info)
            .map_err(|error| ClientError::SerializationError(error.to_string()))?;
        self.storage
            .store_config(LOCAL_VAULT_CONFIG_KEY, &encoded)
            .await?;
        self.storage
            .store_config("group_id", &info.group_id.to_string())
            .await?;
        Ok(())
    }
}

struct LocalVaultEpoch {
    number: u64,
    created_at: DateTime<Utc>,
    is_active: bool,
    key: Zeroizing<[u8; 32]>,
}

#[cfg(test)]
#[path = "../../../tests/local_vault/test_local_vault.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../tests/local_vault/test_vault_group_transfer.rs"]
mod group_transfer_tests;
