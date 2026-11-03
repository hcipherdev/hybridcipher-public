use crate::commands::file_ops::LocalClient;
use crate::{
    error::CliError,
    recovery_artifact::{BackupArtifact, BackupEntryPlain},
    session::{JoinCardPublishState, Session, SessionManager},
    ui,
};
use base64::engine::{general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use dirs;
use hkdf::Hkdf;
use hybridcipher_client::state::client::GroupRole;
use hybridcipher_client::{
    auth::opaque::DeviceLoginMetadata,
    device_actions::DeviceActionContext,
    saved_code_recovery::RecoveryGroupScope,
    saved_code_transport::{
        authorize_saved_code_recovery, enroll_recovery_credential, fetch_recovery_credential,
        protected_upload_recovery_artifact,
    },
    state::client::CoverageRegistryEntry,
};
use hybridcipher_crypto::account_protection::{decrypt_with_ad, encrypt_with_ad, ProtectedData};
use hybridcipher_messages::recovery_credentials::{
    recovery_envelope_sha256, RecoveryCredentialStatus,
};
use rand::{rngs::OsRng, RngCore};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const RECOVERY_CODE_BYTES: usize = 32;
const REGISTRY_ENCRYPTION_LABEL: &[u8] = b"hybridcipher/coverage-registry";
const REGISTRY_VERSION: u32 = 1;

#[derive(Subcommand, Clone, Debug)]
pub enum RecoveryCommands {
    /// Seal epoch secrets locally and upload the capsule to the server
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Create or update your personal recovery backup")
    )]
    Upload {
        /// Group identifier (defaults to the active group if omitted)
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
    },
    /// Download the latest sealed capsule and decrypt it locally
    #[cfg_attr(
        feature = "individual-edition",
        command(about = "Download and restore your personal recovery backup")
    )]
    Fetch {
        /// Group identifier (defaults to the active group if omitted)
        #[cfg_attr(feature = "individual-edition", arg(hide = true))]
        #[arg(value_name = "GROUP_ID")]
        group_id: Option<String>,
        /// Optional path to persist the sealed capsule artifact
        #[arg(long)]
        output: Option<PathBuf>,
        /// Skip importing decrypted epoch keys into the local client
        #[arg(long)]
        no_import: bool,
    },
}

#[derive(Clone, Copy, Debug)]
pub enum AutoProvisionMode {
    /// Run without prompting (e.g., post-registration onboarding).
    SilentOnboarding,
    /// Prompt the user before creating a capsule (e.g., on login if missing).
    PromptOnLogin,
}

pub async fn handle_recovery_command(
    command: RecoveryCommands,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    // A desktop action is scoped to the workspace selected when it started.
    // Keep ordinary CLI account-wide recovery behavior for invocations without this protocol.
    let desktop_group = if ui::desktop::enabled() {
        Some(
            std::env::var("HYBRIDCIPHER_DESKTOP_GROUP")
                .map_err(|_| CliError::invalid_input("Select a group before opening recovery"))?,
        )
    } else {
        None
    };
    let scoped_group = |provided: Option<String>| -> Result<Option<String>, CliError> {
        if let (Some(expected), Some(provided)) = (&desktop_group, &provided) {
            if expected != provided {
                return Err(CliError::permission(
                    "Recovery group does not match the selected workspace",
                ));
            }
        }
        Ok(provided.or_else(|| desktop_group.clone()))
    };
    match command {
        RecoveryCommands::Upload { group_id } => {
            handle_upload(scoped_group(group_id)?, session_manager).await
        }
        RecoveryCommands::Fetch {
            group_id,
            output,
            no_import,
        } => handle_fetch(scoped_group(group_id)?, output, no_import, session_manager).await,
    }
}

async fn handle_upload(
    group_id_arg: Option<String>,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;
    let client = session_manager.create_client().await?;

    let target_groups: Vec<Uuid> = if let Some(group_id) = group_id_arg {
        let group_uuid = Uuid::parse_str(group_id.trim()).map_err(|err| {
            CliError::invalid_input(format!("Group identifier is not a valid UUID: {}", err))
        })?;
        session_manager
            .require_group_admin(group_uuid, "hybridcipher recovery upload")
            .await?;
        vec![group_uuid]
    } else {
        // Fetch group memberships from server to get current role information
        let all_groups = list_all_recovery_groups(session_manager)
            .await
            .map_err(|err| {
                CliError::operation(format!("Unable to fetch group memberships: {}", err))
            })?;

        all_groups
            .into_iter()
            .filter(|g| g.role.eq_ignore_ascii_case("admin"))
            .filter_map(|g| Uuid::parse_str(&g.id).ok())
            .collect()
    };

    if target_groups.is_empty() {
        return Err(CliError::permission(SessionManager::admin_only_message(
            "hybridcipher recovery upload",
            None,
        )));
    }

    let mut entries: Vec<BackupEntryPlain> = Vec::new();
    for group_id in target_groups.iter().copied() {
        let capsule = client
            .export_recovery_capsule(group_id)
            .await
            .map_err(|err| {
                CliError::operation(format!(
                    "Unable to collect epoch secrets for recovery (group {}): {}\n\nThis device doesn't have epoch keys for this group yet. To resolve:\n  • Ask an existing group member to send you a Welcome message, or\n  • Run 'hybridcipher recovery fetch' if you have a recovery backup from another device.",
                    group_id, err
                ))
            })?;

        for epoch in &capsule.epochs {
            entries.push(BackupEntryPlain {
                group_id: capsule.group_id,
                epoch_number: epoch.epoch_number,
                epoch_uuid: epoch.epoch_uuid,
                created_at: epoch.created_at,
                is_active: epoch.is_active,
                encryption_key_b64: epoch.encryption_key_b64.clone(),
            });
        }
    }

    if entries.is_empty() {
        return Err(CliError::not_found(
            "No epoch secrets available to upload for recovery".to_string(),
        ));
    }

    ui::section("Sealing Recovery Backup");
    ui::info(&format!(
        "Including {} epoch entries across {} group(s)",
        entries.len(),
        target_groups.len()
    ));

    let path = session_manager.recovery_artifact_path()?;
    let mut artifact = BackupArtifact::load_from_path(&path).ok();
    let mut updated = false;

    // Try silent path using stored writer material first.
    let writer = load_writer_material(session_manager, &session.device_id)
        .ok()
        .flatten();
    let writer_available = writer.is_some();
    if let (Some(mut existing), Some(writer)) = (artifact.take(), writer) {
        match existing.append_entries_with_epoch_key(&entries, &writer.epoch_key) {
            Ok(_) => {
                existing.save_to_path(&path)?;
                upload_backup_artifact(&existing, &session, session_manager).await?;
                ui::dim("Recovery backup updated using stored writer key.");
                artifact = Some(existing);
                updated = true;
            }
            Err(err) => {
                ui::warning(&format!(
                    "Stored writer key failed; falling back to prompts: {}",
                    err
                ));
                artifact = Some(existing);
            }
        }
    }

    if !updated {
        // Fallback to prompts (either writer missing/failed or artifact missing).
        let (password, recovery_secret) = prompt_for_recovery_materials(writer_available)?;
        let mut artifact = match artifact {
            Some(existing) => existing,
            None => BackupArtifact::new(&password, recovery_secret.as_ref())?,
        };
        append_with_prompts(
            &mut artifact,
            &entries,
            &password,
            recovery_secret.as_ref(),
            session_manager,
            &session,
        )
        .await?;
    }

    ui::success(&format!(
        "Recovery backup uploaded with {} epoch entries for {} group(s).",
        entries.len(),
        target_groups.len()
    ));

    // Upload coverage registry snapshot separately (encrypted with OPAQUE export key).
    match session_manager.opaque_export_key().await {
        Ok(export_key) => {
            let entry_count = client
                .coverage_root_registry_entries()
                .await
                .unwrap_or_default()
                .len();
            match upload_coverage_registry_snapshot(
                &client,
                &session,
                session_manager,
                &*export_key,
            )
            .await
            {
                Ok(_) => ui::dim(&format!(
                    "Coverage registry uploaded ({} enrolled folder(s)).",
                    entry_count
                )),
                Err(err) => ui::warning(&format!(
                    "Coverage registry upload skipped (OPAQUE export key channel): {}",
                    err
                )),
            }
        }
        Err(err) => ui::warning(&format!(
            "Coverage registry upload skipped (OPAQUE export key unavailable): {}",
            err
        )),
    }

    Ok(())
}

/// Automatically provision a recovery capsule if missing.
pub async fn auto_provision_recovery_capsule(
    session_manager: &SessionManager,
    mode: AutoProvisionMode,
    password: Option<&str>,
) -> Result<(), CliError> {
    let session = match session_manager.current_session() {
        Some(s) => s,
        None => return Ok(()),
    };

    let group_id = match session_manager.ensure_current_group().await {
        Ok(g) => g,
        Err(err) => {
            ui::dim(&format!(
                "Skipping recovery auto-provision (no active group): {}",
                err
            ));
            return Ok(());
        }
    };

    if matches!(mode, AutoProvisionMode::PromptOnLogin) {
        let artifact_missing = session_manager
            .recovery_artifact_path()
            .ok()
            .map(|p| !p.exists())
            .unwrap_or(true);
        let writer_missing = load_writer_material(session_manager, &session.device_id)
            .ok()
            .flatten()
            .is_none();

        if artifact_missing && writer_missing {
            ui::warning(
                "No recovery backup found locally. Run 'hybridcipher recovery fetch' to restore your backup and re-enable automatic epoch backups on this device.",
            );
            return Ok(());
        }
    }

    let client = session_manager.create_client().await?;
    let capsule = client
        .export_recovery_capsule(group_id)
        .await
        .map_err(|err| {
            CliError::operation(format!(
                "Unable to collect epoch secrets for recovery: {}",
                err
            ))
        })?;

    let mut entries: Vec<BackupEntryPlain> = Vec::new();
    for epoch in &capsule.epochs {
        entries.push(BackupEntryPlain {
            group_id: capsule.group_id,
            epoch_number: epoch.epoch_number,
            epoch_uuid: epoch.epoch_uuid,
            created_at: epoch.created_at,
            is_active: epoch.is_active,
            encryption_key_b64: epoch.encryption_key_b64.clone(),
        });
    }

    if entries.is_empty() {
        return Err(CliError::not_found(
            "No epoch secrets available to upload for recovery".to_string(),
        ));
    }

    ui::section("Recovery Backup");
    ui::info(&format!(
        "Including {} epoch entries across 1 group(s)",
        entries.len()
    ));

    let (password, recovery_secret) = match mode {
        AutoProvisionMode::SilentOnboarding => {
            // First-time setup: generate new recovery code and use provided password or prompt
            let mut recovery_secret_bytes = [0u8; RECOVERY_CODE_BYTES];
            OsRng.fill_bytes(&mut recovery_secret_bytes);
            let recovery_secret = Zeroizing::new(recovery_secret_bytes.to_vec());
            let formatted_code = format_recovery_code(&recovery_secret_bytes);

            // Use provided password or prompt if not available
            let password = match password {
                Some(pwd) => pwd.to_string(),
                None => {
                    let pwd =
                        ui::prompts::password("Enter account password to create recovery backup")?;
                    if pwd.trim().is_empty() {
                        return Err(CliError::invalid_input(
                            "Password cannot be empty for recovery".to_string(),
                        ));
                    }
                    pwd
                }
            };

            ui::warning("Store this recovery code somewhere safe. It is required to restore epoch keys if all devices are lost. We do not retain a copy.");
            ui::info(&format!("Recovery Code: {}", formatted_code));

            (password, recovery_secret)
        }
        AutoProvisionMode::PromptOnLogin => {
            // Try silent path first using stored writer material from keyring
            let path = session_manager.recovery_artifact_path()?;
            let mut artifact = match BackupArtifact::load_from_path(&path) {
                Ok(existing) => Some(existing),
                Err(_) => None,
            };

            let writer = load_writer_material(session_manager, &session.device_id)
                .ok()
                .flatten();
            let writer_available = writer.is_some();

            if let (Some(mut existing), Some(writer)) = (artifact.take(), writer) {
                // Silent append using keyring writer material
                match existing.append_entries_with_epoch_key(&entries, &writer.epoch_key) {
                    Ok(_) => {
                        existing.save_to_path(&path)?;
                        upload_backup_artifact(&existing, &session, session_manager).await?;
                        ui::dim("Recovery backup updated silently using stored writer key.");

                        ui::success(&format!(
                            "Recovery backup uploaded with {} epoch entries for 1 group(s).",
                            entries.len()
                        ));
                        return Ok(());
                    }
                    Err(err) => {
                        ui::warning(&format!(
                            "Stored writer key failed; falling back to prompts: {}",
                            err
                        ));
                        artifact = Some(existing);
                    }
                }
            }

            // Fallback: prompt for password and recovery code
            let (password, recovery_secret) = prompt_for_recovery_materials(!writer_available)?;
            let mut artifact = match artifact {
                Some(existing) => existing,
                None => BackupArtifact::new(&password, recovery_secret.as_ref())?,
            };

            append_with_prompts(
                &mut artifact,
                &entries,
                &password,
                recovery_secret.as_ref(),
                session_manager,
                &session,
            )
            .await?;

            ui::success(&format!(
                "Recovery backup uploaded with {} epoch entries for 1 group(s).",
                entries.len()
            ));
            return Ok(());
        }
    };

    let mut artifact = BackupArtifact::new(&password, recovery_secret.as_ref())?;
    append_with_prompts(
        &mut artifact,
        &entries,
        &password,
        recovery_secret.as_ref(),
        session_manager,
        &session,
    )
    .await?;

    ui::success(&format!(
        "Recovery backup uploaded with {} epoch entries for 1 group(s).",
        entries.len()
    ));

    Ok(())
}

async fn handle_fetch(
    group_id_arg: Option<String>,
    output: Option<PathBuf>,
    no_import: bool,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    let password = Zeroizing::new(ui::prompts::password(
        "Enter account password (required to unwrap recovery backup)",
    )?);
    if password.trim().is_empty() {
        return Err(CliError::invalid_input(
            "Password cannot be empty for recovery".to_string(),
        ));
    }

    // Initialize session encryption so we can read encrypted configs like group_id
    session_manager.initialize_account_protection(&password)?;

    let group_filter = if let Some(group_id) = group_id_arg {
        Some(Uuid::parse_str(group_id.trim()).map_err(|err| {
            CliError::invalid_input(format!("Group identifier is not a valid UUID: {}", err))
        })?)
    } else {
        None
    };

    let artifact_path = session_manager.recovery_artifact_path()?;
    // A restore that grants trust must use the latest online authenticated
    // backup; local ciphertext cannot extend the server-authorized snapshot.
    let downloaded = download_backup_artifact_with_version(session_manager, &session).await?;
    let fetched_server_version = Some(downloaded.server_version);
    let artifact = downloaded.artifact;

    let recovery_code_input = Zeroizing::new(ui::prompts::password(
        "Enter recovery code to decrypt backup",
    )?);
    let recovery_secret = parse_recovery_code(&recovery_code_input)?;

    let unlocked = artifact.unlock(&password, recovery_secret.as_ref())?;

    let mut client = session_manager.create_client().await?;

    // Fetch group memberships from server to get current role information
    let all_groups = list_all_recovery_groups(session_manager)
        .await
        .map_err(|err| {
            CliError::operation(format!("Unable to fetch group memberships: {}", err))
        })?;

    let scopes = recovery_scopes(&all_groups, group_filter)?;
    let mut restore = unlocked
        .validate_for_groups(&scopes, group_filter)
        .map_err(CliError::format)?;
    client
        .validate_authenticated_recovery(&restore)
        .await
        .map_err(|e| CliError::operation(e.to_string()))?;
    let identity = session_manager.get_or_create_device_keypair().await?;
    let context = recovery_context(&session);
    let status = ensure_cli_recovery_credential(
        session_manager,
        &session,
        &artifact,
        recovery_secret.as_ref(),
        fetched_server_version,
    )
    .await?;
    let credential = status
        .credential
        .as_ref()
        .ok_or_else(|| CliError::authentication("Recovery credential has not been enrolled"))?;
    let version = status
        .artifact_version
        .ok_or_else(|| CliError::not_found("Recovery backup revision is unavailable"))?;
    // Enrollment may have changed the backup revision: always bind the proof to
    // the exact current sealed bytes and validate every entry in that snapshot.
    let current_remote = download_backup_artifact_with_version(session_manager, &session).await?;
    if current_remote.server_version != version
        || !artifact.has_same_envelope(&current_remote.artifact)
    {
        return Err(CliError::operation(
            "Recovery backup changed during setup. Fetch it again.",
        ));
    }
    let exact_hash = hex::encode(Sha256::digest(
        general_purpose::STANDARD
            .decode(&current_remote.artifact_blob)
            .map_err(|e| CliError::format(e.to_string()))?,
    ));
    let unlocked = current_remote
        .artifact
        .unlock(&password, recovery_secret.as_ref())?;
    let current_groups = list_all_recovery_groups(session_manager).await?;
    restore = unlocked
        .validate_for_groups(
            &recovery_scopes(&current_groups, group_filter)?,
            group_filter,
        )
        .map_err(CliError::format)?;
    client
        .validate_authenticated_recovery(&restore)
        .await
        .map_err(|e| CliError::operation(e.to_string()))?;
    let metadata = recovery_device_metadata(session_manager, &session, &identity).await?;
    authorize_saved_code_recovery(
        &identity,
        &context,
        &session.username,
        &password,
        metadata,
        unlocked.recovery_secret(),
        credential,
        version,
        &exact_hash,
    )
    .await
    .map_err(CliError::authentication)?;
    session_manager.mark_device_recovered()?;
    // Check current epochs again after the proof so a concurrent rekey cannot
    // turn a stale backup entry into the writable current group.
    let fresh_groups = list_all_recovery_groups(session_manager).await?;
    restore = unlocked
        .validate_for_groups(&recovery_scopes(&fresh_groups, group_filter)?, group_filter)
        .map_err(CliError::format)?;
    if !no_import {
        let installed = client
            .install_authenticated_recovery(&restore)
            .await
            .map_err(|e| CliError::operation(e.to_string()))?;
        ui::info(&format!(
            "Restored {} authenticated epoch(s) across {} group(s).",
            installed.imported_epochs,
            restore.group_ids().len()
        ));
        if !installed.missing_current_groups.is_empty() {
            ui::warning("Historical keys were restored, but the current encryption key is missing. Obtain a newer backup or a Welcome message before enrolling folders.");
        }
        // Register recovered keys server-side so the next login keeps this device approved.
        match client
            .publish_recovered_self_welcomes(&installed.ready_groups)
            .await
        {
            Ok(failed) if failed.is_empty() => {}
            _ => ui::warning("Group key access could not be registered with the server yet; it will retry on the next Welcome sync."),
        }
    } else {
        ui::info("Saved code verified; epoch import skipped (--no-import).");
    }
    current_remote.artifact.save_to_path(&artifact_path)?;
    save_artifact_meta(session_manager, version)?;
    if let Some(path) = output {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| CliError::io(format!("Unable to create output directory: {err}")))?;
        }
        let bytes = general_purpose::STANDARD
            .decode(&current_remote.artifact_blob)
            .map_err(|err| CliError::format(err.to_string()))?;
        fs::write(&path, &bytes)
            .map_err(|err| CliError::io(format!("Failed to save sealed backup: {err}")))?;
        ui::info(&format!(
            "Sealed artifact saved to {} ({} bytes)",
            path.display(),
            bytes.len()
        ));
    }
    if let Err(error) = persist_writer_material(
        session_manager,
        &session.device_id,
        unlocked.file_key(),
        unlocked.entry_key(),
    ) {
        ui::warning(&format!(
            "Keys and device trust recovered; automatic backup needs secure storage: {}",
            error
        ));
    }
    // Fetch coverage registry via the OPAQUE export-key channel.
    match session_manager.opaque_export_key().await {
        Ok(export_key) => match download_coverage_registry(session_manager, &session, &*export_key)
            .await
        {
            Ok(Some(entries)) => {
                if let Err(err) = client.coverage_import_registry_entries(entries).await {
                    ui::warning(&format!(
                        "Coverage registry restore skipped (OPAQUE export key channel): {}",
                        err
                    ));
                } else {
                    ui::dim("Coverage registry restored from server (OPAQUE export key channel).");
                    // Recreate client to pick up newly imported coverage registry entries
                    client = session_manager.create_client().await?;
                }
            }
            Ok(None) => {
                ui::dim(
                    "No server-side coverage registry snapshot found (OPAQUE export key channel).",
                );
            }
            Err(err) => {
                ui::warning(&format!(
                    "Coverage registry download failed (OPAQUE export key channel): {}",
                    err
                ));
            }
        },
        Err(err) => ui::warning(&format!(
            "Coverage registry download skipped (OPAQUE export key unavailable): {}",
            err
        )),
    }

    if !no_import {
        if let Some(group) = group_filter.or_else(|| restore.group_ids().first().copied()) {
            client
                .use_group(group)
                .await
                .map_err(|e| CliError::operation(e.to_string()))?;
        }
        if let Err(error) = auto_recover_coverage_after_restore(&client).await {
            ui::warning(&format!("Coverage recovery post-fetch skipped: {}", error));
        }
    }
    if let Err(error) = ensure_join_card_published(session_manager).await {
        ui::warning(&format!("Join card publication check failed: {}", error));
    }
    ui::success("Saved-code recovery completed; this device is trusted.");
    Ok(())
}

fn recovery_scopes(
    groups: &[crate::session::GroupInfo],
    _filter: Option<Uuid>,
) -> Result<Vec<RecoveryGroupScope>, CliError> {
    if groups.is_empty() {
        return Err(CliError::permission(
            "This account has no recovery group memberships",
        ));
    }
    groups
        .iter()
        .map(|group| {
            let id = Uuid::parse_str(&group.id)
                .map_err(|_| CliError::format("Recovery group ID is invalid"))?;
            Ok(RecoveryGroupScope {
                group_id: id,
                group_name: group.name.clone(),
                user_role: if group.role.eq_ignore_ascii_case("admin")
                    || group.role.eq_ignore_ascii_case("owner")
                {
                    GroupRole::Admin
                } else {
                    GroupRole::Member
                },
                current_epoch_uuid: group
                    .current_epoch
                    .as_deref()
                    .map(Uuid::parse_str)
                    .transpose()
                    .map_err(|_| CliError::format("Current recovery group epoch is invalid"))?,
            })
        })
        .collect()
}

#[derive(Deserialize)]
struct RecoveryMembershipPage {
    groups: Vec<RecoveryMembership>,
    has_more: bool,
    next_cursor: Option<String>,
}

#[derive(Deserialize)]
struct RecoveryMembership {
    id: String,
    organization_id: Option<String>,
    name: String,
    description: Option<String>,
    user_role: String,
    current_epoch: Option<String>,
    member_count: usize,
    created_at: String,
}

async fn list_all_recovery_groups(
    session_manager: &SessionManager,
) -> Result<Vec<crate::session::GroupInfo>, CliError> {
    let session = session_manager.require_auth()?;
    let client = recovery_http_client()?;
    let endpoint = format!("{}/api/v1/groups", session.server_url.trim_end_matches('/'));
    let mut cursor: Option<String> = None;
    let mut cursors = HashSet::new();
    let mut groups = Vec::new();
    let mut ids = HashSet::new();
    for _ in 0..1000 {
        let mut request = client
            .get(&endpoint)
            .bearer_auth(&session.token)
            .query(&[("limit", "100")]);
        if let Some(cursor) = &cursor {
            request = request.query(&[("cursor", cursor)]);
        }
        let response = request
            .send()
            .await
            .map_err(|e| CliError::network_from(&e))?;
        if response.status() == StatusCode::UNAUTHORIZED {
            session_manager.invalidate_session("recovery_memberships").await?;
            return Err(CliError::authentication(
                "Login again to fetch recovery memberships",
            ));
        }
        if !response.status().is_success() {
            return Err(CliError::network(format!(
                "Cannot fetch recovery memberships: {}",
                response.status()
            )));
        }
        let page: RecoveryMembershipPage = response
            .json()
            .await
            .map_err(|e| CliError::format(format!("Invalid recovery membership page: {e}")))?;
        for group in page.groups {
            if !ids.insert(group.id.clone()) {
                return Err(CliError::format(
                    "Duplicate recovery membership; fetch again",
                ));
            }
            groups.push(crate::session::GroupInfo {
                id: group.id,
                organization_id: group.organization_id,
                name: group.name,
                description: group.description,
                role: group.user_role,
                current_epoch: group.current_epoch,
                member_count: group.member_count,
                created_at: group.created_at,
            });
        }
        if !page.has_more {
            return Ok(groups);
        }
        let next = page
            .next_cursor
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::format("Recovery membership pagination is incomplete"))?;
        if !cursors.insert(next.clone()) {
            return Err(CliError::format(
                "Recovery membership pagination repeated a cursor",
            ));
        }
        cursor = Some(next);
    }
    Err(CliError::format(
        "Recovery membership list exceeded the page limit",
    ))
}

fn recovery_context(session: &Session) -> DeviceActionContext<'_> {
    DeviceActionContext {
        server_url: &session.server_url,
        token: &session.token,
        user_id: &session.user_id,
        device_id: &session.device_id,
    }
}

async fn recovery_device_metadata(
    session_manager: &SessionManager,
    _session: &Session,
    identity: &hybridcipher_crypto::signatures::Ed25519KeyPair,
) -> Result<DeviceLoginMetadata, CliError> {
    let invitation = session_manager.get_or_create_invitation_keypair().await?;
    let public = invitation
        .invitation_public_key()
        .map_err(|e| CliError::session(e.to_string()))?
        .to_bytes();
    Ok(DeviceLoginMetadata {
        identity_public_key_hex: hex::encode(identity.public_key_bytes()),
        invitation_public_key_hex: hex::encode(public),
        device_display_name: None,
        mfa_code: None,
        backup_code: None,
    })
}

async fn ensure_cli_recovery_credential(
    session_manager: &SessionManager,
    session: &Session,
    artifact: &BackupArtifact,
    raw_code: &[u8],
    expected_version: Option<u32>,
) -> Result<RecoveryCredentialStatus, CliError> {
    let context = recovery_context(session);
    let status = fetch_recovery_credential(&context)
        .await
        .map_err(CliError::authentication)?;
    if let Some(credential) = &status.credential {
        let hash = recovery_envelope_sha256(
            &serde_json::to_value(artifact).map_err(|e| CliError::format(e.to_string()))?,
        )
        .map_err(CliError::format)?;
        if hash != credential.recovery_envelope_sha256 {
            return Err(CliError::operation("This backup uses another encryption envelope. Fetch the current recovery backup before updating it."));
        }
        return Ok(status);
    }
    // Legacy enrollment uses the established OTP/MFA trust-confirmation flow
    // once; later saved-code recovery needs no additional verification.
    super::auth::ensure_device_management_trust(session_manager).await?;
    let identity = session_manager.get_or_create_device_keypair().await?;
    let version = expected_version.or(status.artifact_version);
    let enrolled =
        enroll_recovery_credential(&identity, &context, raw_code, artifact, version, None, None)
            .await
            .map_err(CliError::authentication)?;
    if let Some(version) = enrolled.artifact_version {
        save_artifact_meta(session_manager, version)?;
    }
    Ok(enrolled)
}

fn format_recovery_code(code: &[u8]) -> String {
    let hex = hex::encode_upper(code);
    let mut grouped = String::with_capacity(hex.len() + hex.len() / 8);
    for (idx, ch) in hex.chars().enumerate() {
        if idx > 0 && idx % 8 == 0 {
            grouped.push('-');
        }
        grouped.push(ch);
    }
    grouped
}

pub fn parse_recovery_code(input: &str) -> Result<Zeroizing<Vec<u8>>, CliError> {
    let normalized = Zeroizing::new(
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect::<String>(),
    );

    if normalized.len() != RECOVERY_CODE_BYTES * 2 {
        return Err(CliError::invalid_input(format!(
            "Recovery code must contain exactly {} hexadecimal characters (ignoring dashes)",
            RECOVERY_CODE_BYTES * 2
        )));
    }

    let bytes = hex::decode(&normalized).map_err(|err| {
        CliError::invalid_input(format!("Recovery code is not valid hexadecimal: {}", err))
    })?;

    if bytes.len() != RECOVERY_CODE_BYTES {
        return Err(CliError::invalid_input(
            "Recovery code has an unexpected length".to_string(),
        ));
    }

    Ok(Zeroizing::new(bytes))
}

struct WriterMaterial {
    epoch_key: [u8; 32],
}

impl Drop for WriterMaterial {
    fn drop(&mut self) {
        self.epoch_key.zeroize();
    }
}

const WRITER_BLOB_FILE: &str = "recovery_writer_blob.json";
const WRITER_AAD: &[u8] = b"hybridcipher/recovery/writer";
const WRITER_KEY_SERVICE: &str = "hybridcipher-recovery-writer";
const DESKTOP_KEY_BUNDLE_SERVICE: &str = "hybridcipher-desktop-keybundle";
const DESKTOP_KEY_BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct DesktopKeyBundleRecord {
    #[serde(default)]
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    state_key_b64: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    writer_keys_b64: HashMap<String, String>,
}

fn prompt_for_recovery_materials(
    remind_keyring: bool,
) -> Result<(String, Zeroizing<Vec<u8>>), CliError> {
    if remind_keyring {
        ui::warning(
            "Silent recovery backup is unavailable (secure keyring not accessible). Enter your password and recovery code. To re-enable automatic backup, ensure your OS keychain/keyring is available and unlocked.",
        );
    }
    let password = ui::prompts::password("Enter account password to update recovery backup")?;
    if password.trim().is_empty() {
        return Err(CliError::invalid_input(
            "Password cannot be empty for recovery".to_string(),
        ));
    }
    let recovery_code_input = Zeroizing::new(ui::prompts::password("Enter recovery code")?);
    let recovery_secret = parse_recovery_code(&recovery_code_input)?;
    Ok((password, recovery_secret))
}

async fn append_with_prompts(
    artifact: &mut BackupArtifact,
    entries: &[BackupEntryPlain],
    password: &str,
    recovery_secret: &[u8],
    session_manager: &SessionManager,
    session: &Session,
) -> Result<(), CliError> {
    artifact.append_entries(entries, password, recovery_secret)?;
    let k_file = artifact.unwrap_file_key(password, recovery_secret)?;
    let epoch_key = Zeroizing::new(artifact.derive_epoch_key(k_file.as_ref())?);
    persist_writer_material(
        session_manager,
        &session.device_id,
        slice_to_key(k_file.as_ref())?,
        &epoch_key,
    )?;
    let path = session_manager.recovery_artifact_path()?;
    artifact.save_to_path(&path)?;
    ensure_cli_recovery_credential(
        session_manager,
        session,
        artifact,
        recovery_secret,
        load_artifact_meta(session_manager),
    )
    .await?;
    upload_backup_artifact(artifact, session, session_manager).await?;
    Ok(())
}

fn writer_key_entry(device_id: &str) -> Result<keyring::Entry, CliError> {
    keyring::Entry::new(WRITER_KEY_SERVICE, device_id).map_err(|e| {
        CliError::storage(format!(
            "Unable to open secure storage for recovery writer key: {}",
            e
        ))
    })
}

fn decode_writer_key(encoded: &str) -> Result<[u8; 32], CliError> {
    let writer_key = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| CliError::format(format!("Stored writer key is invalid base64: {}", e)))?;
    if writer_key.len() != 32 {
        return Err(CliError::format(
            "Stored writer key has invalid length".to_string(),
        ));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&writer_key);
    Ok(key)
}

fn desktop_bundle_storage_id(session_manager: &SessionManager) -> Option<String> {
    let session = session_manager.current_session()?;
    Some(session_manager.user_storage_id_for(&session.username, &session.server_url))
}

fn desktop_bundle_entry(storage_id: &str) -> Result<keyring::Entry, CliError> {
    keyring::Entry::new(DESKTOP_KEY_BUNDLE_SERVICE, storage_id).map_err(|e| {
        CliError::storage(format!(
            "Unable to open desktop secure bundle entry for recovery writer key: {}",
            e
        ))
    })
}

fn load_desktop_bundle_record(
    session_manager: &SessionManager,
) -> Result<Option<DesktopKeyBundleRecord>, CliError> {
    let Some(storage_id) = desktop_bundle_storage_id(session_manager) else {
        return Ok(None);
    };
    let entry = desktop_bundle_entry(&storage_id)?;
    match entry.get_password() {
        Ok(serialized) => {
            let bundle =
                serde_json::from_str::<DesktopKeyBundleRecord>(&serialized).map_err(|e| {
                    CliError::format(format!("Desktop secure bundle is malformed: {}", e))
                })?;
            Ok(Some(bundle))
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(CliError::storage(format!(
            "Failed to read desktop secure bundle: {}",
            e
        ))),
    }
}

fn store_writer_key_in_desktop_bundle(
    session_manager: &SessionManager,
    device_id: &str,
    writer_key: &[u8; 32],
) -> Result<bool, CliError> {
    let Some(storage_id) = desktop_bundle_storage_id(session_manager) else {
        return Ok(false);
    };

    let mut bundle = load_desktop_bundle_record(session_manager)?.unwrap_or_default();
    bundle.version = DESKTOP_KEY_BUNDLE_VERSION;
    bundle.writer_keys_b64.insert(
        device_id.to_string(),
        general_purpose::STANDARD.encode(writer_key),
    );

    let serialized = serde_json::to_string(&bundle).map_err(|e| {
        CliError::format(format!("Failed to serialize desktop secure bundle: {}", e))
    })?;
    let entry = desktop_bundle_entry(&storage_id)?;
    entry.set_password(&serialized).map_err(|e| {
        CliError::storage(format!("Failed to persist desktop secure bundle: {}", e))
    })?;
    Ok(true)
}

fn load_writer_key_from_desktop_bundle(
    session_manager: &SessionManager,
    device_id: &str,
) -> Result<Option<[u8; 32]>, CliError> {
    let bundle = match load_desktop_bundle_record(session_manager)? {
        Some(bundle) => bundle,
        None => return Ok(None),
    };
    let Some(encoded) = bundle.writer_keys_b64.get(device_id) else {
        return Ok(None);
    };
    decode_writer_key(encoded).map(Some)
}

fn load_writer_key_from_legacy_keyring(device_id: &str) -> Result<Option<[u8; 32]>, CliError> {
    let writer_key_b64 = match writer_key_entry(device_id)
        .ok()
        .and_then(|entry| entry.get_password().ok())
    {
        Some(v) => v,
        None => return Ok(None),
    };
    decode_writer_key(&writer_key_b64).map(Some)
}

pub(crate) fn slice_to_key(slice: &[u8]) -> Result<&[u8; 32], CliError> {
    slice
        .try_into()
        .map_err(|_| CliError::format("Unexpected key length for recovery backup".to_string()))
}

fn derive_writer_key(k_file: &[u8], device_id: &str) -> Result<[u8; 32], CliError> {
    let mut writer_key = [0u8; 32];
    let hk = Hkdf::<sha2::Sha256>::new(None, k_file);
    hk.expand(format!("writer:{}", device_id).as_bytes(), &mut writer_key)
        .map_err(|_| CliError::encryption("Failed to derive writer key".to_string()))?;
    Ok(writer_key)
}

pub(crate) fn persist_writer_material(
    session_manager: &SessionManager,
    device_id: &str,
    k_file: &[u8; 32],
    epoch_key: &[u8; 32],
) -> Result<(), CliError> {
    let writer_key = derive_writer_key(k_file, device_id)?;
    persist_writer_blob(session_manager, device_id, &writer_key, epoch_key)?;
    Ok(())
}

fn persist_writer_blob(
    session_manager: &SessionManager,
    device_id: &str,
    writer_key: &[u8; 32],
    epoch_key: &[u8; 32],
) -> Result<(), CliError> {
    let blob = encrypt_with_ad(epoch_key, *writer_key, WRITER_AAD)
        .map_err(|e| CliError::encryption(format!("Failed to seal writer blob: {}", e)))?;

    // Store writer key in the desktop bundle first (shared with desktop app).
    // Fall back to legacy per-device keyring entry for older states.
    let bundle_result = store_writer_key_in_desktop_bundle(session_manager, device_id, writer_key);
    if !matches!(bundle_result, Ok(true)) {
        let bundle_err = bundle_result
            .err()
            .map(|e| e.to_string())
            .unwrap_or_else(|| "desktop bundle storage context unavailable".to_string());
        let legacy_result = writer_key_entry(device_id).and_then(|entry| {
            let key_b64 = base64::engine::general_purpose::STANDARD.encode(writer_key);
            entry.set_password(&key_b64).map_err(|e| {
                CliError::storage(format!(
                    "Unable to persist legacy recovery writer key in secure storage: {}",
                    e
                ))
            })
        });
        if let Err(legacy_err) = legacy_result {
            ui::warning(&format!(
                "Could not store recovery writer key in secure storage (desktop bundle error: {}; legacy fallback error: {}). Silent append may be unavailable.",
                bundle_err, legacy_err
            ));
        }
    }

    let dir = session_manager.user_config_dir().ok_or_else(|| {
        CliError::configuration("No active user context for storing writer blob".to_string())
    })?;
    let path = dir.join(WRITER_BLOB_FILE);
    let serialized = serde_json::to_vec(&blob)
        .map_err(|e| CliError::format(format!("Failed to serialize writer blob: {}", e)))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::io(format!("Failed to create writer blob dir: {}", e)))?;
    }
    std::fs::write(&path, serialized)
        .map_err(|e| CliError::io(format!("Failed to persist writer blob: {}", e)))?;
    Ok(())
}

fn load_writer_material(
    session_manager: &SessionManager,
    device_id: &str,
) -> Result<Option<WriterMaterial>, CliError> {
    let dir = match session_manager.user_config_dir() {
        Some(dir) => dir,
        None => return Ok(None),
    };
    let path = dir.join(WRITER_BLOB_FILE);
    if !path.exists() {
        return Ok(None);
    }

    let blob_bytes = std::fs::read(&path)
        .map_err(|e| CliError::io(format!("Failed to read writer blob: {}", e)))?;
    let blob: ProtectedData = serde_json::from_slice(&blob_bytes)
        .map_err(|e| CliError::format(format!("Writer blob is malformed: {}", e)))?;

    let key = match load_writer_key_from_desktop_bundle(session_manager, device_id)? {
        Some(key) => key,
        None => match load_writer_key_from_legacy_keyring(device_id)? {
            Some(key) => key,
            None => return Ok(None),
        },
    };
    let epoch_key_bytes = Zeroizing::new(decrypt_with_ad(&blob, key, WRITER_AAD).map_err(|e| {
        CliError::decryption(format!(
            "Failed to decrypt writer blob; recovery prompts will be required: {}",
            e
        ))
    })?);
    if epoch_key_bytes.len() != 32 {
        return Ok(None);
    }
    let mut epoch_key = [0u8; 32];
    epoch_key.copy_from_slice(&epoch_key_bytes);
    Ok(Some(WriterMaterial { epoch_key }))
}
#[derive(Serialize, Deserialize)]
struct RecoveryArtifactEnvelope {
    artifact_blob: String,
    version: u32,
    #[serde(default)]
    expected_version: Option<u32>,
}

struct DownloadedBackupArtifact {
    artifact: BackupArtifact,
    artifact_blob: String,
    server_version: u32,
}

#[derive(Serialize, Deserialize)]
struct CoverageRegistryEnvelope {
    registry_blob: String,
    #[serde(default)]
    expected_version: Option<u32>,
}

#[derive(Serialize, Deserialize)]
struct CoverageRegistryResponse {
    version: u32,
    updated_at: DateTime<Utc>,
    registry_blob: String,
}

fn recovery_http_client() -> Result<reqwest::Client, CliError> {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| CliError::network(format!("Failed to initialize recovery HTTP client: {}", e)))
}

async fn upload_backup_artifact(
    artifact: &BackupArtifact,
    session: &Session,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let identity = session_manager.get_or_create_device_keypair().await?;
    let context = recovery_context(session);
    let mut pending = artifact.clone();
    for _ in 0..3 {
        let status = fetch_recovery_credential(&context)
            .await
            .map_err(CliError::authentication)?;
        let credential = status.credential.ok_or_else(|| CliError::authentication(
            "This legacy backup needs recovery-code enrollment. Run recovery fetch with your saved code first."))?;
        let envelope_hash = recovery_envelope_sha256(
            &serde_json::to_value(&pending).map_err(|e| CliError::format(e.to_string()))?,
        )
        .map_err(CliError::format)?;
        if envelope_hash != credential.recovery_envelope_sha256 {
            return Err(CliError::operation(
                "Recovery backup envelope changed. Fetch the current backup before uploading.",
            ));
        }
        if status.artifact_version.is_some() {
            let remote = download_backup_artifact_with_version(session_manager, session).await?;
            pending = merge_artifacts(remote.artifact, pending);
        }
        match protected_upload_recovery_artifact(
            &identity,
            &context,
            &pending,
            status.artifact_version,
            Some(&credential.credential_id),
        )
        .await
        {
            Ok(response) => {
                let version = response["version"]
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| {
                        CliError::format("Recovery upload response has invalid revision")
                    })?;
                save_artifact_meta(session_manager, version)?;
                pending.save_to_path(&session_manager.recovery_artifact_path()?)?;
                return Ok(());
            }
            Err(error) => {
                // A lost response can follow a successful upload. Refetch the
                // current revision and retry an identical, deduplicated merge.
                ui::warning(&format!("Recovery upload did not complete: {}", error));
            }
        }
    }
    Err(CliError::operation(
        "Recovery upload could not be confirmed. The local sealed backup was preserved.",
    ))
}

pub(crate) async fn upload_coverage_registry_snapshot(
    client: &LocalClient,
    session: &Session,
    session_manager: &SessionManager,
    opaque_export_key: &[u8; 64],
) -> Result<(), CliError> {
    let entries = client
        .coverage_root_registry_entries()
        .await
        .unwrap_or_default();

    upload_coverage_registry_entries(&entries, session, session_manager, opaque_export_key).await?;

    Ok(())
}

pub(crate) async fn upload_coverage_registry_entries(
    entries: &[CoverageRegistryEntry],
    session: &Session,
    session_manager: &SessionManager,
    opaque_export_key: &[u8; 64],
) -> Result<(), CliError> {
    let registry_json = serde_json::to_string(entries).map_err(|e| {
        CliError::format(format!(
            "Failed to serialize coverage registry for upload: {}",
            e
        ))
    })?;

    let registry_blob = encrypt_registry_blob(opaque_export_key, registry_json)?;
    let endpoint = coverage_registry_endpoint(&session.server_url)?;
    let expected_version = load_registry_meta(session_manager);
    let payload = CoverageRegistryEnvelope {
        registry_blob,
        expected_version,
    };

    let resp = reqwest::Client::new()
        .put(&endpoint)
        .bearer_auth(&session.token)
        .json(&payload)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to upload coverage registry: {}", e)))?;

    if resp.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("coverage_registry_upload").await?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::network(format!(
            "Server rejected coverage registry upload ({}): {}",
            status, body
        )));
    }

    let parsed: CoverageRegistryResponse = resp.json().await.map_err(|e| {
        CliError::format(format!(
            "Failed to parse coverage registry upload response: {}",
            e
        ))
    })?;
    save_registry_meta(session_manager, parsed.version)?;
    Ok(())
}

async fn download_backup_artifact_with_version(
    session_manager: &SessionManager,
    session: &Session,
) -> Result<DownloadedBackupArtifact, CliError> {
    let endpoint = recovery_artifact_endpoint(&session.server_url)?;
    let client = recovery_http_client()?;
    let response = client
        .get(&endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to fetch recovery backup: {}", e)))?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED => {
            session_manager.invalidate_session("download_backup_artifact").await?;
            return Err(CliError::authentication(
                "Authentication token rejected. Please login again.".to_string(),
            ));
        }
        StatusCode::NOT_FOUND => {
            return Err(CliError::not_found(
                "No recovery backup artifact available on the server".to_string(),
            ))
        }
        other => {
            let body = response.text().await.unwrap_or_default();
            return Err(CliError::network(format!(
                "Server returned {} while fetching recovery backup: {}",
                other, body
            )));
        }
    }

    let envelope: RecoveryArtifactEnvelope = response.json().await.map_err(|e| {
        CliError::format(format!("Failed to parse recovery backup response: {}", e))
    })?;
    Ok(DownloadedBackupArtifact {
        artifact: BackupArtifact::from_base64(&envelope.artifact_blob)?,
        artifact_blob: envelope.artifact_blob,
        server_version: envelope.version,
    })
}

pub async fn download_backup_artifact(
    session_manager: &SessionManager,
    session: &Session,
) -> Result<BackupArtifact, CliError> {
    download_backup_artifact_with_version(session_manager, session)
        .await
        .map(|downloaded| downloaded.artifact)
}

fn recovery_artifact_endpoint(base_url: &str) -> Result<String, CliError> {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        Ok(format!("{}/recovery-artifact", trimmed))
    } else {
        Ok(format!("{}/api/v1/recovery-artifact", trimmed))
    }
}

fn coverage_registry_endpoint(base_url: &str) -> Result<String, CliError> {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/api/v1") {
        Ok(format!("{}/coverage-registry", trimmed))
    } else {
        Ok(format!("{}/api/v1/coverage-registry", trimmed))
    }
}

fn artifact_meta_path(session_manager: &SessionManager) -> Result<PathBuf, CliError> {
    let dir = session_manager.user_config_dir().ok_or_else(|| {
        CliError::configuration("No active user context for artifact metadata".to_string())
    })?;
    Ok(dir.join("recovery_backup.meta.json"))
}

fn load_artifact_meta(session_manager: &SessionManager) -> Option<u32> {
    let path = artifact_meta_path(session_manager).ok()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&data)
        .ok()
        .and_then(|v| v.get("version").and_then(|v| v.as_u64()))
        .and_then(|v| v.try_into().ok())
}

fn save_artifact_meta(session_manager: &SessionManager, version: u32) -> Result<(), CliError> {
    let path = artifact_meta_path(session_manager)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::io(format!("Failed to create artifact meta dir: {}", e)))?;
    }
    let payload = json!({
        "version": version,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&payload).unwrap_or_default(),
    )
    .map_err(|e| CliError::io(format!("Failed to write artifact metadata: {}", e)))?;
    Ok(())
}

fn registry_meta_path(session_manager: &SessionManager) -> Result<PathBuf, CliError> {
    let dir = session_manager.user_config_dir().ok_or_else(|| {
        CliError::configuration("No active user context for registry metadata".to_string())
    })?;
    Ok(dir.join("coverage_registry.meta.json"))
}

fn load_registry_meta(session_manager: &SessionManager) -> Option<u32> {
    let path = registry_meta_path(session_manager).ok()?;
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str::<Value>(&data)
        .ok()
        .and_then(|v| v.get("version").and_then(|v| v.as_u64()))
        .and_then(|v| v.try_into().ok())
}

fn save_registry_meta(session_manager: &SessionManager, version: u32) -> Result<(), CliError> {
    let path = registry_meta_path(session_manager)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::io(format!("Failed to create registry meta dir: {}", e)))?;
    }
    let payload = json!({
        "version": version,
        "updated_at": chrono::Utc::now().to_rfc3339(),
    });
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&payload).unwrap_or_default(),
    )
    .map_err(|e| CliError::io(format!("Failed to write registry metadata: {}", e)))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CoverageRegistryPackage {
    version: u32,
    registry_json: String,
}

#[derive(Serialize, Deserialize)]
struct CoverageRegistryBlob {
    version: u32,
    salt_b64: String,
    protected: ProtectedData,
}

fn derive_registry_key(opaque_export_key: &[u8; 64], salt: &[u8]) -> Result<[u8; 32], CliError> {
    let hk = Hkdf::<sha2::Sha256>::new(Some(salt), opaque_export_key);
    let mut key = [0u8; 32];
    hk.expand(REGISTRY_ENCRYPTION_LABEL, &mut key)
        .map_err(|_| CliError::encryption("Failed to derive registry key".to_string()))?;
    Ok(key)
}

fn encrypt_registry_blob(
    opaque_export_key: &[u8; 64],
    registry_json: String,
) -> Result<String, CliError> {
    let mut salt = [0u8; 16]; // lgtm[rust/hard-coded-cryptographic-value] zeroed buffer is immediately filled from OsRng
    OsRng.fill_bytes(&mut salt);
    let key = derive_registry_key(opaque_export_key, &salt)?;
    let package = CoverageRegistryPackage {
        version: REGISTRY_VERSION,
        registry_json,
    };
    let plaintext = serde_json::to_vec(&package)
        .map_err(|e| CliError::format(format!("Failed to serialize registry: {}", e)))?;
    let protected = encrypt_with_ad(&plaintext, key, REGISTRY_ENCRYPTION_LABEL)
        .map_err(|e| CliError::encryption(format!("Failed to encrypt registry: {}", e)))?;
    let blob = CoverageRegistryBlob {
        version: REGISTRY_VERSION,
        salt_b64: base64::engine::general_purpose::STANDARD.encode(salt),
        protected,
    };
    let encoded = serde_json::to_vec(&blob)
        .map_err(|e| CliError::format(format!("Failed to serialize registry blob: {}", e)))?;
    Ok(base64::engine::general_purpose::STANDARD.encode(encoded))
}

fn decrypt_registry_blob(opaque_export_key: &[u8; 64], blob_b64: &str) -> Result<String, CliError> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob_b64.trim())
        .map_err(|e| CliError::format(format!("Registry blob is not valid base64: {}", e)))?;
    let blob: CoverageRegistryBlob = serde_json::from_slice(&decoded)
        .map_err(|e| CliError::format(format!("Registry blob is invalid JSON: {}", e)))?;
    let salt = base64::engine::general_purpose::STANDARD
        .decode(&blob.salt_b64)
        .map_err(|e| CliError::format(format!("Registry salt is invalid base64: {}", e)))?;
    let key = derive_registry_key(opaque_export_key, &salt)?;
    let plaintext = decrypt_with_ad(&blob.protected, key, REGISTRY_ENCRYPTION_LABEL)
        .map_err(|e| CliError::decryption(format!("Failed to decrypt coverage registry: {}", e)))?;
    let package: CoverageRegistryPackage = serde_json::from_slice(&plaintext).map_err(|e| {
        CliError::format(format!("Decrypted registry payload is invalid JSON: {}", e))
    })?;
    Ok(package.registry_json)
}

fn merge_artifacts(mut server: BackupArtifact, mut local: BackupArtifact) -> BackupArtifact {
    if !server.has_same_envelope(&local) {
        return server;
    }
    // Prefer higher version as base.
    let mut merged = if server.version >= local.version {
        server.clone()
    } else {
        local.clone()
    };

    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for e in &merged.entries {
        if let Ok(ct) = serde_json::to_vec(e) {
            seen.insert(ct);
        }
    }
    for e in std::mem::take(&mut local.entries)
        .into_iter()
        .chain(std::mem::take(&mut server.entries))
    {
        if let Ok(ct) = serde_json::to_vec(&e) {
            if seen.insert(ct.clone()) {
                merged.entries.push(e);
            }
        } else {
            merged.entries.push(e);
        }
    }
    // Persist the canonical format version to avoid leaking bumped values from older clients.
    merged.version = crate::recovery_artifact::BACKUP_VERSION;

    merged
}

async fn download_coverage_registry(
    session_manager: &SessionManager,
    session: &Session,
    opaque_export_key: &[u8; 64],
) -> Result<Option<Vec<CoverageRegistryEntry>>, CliError> {
    let endpoint = coverage_registry_endpoint(&session.server_url)?;
    let resp = reqwest::Client::new()
        .get(&endpoint)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|e| CliError::network(format!("Failed to fetch coverage registry: {}", e)))?;

    if resp.status() == StatusCode::UNAUTHORIZED {
        session_manager.invalidate_session("download_coverage_registry").await?;
        return Err(CliError::authentication(
            "Authentication token rejected. Please login again.".to_string(),
        ));
    }

    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(CliError::network(format!(
            "Server returned {} while fetching coverage registry: {}",
            status, body
        )));
    }

    let parsed: CoverageRegistryResponse = resp.json().await.map_err(|e| {
        CliError::format(format!("Failed to parse coverage registry response: {}", e))
    })?;

    let registry_json = decrypt_registry_blob(opaque_export_key, &parsed.registry_blob)?;
    let entries: Vec<CoverageRegistryEntry> =
        serde_json::from_str(&registry_json).map_err(|e| {
            CliError::format(format!(
                "Decrypted coverage registry is invalid JSON: {}",
                e
            ))
        })?;
    Ok(Some(entries))
}

/// Append the latest active epoch of a group into the unified backup artifact (admin groups).
/// Attempts a silent path using a device-local writer key; falls back to prompting for password
/// and recovery code when writer material is missing.
pub async fn append_active_epoch_to_artifact(
    session_manager: &SessionManager,
    group_id: Uuid,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    let client = session_manager.create_client().await?;
    let memberships = client.get_group_memberships().await;
    let is_admin = memberships
        .iter()
        .find(|m| m.group_id == group_id)
        .map(|m| matches!(m.user_role, GroupRole::Admin))
        .unwrap_or(false);
    if !is_admin {
        ui::dim("Skipping backup append: not an admin of the target group.");
        return Ok(());
    }

    let capsule = client.export_recovery_capsule(group_id).await?;
    let latest = capsule
        .epochs
        .iter()
        .filter(|e| e.is_active)
        .max_by_key(|e| e.epoch_number)
        .cloned();
    let Some(epoch) = latest else {
        return Err(CliError::not_found(
            "No active epoch found to append to backup".to_string(),
        ));
    };

    let writer = load_writer_material(session_manager, &session.device_id)
        .ok()
        .flatten();
    let mut artifact =
        match BackupArtifact::load_from_path(&session_manager.recovery_artifact_path()?) {
            Ok(existing) => existing,
            Err(_) => {
                // No artifact: require interactive path to seed it.
                let (password, recovery_secret) = prompt_for_recovery_materials(false)?;
                BackupArtifact::new(&password, recovery_secret.as_ref())?
            }
        };

    let entry = BackupEntryPlain {
        group_id,
        epoch_number: epoch.epoch_number,
        epoch_uuid: epoch.epoch_uuid,
        created_at: epoch.created_at,
        is_active: epoch.is_active,
        encryption_key_b64: epoch.encryption_key_b64.clone(),
    };

    if let Some(writer) = writer {
        if let Err(err) =
            artifact.append_entries_with_epoch_key(&[entry.clone()], &writer.epoch_key)
        {
            ui::warning(&format!(
                "Silent recovery backup append failed; falling back to prompts: {}",
                err
            ));
            let (password, recovery_secret) = prompt_for_recovery_materials(true)?;
            append_with_prompts(
                &mut artifact,
                &[entry],
                &password,
                recovery_secret.as_ref(),
                session_manager,
                &session,
            )
            .await?;
            return Ok(());
        }
    } else {
        let (password, recovery_secret) = prompt_for_recovery_materials(true)?;
        append_with_prompts(
            &mut artifact,
            &[entry],
            &password,
            recovery_secret.as_ref(),
            session_manager,
            &session,
        )
        .await?;
        return Ok(());
    }

    let path = session_manager.recovery_artifact_path()?;
    artifact.save_to_path(&path)?;
    upload_backup_artifact(&artifact, &session, session_manager).await?;
    ui::dim(&format!(
        "Updated unified backup artifact with epoch {} at {}",
        epoch.epoch_number,
        path.display()
    ));

    Ok(())
}

async fn auto_recover_coverage_after_restore(client: &LocalClient) -> Result<(), CliError> {
    // Step 1: Load registry snapshot (if any) from the restored backup.
    let registry_entries = match client.coverage_root_registry_entries().await {
        Ok(entries) => entries,
        Err(err) => {
            ui::warning(&format!(
                "Skipping coverage re-enrollment (registry unavailable): {}",
                err
            ));
            return run_background_scans_all_groups(client).await;
        }
    };

    if registry_entries.is_empty() {
        ui::dim("No enrolled folders recorded in backup; skipping auto re-enrollment.");
        return run_background_scans_all_groups(client).await;
    }

    ui::section(&format!(
        "Found {} enrolled folder(s) from previous devices:",
        registry_entries.len()
    ));
    for entry in &registry_entries {
        ui::info(&format!(
            "  - {} (group {}, root_id: {})",
            entry.path,
            entry.group_id,
            entry
                .root_id
                .map(|r| r.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        ));
    }

    if !ui::prompts::confirm_with_default("Attempt automatic re-enrollment now?", true)? {
        ui::info(
            "Skipping auto re-enrollment. You can re-enroll folders manually later with `hybridcipher coverage enroll <path>`.",
        );
        return run_background_scans_all_groups(client).await;
    }

    let search_roots = common_marker_search_roots();

    // Keep track of successfully matched registry entries by group + path.
    let mut matched: HashSet<(Uuid, String)> = HashSet::new();

    let grouped_registry: HashMap<Uuid, Vec<_>> =
        registry_entries
            .iter()
            .cloned()
            .fold(HashMap::new(), |mut acc, entry| {
                acc.entry(entry.group_id).or_default().push(entry);
                acc
            });

    for (group_id, entries) in grouped_registry {
        if let Err(err) = client.use_group(group_id).await {
            ui::warning(&format!(
                "Skipping group {} for coverage re-enrollment (cannot activate group): {}",
                group_id, err
            ));
            continue;
        }

        // Pass 1: exact path + marker validation.
        for entry in &entries {
            let path = PathBuf::from(&entry.path);
            if !path.exists() {
                continue;
            }

            if entry.root_id.is_some() && !marker_matches_hint(&path, entry.root_id) {
                continue;
            }

            match client.coverage_enroll_root(&path).await {
                Ok(_) => {
                    matched.insert((entry.group_id, entry.path.clone()));
                }
                Err(err) => ui::warning(&format!(
                    "Auto-enroll skipped for {} (group {}): {}",
                    path.display(),
                    group_id,
                    err
                )),
            }
        }

        // Pass 2: marker search for unresolved entries in this group.
        let already_enrolled: HashSet<Uuid> = client
            .coverage_roots()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.group_id == Some(group_id))
            .map(|r| r.root_id)
            .collect();

        let marker_result = client
            .coverage_recover_from_markers(search_roots.clone(), 5, true)
            .await;

        if let Ok(result) = marker_result {
            if !result.enrolled.is_empty() {
                ui::info(&format!(
                    "Recovered {} coverage root(s) via markers for group {}.",
                    result.enrolled.len(),
                    group_id
                ));
            }
        } else if let Err(err) = marker_result {
            ui::warning(&format!(
                "Marker-based recovery for group {} failed: {}",
                group_id, err
            ));
        }

        // Recompute matched entries after marker recovery.
        let now_enrolled: Vec<_> = client
            .coverage_roots()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|r| r.group_id == Some(group_id) && !already_enrolled.contains(&r.root_id))
            .collect();

        for root in now_enrolled {
            // Match by root_id when present; fall back to path equality.
            if let Some(entry) = entries.iter().find(|e| {
                e.root_id == Some(root.root_id) || e.path == root.path.display().to_string()
            }) {
                matched.insert((entry.group_id, entry.path.clone()));
            }
        }
    }

    // Compute missing entries.
    let coverage_roots = client.coverage_roots().await.unwrap_or_default();
    let mut missing: Vec<(Uuid, String)> = Vec::new();
    for entry in registry_entries {
        let found = coverage_roots.iter().any(|root| {
            root.group_id == Some(entry.group_id)
                && (entry.root_id.map(|id| id == root.root_id).unwrap_or(false)
                    || root.path.display().to_string() == entry.path)
        });
        if !found {
            missing.push((entry.group_id, entry.path));
        }
    }

    ui::section("Coverage Re-enrollment Summary");
    ui::success(&format!("Re-enrolled {} folder(s).", matched.len()));
    if !missing.is_empty() {
        ui::warning("Folders still missing (re-enroll manually if needed):");
        for (group_id, path) in &missing {
            ui::warning(&format!("  - group {}: {}", group_id, path));
        }
    }

    run_background_scans_all_groups(client).await
}

fn common_marker_search_roots() -> Vec<PathBuf> {
    let mut search = Vec::new();
    if let Some(home) = dirs::home_dir() {
        search.push(home);
    }
    if let Some(doc) = dirs::document_dir() {
        search.push(doc);
    }
    if let Some(desktop) = dirs::desktop_dir() {
        search.push(desktop);
    }
    search
}

fn marker_matches_hint(path: &Path, root_id: Option<Uuid>) -> bool {
    let Some(root_id) = root_id else {
        return true;
    };

    let marker_name = format!(".hybridcipher-root-{}.json", root_id);
    let marker_path = if path.is_dir() {
        path.join(&marker_name)
    } else {
        match path.parent() {
            Some(parent) => parent.join(&marker_name),
            None => return false,
        }
    };

    if !marker_path.exists() {
        return false;
    }

    // Best-effort parse to confirm root_id matches.
    #[derive(Deserialize)]
    struct MarkerCheck {
        #[serde(default)]
        root_id: Option<Uuid>,
    }

    std::fs::read_to_string(&marker_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<MarkerCheck>(&raw).ok())
        .and_then(|m| m.root_id)
        .map(|id| id == root_id)
        .unwrap_or(false)
}

async fn run_background_scans_all_groups(client: &LocalClient) -> Result<(), CliError> {
    let memberships = client.get_group_memberships().await;
    if memberships.is_empty() {
        return Ok(());
    }

    let mut total_roots_scanned = 0usize;
    for membership in memberships {
        if let Err(err) = client.use_group(membership.group_id).await {
            ui::warning(&format!(
                "Skipping coverage scan for group {} (cannot switch group): {}",
                membership.group_id, err
            ));
            continue;
        }

        ui::dim(&format!(
            "Scanning enrolled folders for group {}...",
            membership.group_id
        ));

        match client.coverage_rescan(None).await {
            Ok(summary) => {
                total_roots_scanned += summary.roots_scanned;
                ui::dim(&format!(
                    "Group {} scan: {} root(s), {} tracked files updated",
                    membership.group_id, summary.roots_scanned, summary.files_indexed
                ));
            }
            Err(err) => ui::warning(&format!(
                "Coverage scan failed for group {}: {}",
                membership.group_id, err
            )),
        }

        if let Err(err) = client.coverage_guard(None, true).await {
            ui::warning(&format!(
                "Coverage guard failed for group {}: {}",
                membership.group_id, err
            ));
        }
    }

    if total_roots_scanned > 0 {
        ui::dim(&format!(
            "Background coverage scans completed across all groups ({} root(s) scanned).",
            total_roots_scanned
        ));
    }

    Ok(())
}

/// Ensure that a join card is published for this device.
/// Checks local cache and server before creating a new one.
async fn ensure_join_card_published(session_manager: &SessionManager) -> Result<(), CliError> {
    ui::subsection("Join Card Publication Check");
    let session = session_manager.require_auth()?;
    match session_manager
        .ensure_join_card_published_for_current_device()
        .await
    {
        Ok(JoinCardPublishState::AlreadyPresent) => {
            ui::dim(&format!(
                "Join card already exists on server for device {}",
                session.device_id
            ));
        }
        Ok(JoinCardPublishState::Published) => {
            ui::success(&format!(
                "Join card published for device {}",
                session.device_id
            ));
            ui::dim("Device join card is now registered in the server directory");
        }
        Err(err) => return Err(err),
    }

    Ok(())
}

#[cfg(test)]
#[path = "../../tests/recovery/test_recovery_workflow.rs"]
mod recovery_workflow_tests;
