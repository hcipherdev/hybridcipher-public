use crate::{
    commands::recovery::parse_recovery_code, error::CliError, recovery_artifact::BackupArtifact,
    security::unlock::validate_unlock_code, session::SessionManager, ui,
};
use chrono::Utc;
use hybridcipher_client::{RecoveryCapsulePlain, RecoveryEpochSecret};
use std::collections::HashMap;
use uuid::Uuid;

/// Hidden SOS decrypt entry point gated by support-issued unlock codes.
pub async fn handle_sos_decrypt(
    code: String,
    session_manager: &SessionManager,
) -> Result<(), CliError> {
    let session = session_manager.require_auth()?;

    let unlock_config = session_manager
        .fetch_unlock_config(&session.server_url)
        .await?
        .ok_or_else(|| {
            CliError::configuration("SOS unlock validation is not configured. Provide HYBRIDCIPHER_UNLOCK_PUBLIC_KEY or use a build with a bundled SOS unlock key.".to_string())
        })?;

    validate_unlock_code(&code, &session.user_id, &unlock_config)?;

    let password =
        ui::prompts::password("Enter account password (required to unwrap recovery backup)")?;
    if password.trim().is_empty() {
        return Err(CliError::invalid_input(
            "Password cannot be empty for recovery".to_string(),
        ));
    }
    let recovery_input = ui::prompts::password("Enter recovery code")?;
    let recovery_secret = parse_recovery_code(&recovery_input)?;

    let artifact_path = session_manager.recovery_artifact_path()?;
    let artifact = match BackupArtifact::load_from_path(&artifact_path) {
        Ok(local) => local,
        Err(_) => {
            ui::dim("Local backup artifact not found; attempting server fetch...");
            let session = session_manager.require_auth()?;
            match crate::commands::recovery::download_backup_artifact(session_manager, &session)
                .await
            {
                Ok(remote) => {
                    remote.save_to_path(&artifact_path)?;
                    ui::dim(&format!(
                        "Downloaded recovery backup to {}",
                        artifact_path.display()
                    ));
                    remote
                }
                Err(err) => {
                    return Err(CliError::not_found(format!(
                        "Unable to load recovery backup: {}",
                        err
                    )))
                }
            }
        }
    };
    let entries = artifact.decrypt_entries(&password, recovery_secret.as_ref())?;
    if entries.is_empty() {
        return Err(CliError::not_found(
            "Recovery backup contains no epoch entries".to_string(),
        ));
    }

    let k_file = artifact.unwrap_file_key(&password, recovery_secret.as_ref())?;
    let epoch_key = artifact.derive_epoch_key(k_file.as_ref())?;
    crate::commands::recovery::persist_writer_material(
        session_manager,
        &session.device_id,
        crate::commands::recovery::slice_to_key(k_file.as_ref())?,
        &epoch_key,
    )?;

    let mut grouped: HashMap<Uuid, Vec<RecoveryEpochSecret>> = HashMap::new();
    for entry in entries {
        grouped
            .entry(entry.group_id)
            .or_default()
            .push(RecoveryEpochSecret {
                epoch_number: entry.epoch_number,
                epoch_uuid: entry.epoch_uuid,
                created_at: entry.created_at,
                is_active: entry.is_active,
                file_count: 0,
                encryption_key_b64: entry.encryption_key_b64,
            });
    }

    let client = session_manager.create_client().await?;
    let mut imported_groups = 0usize;
    for (group_id, epochs) in grouped {
        let capsule = RecoveryCapsulePlain {
            group_id,
            generated_at: Utc::now(),
            epochs,
        };
        client
            .import_recovery_capsule(&capsule)
            .await
            .map_err(|e| {
                CliError::operation(format!("Failed to import epochs for {}: {}", group_id, e))
            })?;
        imported_groups += 1;
    }

    ui::success(&format!(
        "SOS recovery imported epoch keys for {} group(s)",
        imported_groups
    ));
    ui::info("Next, decrypt your encrypted file or directory with: hybridcipher decrypt <PATH>");

    Ok(())
}
