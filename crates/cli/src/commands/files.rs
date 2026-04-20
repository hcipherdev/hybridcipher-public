use crate::{
    commands::file_ops::{
        append_timestamp_to_name, capture_directory_mtime, current_timestamp,
        decrypt_parsed_file_to_path, default_encrypted_path, default_in_place_decrypted_path,
        default_safe_decrypt_dir_root, default_safe_decrypt_file_path,
        detect_existing_encryption_metadata, encrypt_file_to_path,
        enforce_directory_ciphertext_policy, ensure_directory, ensure_hidden_subdir,
        parse_encrypted_file, preserve_directory_mtime, preserve_file_mtime,
        scan_directory_ciphertext_groups, DirectoryCiphertextGroup, DirectoryCiphertextPolicyError,
        ExistingEncryptionMetadata, LocalClient, TraversalMode,
    },
    error::CliError,
    session::SessionManager,
    ui,
};
use std::{
    collections::HashSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use uuid::Uuid;

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessingMode {
    Safe,
    InPlace,
}

#[derive(Default)]
struct TraversalWarnings {
    messages: Vec<String>,
}

impl TraversalWarnings {
    fn warn(&mut self, message: String) {
        self.messages.push(message);
    }

    fn emit(&self, context: &str) {
        if self.messages.is_empty() {
            return;
        }
        ui::warning(&format!(
            "{} completed with {} warning(s):",
            context,
            self.messages.len()
        ));
        for warning in self.messages.iter().take(5) {
            ui::warning(&format!("  - {}", warning));
        }
        if self.messages.len() > 5 {
            ui::warning(&format!(
                "  - ... {} more warning(s)",
                self.messages.len() - 5
            ));
        }
    }
}
/// Handle file encryption command
pub async fn handle_encrypt(
    file_path: PathBuf,
    output_path: Option<PathBuf>,
    in_place: bool,
    strict: bool,
    session: &SessionManager,
) -> Result<(), CliError> {
    if in_place && output_path.is_some() {
        return Err(CliError::file_operation(
            "--output cannot be combined with --in-place for encryption",
        ));
    }

    let mode = if in_place {
        ui::warning("In-place encryption will remove originals without creating safety backups.");
        ui::warning(
            "This action cannot be undone unless you keep your own copies. Continue?", // warn before confirmation
        );
        if !ui::prompts::confirm("Proceed with in-place encryption?")? {
            ui::info("Operation cancelled by user.");
            return Ok(());
        }
        ProcessingMode::InPlace
    } else {
        ProcessingMode::Safe
    };

    let client = session
        .create_local_client()
        .await
        .map_err(|e| CliError::authentication(format!("Failed to create local client: {}", e)))?;

    if file_path.is_dir() {
        let traversal_mode = if strict {
            TraversalMode::Strict
        } else {
            TraversalMode::BestEffort
        };
        let mut warnings = TraversalWarnings::default();
        let active_group = session.ensure_current_group().await?;
        let active_epoch = client.current_epoch_id().await.ok_or_else(|| {
            CliError::file_operation(
                "Active epoch is unavailable. This device needs epoch keys.\n\
                Options:\n\
                1. If this is a new device, in an existing device, run: hybridcipher issue-welcome --device <YOUR_DEVICE_ID>\n\
                   Then run: hybridcipher process-welcome-messages\n\
                2. If you have a recovery code, run: hybridcipher recovery fetch",
            )
        })?;

        let ciphertext_groups =
            scan_directory_ciphertext_groups(&file_path, traversal_mode, &mut warnings.messages)?;
        let matching_group = enforce_directory_ciphertext_policy(
            &ciphertext_groups,
            Some(active_group),
            Some(active_epoch),
        )
        .map_err(|err| handle_directory_ciphertext_error(&file_path, err))?;
        let skip_paths = build_skip_set_for_dir(&file_path, matching_group.as_ref());

        if mode == ProcessingMode::Safe {
            if let Some(backup_path) = backup_directory(&file_path, traversal_mode, &mut warnings)?
            {
                ui::info(&format!("Backed up folder to {}", backup_path.display()));
            }
        }

        let count = encrypt_directory(
            &client,
            &file_path,
            output_path.as_deref(),
            mode,
            &skip_paths,
            traversal_mode,
            &mut warnings,
        )
        .await?;
        if count == 0 {
            ui::warning(&format!(
                "No files found to encrypt in {}",
                file_path.display()
            ));
        } else {
            ui::success(&format!(
                "Encrypted {} file(s) under {}",
                count,
                file_path.display()
            ));
        }
        warnings.emit("Directory encryption");
        Ok(())
    } else {
        if guard_against_double_encryption(&file_path, session).await? {
            return Ok(());
        }

        if mode == ProcessingMode::Safe {
            if let Some(backup_path) = backup_file(&file_path)? {
                ui::info(&format!("Backed up file to {}", backup_path.display()));
            }
        }

        encrypt_single_file(&client, &file_path, output_path, mode, None, false).await?;
        Ok(())
    }
}

fn build_skip_set_for_dir(
    dir_path: &Path,
    matching_group: Option<&DirectoryCiphertextGroup>,
) -> HashSet<PathBuf> {
    if let Some(group) = matching_group {
        if !group.files.is_empty() {
            ui::info(&format!(
                "{} already contains {} encrypted file(s) (group {}, epoch {}). They will be left untouched.",
                dir_path.display(),
                group.files.len(),
                format_group_label(group.group_id),
                group.epoch_id
            ));
        }
        return group
            .files
            .iter()
            .map(|entry| entry.relative_path.clone())
            .collect();
    }

    HashSet::new()
}

fn handle_directory_ciphertext_error(
    dir_path: &Path,
    err: DirectoryCiphertextPolicyError,
) -> CliError {
    match err {
        DirectoryCiphertextPolicyError::MissingActiveContext => CliError::file_operation(
            "Active group or epoch is unknown; select a group and ensure it has an initialized epoch before encrypting folders.",
        ),
        DirectoryCiphertextPolicyError::Mixed(groups) => {
            ui::warning(&format!(
                "{} contains encrypted files from multiple groups or epochs.",
                dir_path.display()
            ));
            render_ciphertext_group_warnings(&groups);
            ui::warning(
                "This folder may belong to a different group or user. Move the encrypted files out before trying again.",
            );
            CliError::file_operation(format!(
                "Aborting encryption for {} due to mixed ciphertext metadata",
                dir_path.display()
            ))
        }
        DirectoryCiphertextPolicyError::ForeignContext {
            offending,
            expected_group,
            expected_epoch,
        } => {
            ui::warning(&format!(
                "{} already contains encrypted file(s) for group {} epoch {}, but your active context is group {} epoch {}.",
                dir_path.display(),
                format_group_label(offending.group_id),
                offending.epoch_id,
                expected_group,
                expected_epoch
            ));
            render_ciphertext_group_warnings(&[offending.clone()]);
            ui::warning(
                "This folder may belong to a different group or user. Move the encrypted files out before trying again.",
            );
            CliError::file_operation(format!(
                "Aborting encryption for {} due to conflicting ciphertext metadata",
                dir_path.display()
            ))
        }
    }
}

fn render_ciphertext_group_warnings(groups: &[DirectoryCiphertextGroup]) {
    for group in groups {
        ui::warning(&format!(
            "- {} file(s) use group {} epoch {}",
            group.files.len(),
            format_group_label(group.group_id),
            group.epoch_id
        ));
        render_ciphertext_samples(group);
    }
}

fn render_ciphertext_samples(group: &DirectoryCiphertextGroup) {
    for sample in group.files.iter().take(3) {
        ui::dim(&format!("    {}", sample.absolute_path.display()));
    }
    if group.files.len() > 3 {
        ui::dim(&format!("    ... {} more", group.files.len() - 3));
    }
}

fn format_group_label(group_id: Option<Uuid>) -> String {
    group_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

async fn guard_against_double_encryption(
    file_path: &Path,
    session: &SessionManager,
) -> Result<bool, CliError> {
    let Some(existing_metadata) = detect_existing_encryption_metadata(file_path)? else {
        return Ok(false);
    };

    let active_group = match session.current_group_id().await? {
        Some(id) => Some(id),
        None => match session.ensure_current_group().await {
            Ok(id) => Some(id),
            Err(err) => {
                ui::warning(&format!(
                    "Detected HybridCipher metadata in \"{}\" but could not determine the active group: {}",
                    file_path.display(),
                    err
                ));
                ui::warning("Treating the existing ciphertext as belonging to a different group.");
                None
            }
        },
    };

    if let Some(group_id) = active_group {
        if existing_metadata.group_id == Some(group_id) {
            ui::warning(&format!(
                "\"{}\" is already encrypted for the active group ({}) at epoch {}.",
                file_path.display(),
                group_id,
                existing_metadata.epoch_id
            ));
            ui::info(&format!(
                "Existing ciphertext file_id: {}",
                existing_metadata.file_id
            ));
            ui::info("Aborting to avoid corrupting the already encrypted file.");
            return Ok(true);
        }
    }

    warn_about_double_encryption(file_path, &existing_metadata, active_group)
}

fn warn_about_double_encryption(
    file_path: &Path,
    metadata: &ExistingEncryptionMetadata,
    active_group: Option<Uuid>,
) -> Result<bool, CliError> {
    let existing_group_label = metadata
        .group_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "unknown origin".to_string());

    match active_group {
        Some(current_group) => {
            ui::warning(&format!(
        "\"{}\" is already encrypted for group {} (epoch {}) while your active group is {}.",
        file_path.display(),
        existing_group_label,
        metadata.epoch_id,
        current_group
    ));
        }
        None => {
            ui::warning(&format!(
                "\"{}\" already contains encrypted HybridCipher data (group: {}, epoch {}).",
                file_path.display(),
                existing_group_label,
                metadata.epoch_id
            ));
            ui::dim(
                "Active group could not be determined; assuming it differs from the existing ciphertext.",
            );
        }
    }

    ui::info(&format!(
        "Existing ciphertext file_id: {}",
        metadata.file_id
    ));
    ui::warning(
        "Encrypting again will add another layer and may cause decryption failures for other members.",
    );

    if ui::prompts::confirm("Proceed and add another encryption layer to this file?")? {
        Ok(false)
    } else {
        ui::info("Operation cancelled by user.");
        Ok(true)
    }
}

async fn encrypt_single_file(
    client: &LocalClient,
    file_path: &Path,
    output_override: Option<PathBuf>,
    mode: ProcessingMode,
    aad_label_override: Option<String>,
    quiet_logs: bool,
) -> Result<PathBuf, CliError> {
    let verbose = std::env::var("HYBRIDCIPHER_VERBOSE").is_ok();
    let show_logs = !quiet_logs || verbose;

    if client.is_path_excluded(file_path) {
        return Err(CliError::file_operation(format!(
            "{} is excluded from encryption by configuration",
            file_path.display()
        )));
    }

    let parent_dir = file_path.parent().map(|dir| dir.to_path_buf());
    let parent_mtime = parent_dir
        .as_ref()
        .and_then(|dir| capture_directory_mtime(dir));

    let file_size = fs::metadata(file_path)
        .map_err(|e| {
            CliError::storage(format!("Failed to inspect {}: {}", file_path.display(), e))
        })?
        .len();

    if show_logs {
        ui::progress::display::display_file_status(
            "Encrypting",
            &format!("{}", file_path.display()),
            &format!("{} bytes", file_size),
        );
    }

    let outcome = encrypt_file_to_path(
        client,
        file_path,
        output_override.as_deref(),
        aad_label_override.as_deref(),
    )
    .await?;
    preserve_file_mtime(file_path, &outcome.encrypted_path)?;

    // Preserve the original file's modification time
    fs::remove_file(file_path).map_err(|e| {
        CliError::storage(format!(
            "Failed to remove original file {}: {}",
            file_path.display(),
            e
        ))
    })?;

    if show_logs {
        ui::success(&format!(
            "Encrypted {} -> {} (epoch {})",
            file_path.display(),
            outcome.encrypted_path.display(),
            outcome.epoch_id
        ));
    }

    if let Some(dir) = parent_dir.as_deref() {
        preserve_directory_mtime(dir, parent_mtime);
    }

    if mode == ProcessingMode::Safe && show_logs {
        ui::info("Original safely backed up before removal.");
    }

    Ok(outcome.encrypted_path)
}

async fn encrypt_directory(
    client: &LocalClient,
    dir_path: &Path,
    output_root: Option<&Path>,
    mode: ProcessingMode,
    skip_paths: &HashSet<PathBuf>,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<usize, CliError> {
    let verbose = std::env::var("HYBRIDCIPHER_VERBOSE").is_ok();
    let original_dir_mtime = capture_directory_mtime(dir_path);

    if let Some(root) = output_root {
        ensure_directory(root)?;
    }

    let total_files = count_regular_files(dir_path, skip_paths, client, traversal_mode, warnings)?;
    let progress_bar = if total_files > 0 {
        let pb = ui::progress::create_file_progress(total_files as u64, "encryption");
        ui::progress::update_progress_with_message(&pb, 0, "Preparing files...");
        Some(pb)
    } else {
        None
    };

    let mut stack = vec![dir_path.to_path_buf()];
    let mut processed = 0usize;

    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                let message = format!("Failed to read directory {}: {}", current.display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let message = format!("Failed to read entry in {}: {}", current.display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let path = entry.path();

            if file_type.is_dir() {
                if client.is_path_excluded(&path) {
                    if verbose {
                        ui::info(&format!(
                            "Skipping {} (excluded by configuration)",
                            path.display()
                        ));
                    }
                    continue;
                }
                stack.push(path.clone());
                if let Some(root) = output_root {
                    let relative = match path.strip_prefix(dir_path) {
                        Ok(relative) => relative,
                        Err(_) => {
                            let message = format!(
                                "Encountered directory {} outside root {}",
                                path.display(),
                                dir_path.display()
                            );
                            if traversal_mode.is_strict() {
                                return Err(CliError::file_operation(message));
                            }
                            warnings.warn(message);
                            continue;
                        }
                    };
                    if let Err(err) = ensure_directory(&root.join(relative)) {
                        let message = format!(
                            "Failed to create output directory for {}: {}",
                            path.display(),
                            err
                        );
                        if traversal_mode.is_strict() {
                            return Err(err);
                        }
                        warnings.warn(message);
                    }
                }
            } else if file_type.is_file() {
                let relative = match path.strip_prefix(dir_path) {
                    Ok(relative) => relative,
                    Err(_) => {
                        let message = format!(
                            "Encountered file {} outside root {}",
                            path.display(),
                            dir_path.display()
                        );
                        if traversal_mode.is_strict() {
                            return Err(CliError::file_operation(message));
                        }
                        warnings.warn(message);
                        continue;
                    }
                };

                if client.is_path_excluded(&path) {
                    ui::info(&format!(
                        "Skipping {} (excluded by configuration)",
                        path.display()
                    ));
                    continue;
                }

                if skip_paths.contains(relative) {
                    continue;
                }

                let output_override = output_root.map(|root| {
                    let base = root.join(relative);
                    default_encrypted_path(&base)
                });

                // Preserve relative path context so exclusion checks see parent directories.
                let aad_label = Some(relative.to_string_lossy().to_string());

                match encrypt_single_file(client, &path, output_override, mode, aad_label, !verbose)
                    .await
                {
                    Ok(_) => {
                        processed += 1;
                    }
                    Err(err) => {
                        let message = format!("Failed to encrypt {}: {}", path.display(), err);
                        if traversal_mode.is_strict() {
                            return Err(err);
                        }
                        warnings.warn(message);
                        continue;
                    }
                }
                if let Some(pb) = progress_bar.as_ref() {
                    ui::progress::update_progress_with_message(
                        pb,
                        processed as u64,
                        &format!("{} ({}/{})", path.display(), processed, total_files),
                    );
                }
            }
        }
    }

    if let Some(pb) = progress_bar.as_ref() {
        ui::progress::finish_progress_with_result(pb, true, "Directory encryption complete");
    }

    preserve_directory_mtime(dir_path, original_dir_mtime);

    Ok(processed)
}

fn count_regular_files(
    dir_path: &Path,
    skip_paths: &HashSet<PathBuf>,
    client: &LocalClient,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<usize, CliError> {
    let mut stack = vec![dir_path.to_path_buf()];
    let mut count = 0usize;

    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                let message = format!("Failed to read directory {}: {}", current.display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let message = format!("Failed to read entry in {}: {}", current.display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let path = entry.path();

            if file_type.is_dir() {
                if client.is_path_excluded(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                if client.is_path_excluded(&path) {
                    continue;
                }

                let relative = match path.strip_prefix(dir_path) {
                    Ok(relative) => relative,
                    Err(_) => {
                        let message = format!(
                            "Encountered file {} outside root {}",
                            path.display(),
                            dir_path.display()
                        );
                        if traversal_mode.is_strict() {
                            return Err(CliError::file_operation(message));
                        }
                        warnings.warn(message);
                        continue;
                    }
                };

                if skip_paths.contains(relative) {
                    continue;
                }

                count += 1;
            }
        }
    }

    Ok(count)
}

fn count_encrypted_files(
    dir_path: &Path,
    client: &LocalClient,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<usize, CliError> {
    let mut stack = vec![dir_path.to_path_buf()];
    let mut count = 0usize;

    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                let message = format!("Failed to read directory {}: {}", current.display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let message = format!("Failed to read entry in {}: {}", current.display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let path = entry.path();

            if file_type.is_dir() {
                if client.is_path_excluded(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                if client.is_path_excluded(&path) {
                    continue;
                }
                if path.extension() == Some(OsStr::new("encrypted")) {
                    count += 1;
                }
            }
        }
    }

    Ok(count)
}

/// Handle file decryption command
pub async fn handle_decrypt(
    file_path: PathBuf,
    output_path: Option<PathBuf>,
    in_place: bool,
    strict: bool,
    session: &SessionManager,
) -> Result<(), CliError> {
    if in_place && output_path.is_some() {
        return Err(CliError::file_operation(
            "--output cannot be combined with --in-place for decryption",
        ));
    }

    let mode = if in_place {
        ui::warning(
            "In-place decryption will overwrite current encrypted data and remove encrypted files.",
        );
        ProcessingMode::InPlace
    } else {
        ProcessingMode::Safe
    };

    let client = session
        .create_local_client()
        .await
        .map_err(|e| CliError::authentication(format!("Failed to create local client: {}", e)))?;

    if file_path.is_dir() {
        let traversal_mode = if strict {
            TraversalMode::Strict
        } else {
            TraversalMode::BestEffort
        };
        let mut warnings = TraversalWarnings::default();
        let target_root = match (mode, output_path.as_deref()) {
            (ProcessingMode::Safe, Some(root)) => {
                ensure_directory(root)?;
                Some(root.to_path_buf())
            }
            (ProcessingMode::Safe, None) => Some(default_safe_decrypt_dir_root(&file_path)?),
            (ProcessingMode::InPlace, Some(root)) => {
                ensure_directory(root)?;
                Some(root.to_path_buf())
            }
            (ProcessingMode::InPlace, None) => None,
        };

        let count = decrypt_directory(
            &client,
            &file_path,
            target_root.as_deref(),
            mode,
            traversal_mode,
            &mut warnings,
        )
        .await?;
        if count == 0 {
            return Err(CliError::format(format!(
                "\"{}\" is not encrypted; no need to decrypt.",
                file_path.display()
            )));
        }
        ui::success(&format!(
            "Decrypted {} file(s) from {}",
            count,
            file_path.display()
        ));
        if let Some(root) = target_root {
            ui::info(&format!("Decrypted content saved under {}", root.display()));
        }
        warnings.emit("Folder decryption");
        Ok(())
    } else {
        decrypt_single_file(&client, &file_path, output_path, mode).await
    }
}

async fn decrypt_single_file(
    client: &LocalClient,
    file_path: &Path,
    output_override: Option<PathBuf>,
    mode: ProcessingMode,
) -> Result<(), CliError> {
    if file_path.extension() != Some(OsStr::new("encrypted")) {
        return Err(CliError::format(format!(
            "\"{}\" is not encrypted; no need to decrypt.",
            file_path.display()
        )));
    }

    let parsed = parse_encrypted_file(file_path)?;

    let parent_dir = file_path.parent().map(|dir| dir.to_path_buf());
    let parent_mtime = parent_dir
        .as_ref()
        .and_then(|dir| capture_directory_mtime(dir));

    ui::info(&format!("File ID: {}", parsed.metadata.file_id));
    ui::info(&format!("Epoch: {}", parsed.metadata.epoch_id));
    ui::info(&format!(
        "Encrypted size: {} bytes",
        parsed.metadata.encrypted_content.len()
    ));

    let output_path = match output_override {
        Some(custom) => custom,
        None if mode == ProcessingMode::Safe => default_safe_decrypt_file_path(&parsed)?,
        None => default_in_place_decrypted_path(file_path, &parsed),
    };

    let outcome = decrypt_parsed_file_to_path(client, file_path, parsed, Some(output_path)).await?;

    if mode == ProcessingMode::InPlace {
        fs::remove_file(file_path).map_err(|e| {
            CliError::storage(format!(
                "Failed to remove encrypted source {}: {}",
                file_path.display(),
                e
            ))
        })?;

        if let Some(dir) = parent_dir.as_deref() {
            preserve_directory_mtime(dir, parent_mtime);
        }
    }

    ui::success(&format!(
        "Decrypted {} -> {} (epoch {})",
        file_path.display(),
        outcome.output_path.display(),
        outcome.epoch_id
    ));

    Ok(())
}

async fn decrypt_directory(
    client: &LocalClient,
    dir_path: &Path,
    output_root: Option<&Path>,
    mode: ProcessingMode,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<usize, CliError> {
    let verbose = std::env::var("HYBRIDCIPHER_VERBOSE").is_ok();

    if let Some(root) = output_root {
        ensure_directory(root)?;
    }

    let mut stack = vec![dir_path.to_path_buf()];
    let mut decrypted = 0usize;
    let total_encrypted = count_encrypted_files(dir_path, client, traversal_mode, warnings)?;
    let progress_bar = if total_encrypted > 0 {
        let pb = ui::progress::create_file_progress(total_encrypted as u64, "decrypt");
        ui::progress::update_progress_with_message(&pb, 0, "Preparing to decrypt...");
        Some(pb)
    } else {
        None
    };
    // Track directory mtimes only when in-place decryption might mutate them
    let mut dir_mtimes: Option<Vec<(PathBuf, Option<SystemTime>)>> =
        if mode == ProcessingMode::InPlace {
            Some(Vec::new())
        } else {
            None
        };

    while let Some(current) = stack.pop() {
        if let Some(mtimes) = dir_mtimes.as_mut() {
            // Capture this directory's mtime before processing its contents
            let current_mtime = capture_directory_mtime(&current);
            mtimes.push((current.clone(), current_mtime));
        }

        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                let message = format!("Failed to read directory {}: {}", current.display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let message = format!("Failed to read entry in {}: {}", current.display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                    if traversal_mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.warn(message);
                    continue;
                }
            };
            let path = entry.path();

            if file_type.is_dir() {
                if client.is_path_excluded(&path) {
                    if verbose {
                        ui::info(&format!(
                            "Skipping {} (excluded by configuration)",
                            path.display()
                        ));
                    }
                    continue;
                }
                stack.push(path.clone());
                if let Some(root) = output_root {
                    if let Ok(relative) = path.strip_prefix(dir_path) {
                        if let Err(err) = ensure_directory(&root.join(relative)) {
                            let message = format!(
                                "Failed to create output directory for {}: {}",
                                path.display(),
                                err
                            );
                            if traversal_mode.is_strict() {
                                return Err(err);
                            }
                            warnings.warn(message);
                        }
                    } else {
                        let message = format!(
                            "Encountered directory {} outside root {}",
                            path.display(),
                            dir_path.display()
                        );
                        if traversal_mode.is_strict() {
                            return Err(CliError::file_operation(message));
                        }
                        warnings.warn(message);
                        continue;
                    }
                }
            } else if file_type.is_file() {
                if path.extension() != Some(OsStr::new("encrypted")) {
                    if verbose {
                        ui::info(&format!("Skipping {} (not encrypted)", path.display()));
                    }
                    continue;
                }

                let parsed = match parse_encrypted_file(&path) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let message =
                            format!("Failed to parse encrypted file {}: {}", path.display(), err);
                        if traversal_mode.is_strict() {
                            return Err(err);
                        }
                        warnings.warn(message);
                        continue;
                    }
                };
                let relative = match path.strip_prefix(dir_path) {
                    Ok(relative) => relative,
                    Err(_) => {
                        let message = format!(
                            "Unable to derive relative path for {} from root {}",
                            path.display(),
                            dir_path.display()
                        );
                        if traversal_mode.is_strict() {
                            return Err(CliError::file_operation(message));
                        }
                        warnings.warn(message);
                        continue;
                    }
                };

                let output_override = match output_root {
                    Some(root) => {
                        let parent_rel = relative.parent();
                        let base_dir = if let Some(parent_rel) = parent_rel {
                            root.join(parent_rel)
                        } else {
                            root.to_path_buf()
                        };
                        ensure_directory(&base_dir)?;
                        let file_name = parsed
                            .original_name
                            .as_deref()
                            .map(|name| name.to_string())
                            .unwrap_or_else(|| derive_plain_name_from_encrypted(&path));
                        Some(base_dir.join(file_name))
                    }
                    None => None,
                };

                let outcome =
                    match decrypt_parsed_file_to_path(client, &path, parsed, output_override).await
                    {
                        Ok(outcome) => outcome,
                        Err(err) => {
                            let message = format!("Failed to decrypt {}: {}", path.display(), err);
                            if traversal_mode.is_strict() {
                                return Err(err);
                            }
                            warnings.warn(message);
                            continue;
                        }
                    };

                if mode == ProcessingMode::InPlace {
                    if let Err(e) = fs::remove_file(&path) {
                        let message = format!(
                            "Failed to remove encrypted source {}: {}",
                            path.display(),
                            e
                        );
                        if traversal_mode.is_strict() {
                            return Err(CliError::storage(message));
                        }
                        warnings.warn(message);
                    }
                }

                if verbose {
                    ui::success(&format!(
                        "Decrypted {} -> {}",
                        path.display(),
                        outcome.output_path.display()
                    ));
                }
                decrypted += 1;
                if let Some(pb) = progress_bar.as_ref() {
                    ui::progress::update_progress_with_message(
                        pb,
                        decrypted as u64,
                        &format!("{} ({}/{})", path.display(), decrypted, total_encrypted),
                    );
                }
            }
        }
    }

    if let Some(pb) = progress_bar.as_ref() {
        ui::progress::finish_progress_with_result(
            pb,
            decrypted == total_encrypted,
            "Folder decryption complete",
        );
    }

    // Restore all directory mtimes in reverse order (deepest first)
    if let Some(mtimes) = dir_mtimes {
        for (dir, mtime) in mtimes.iter().rev() {
            preserve_directory_mtime(dir, *mtime);
        }
    }

    Ok(decrypted)
}

fn backup_file(path: &Path) -> Result<Option<PathBuf>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let backup_dir = ensure_hidden_subdir(&["backups", "files"])?;
    let timestamp = current_timestamp();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let timestamped = append_timestamp_to_name(file_name, &timestamp);
    let backup_path = backup_dir.join(timestamped);
    fs::copy(path, &backup_path).map_err(|e| {
        CliError::storage(format!("Failed to backup file {}: {}", path.display(), e))
    })?;
    Ok(Some(backup_path))
}

fn backup_directory(
    path: &Path,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<Option<PathBuf>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    let backup_root = ensure_hidden_subdir(&["backups", "folders"])?;
    let dir_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder");
    let target_dir = backup_root.join(append_timestamp_to_name(dir_name, &current_timestamp()));
    copy_dir_recursive(path, &target_dir, traversal_mode, warnings)?;
    Ok(Some(target_dir))
}

fn copy_dir_recursive(
    src: &Path,
    dst: &Path,
    traversal_mode: TraversalMode,
    warnings: &mut TraversalWarnings,
) -> Result<(), CliError> {
    if let Err(err) = ensure_directory(dst) {
        let message = format!(
            "Failed to create backup directory {}: {}",
            dst.display(),
            err
        );
        if traversal_mode.is_strict() {
            return Err(err);
        }
        warnings.warn(message);
        return Ok(());
    }
    let entries = match fs::read_dir(src) {
        Ok(entries) => entries,
        Err(e) => {
            let message = format!("Failed to read directory {}: {}", src.display(), e);
            if traversal_mode.is_strict() {
                return Err(CliError::storage(message));
            }
            warnings.warn(message);
            return Ok(());
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                let message = format!("Failed to read entry in {}: {}", src.display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(e) => {
                let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
                continue;
            }
        };
        let target_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&entry.path(), &target_path, traversal_mode, warnings)?;
        } else if file_type.is_file() {
            if let Some(parent) = target_path.parent() {
                if let Err(err) = ensure_directory(parent) {
                    let message = format!(
                        "Failed to create backup directory {}: {}",
                        parent.display(),
                        err
                    );
                    if traversal_mode.is_strict() {
                        return Err(err);
                    }
                    warnings.warn(message);
                    continue;
                }
            }
            if let Err(e) = fs::copy(entry.path(), &target_path) {
                let message = format!(
                    "Failed to copy {} to {}: {}",
                    entry.path().display(),
                    target_path.display(),
                    e
                );
                if traversal_mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.warn(message);
            }
        } else {
            ui::warning(&format!(
                "Skipping unsupported filesystem entry {} during backup",
                entry.path().display()
            ));
        }
    }

    Ok(())
}

fn derive_plain_name_from_encrypted(path: &Path) -> String {
    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
        if stem.ends_with(".encrypted") {
            stem.trim_end_matches(".encrypted").to_string()
        } else {
            stem.to_string()
        }
    } else {
        "decrypted_file".to_string()
    }
}
