use crate::error::{map_missing_welcome_error, CliError};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use filetime::{set_file_mtime, set_file_times, FileTime};
use hybridcipher_client::{
    file::encrypt::SparseFileMetadata,
    file::{write_encrypted_file as write_encrypted_file_with_header, SerializedEncryptedHeader},
    network::MockNetwork,
    storage::LocalFsStorage,
    EncryptedFileMetadata,
};
use serde_json::{self, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::fs as async_fs;
use uuid::Uuid;

pub(crate) type LocalClient =
    hybridcipher_client::state::client::Client<LocalFsStorage, MockNetwork>;

const ENCRYPTED_FILE_SEPARATOR: &str = "\n---ENCRYPTED_DATA---\n";
const METADATA_SCAN_LIMIT: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TraversalMode {
    BestEffort,
    Strict,
}

impl TraversalMode {
    pub(crate) fn is_strict(self) -> bool {
        matches!(self, TraversalMode::Strict)
    }
}

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EncryptFileOutcome {
    pub encrypted_path: PathBuf,
    pub file_id: String,
    pub epoch_id: u64,
    pub group_id: Option<Uuid>,
    pub original_size: u64,
    pub encrypted_size: u64,
    pub original_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub header_version: u32,
    pub wrapped_file_key: Option<Vec<u8>>,
    pub key_wrap_nonce: Option<Vec<u8>>,
    pub key_wrap_aad_hash: Option<Vec<u8>>,
    pub content_nonce: Option<Vec<u8>>,
    pub content_chunk_size: Option<u64>,
    pub plaintext_hash: [u8; 32],
}

pub(crate) async fn encrypt_file_to_path(
    client: &LocalClient,
    source_path: &Path,
    output_override: Option<&Path>,
    aad_label_override: Option<&str>,
) -> Result<EncryptFileOutcome, CliError> {
    let plaintext = async_fs::read(source_path).await.map_err(|err| {
        CliError::storage(format!(
            "Failed to read {} for encryption: {}",
            source_path.display(),
            err
        ))
    })?;

    let mut plaintext_hash = [0u8; 32];
    plaintext_hash.copy_from_slice(&Sha256::digest(&plaintext));

    let aad_label = aad_label_override
        .map(|label| label.to_string())
        .unwrap_or_else(|| source_path.to_string_lossy().to_string());

    let encrypted = client
        .encrypt_file(&aad_label, &plaintext)
        .await
        .map_err(|err| CliError::encryption(map_missing_welcome_error(err.to_string())))?;

    let mut target_path = output_override
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| default_encrypted_path(source_path));
    target_path = ensure_encrypted_suffix(target_path, source_path);

    if let Some(parent) = target_path.parent() {
        ensure_directory(parent)?;
    }

    let original_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string());

    let wrapped_file_key = encrypted.wrapped_file_key.as_ref().ok_or_else(|| {
        CliError::format("Missing wrapped_file_key in encryption metadata".to_string())
    })?;
    let key_wrap_nonce = encrypted.key_wrap_nonce.as_ref().ok_or_else(|| {
        CliError::format("Missing key_wrap_nonce in encryption metadata".to_string())
    })?;
    let key_wrap_aad_hash = encrypted.key_wrap_aad_hash.as_ref().ok_or_else(|| {
        CliError::format("Missing key_wrap_aad_hash in encryption metadata".to_string())
    })?;
    let content_nonce = encrypted.content_nonce.as_ref().ok_or_else(|| {
        CliError::format("Missing content_nonce in encryption metadata".to_string())
    })?;

    let header = SerializedEncryptedHeader {
        file_id: &encrypted.file_id,
        file_path: &encrypted.file_path,
        group_id: encrypted.group_id,
        epoch_id: encrypted.epoch_id,
        header_version: encrypted.header_version.unwrap_or(1),
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size: encrypted.content_chunk_size,
        original_size: encrypted.content_size,
        encrypted_size: encrypted.encrypted_size,
        encrypted_at: encrypted.created_at,
        original_name: original_name.as_deref(),
        platform_metadata: encrypted.platform_metadata.as_ref(),
        sparse_metadata: encrypted.sparse_metadata.as_ref(),
    };

    write_encrypted_file_with_header(&target_path, &header, &encrypted.encrypted_content)
        .map_err(|err| CliError::format(err.to_string()))?;

    let outcome = EncryptFileOutcome {
        encrypted_path: target_path,
        file_id: encrypted.file_id.clone(),
        epoch_id: encrypted.epoch_id,
        group_id: encrypted.group_id,
        original_size: encrypted.content_size,
        encrypted_size: encrypted.encrypted_size,
        original_name,
        created_at: encrypted.created_at,
        header_version: encrypted.header_version.unwrap_or(1),
        wrapped_file_key: encrypted.wrapped_file_key.clone(),
        key_wrap_nonce: encrypted.key_wrap_nonce.clone(),
        key_wrap_aad_hash: encrypted.key_wrap_aad_hash.clone(),
        content_nonce: encrypted.content_nonce.clone(),
        content_chunk_size: encrypted.content_chunk_size,
        plaintext_hash,
    };

    Ok(outcome)
}

#[derive(Debug)]
pub(crate) struct ParsedEncryptedFile {
    pub metadata: EncryptedFileMetadata,
    pub original_name: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExistingEncryptionMetadata {
    pub file_id: String,
    pub group_id: Option<Uuid>,
    pub epoch_id: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct DirectoryEncryptedFile {
    pub absolute_path: PathBuf,
    pub relative_path: PathBuf,
    pub metadata: ExistingEncryptionMetadata,
}

#[derive(Debug, Clone)]
pub(crate) struct DirectoryCiphertextGroup {
    pub group_id: Option<Uuid>,
    pub epoch_id: u64,
    pub files: Vec<DirectoryEncryptedFile>,
}

#[derive(Debug, Clone)]
pub(crate) enum DirectoryCiphertextPolicyError {
    MissingActiveContext,
    Mixed(Vec<DirectoryCiphertextGroup>),
    ForeignContext {
        offending: DirectoryCiphertextGroup,
        expected_group: Uuid,
        expected_epoch: u64,
    },
}

pub(crate) fn parse_encrypted_file(path: &Path) -> Result<ParsedEncryptedFile, CliError> {
    let encrypted_content = fs::read(path)
        .map_err(|e| CliError::storage(format!("Failed to read {}: {}", path.display(), e)))?;
    let separator = ENCRYPTED_FILE_SEPARATOR.as_bytes();
    let sep_pos = encrypted_content
        .windows(separator.len())
        .position(|window| window == separator)
        .ok_or_else(|| CliError::format("Invalid encrypted file format: separator not found"))?;

    let metadata_bytes = &encrypted_content[..sep_pos];
    let ciphertext = encrypted_content[sep_pos + separator.len()..].to_vec();

    let json: Value = serde_json::from_slice(metadata_bytes)
        .map_err(|e| CliError::format(format!("Failed to parse metadata: {}", e)))?;

    let file_id = json["file_id"]
        .as_str()
        .ok_or_else(|| CliError::format("Missing file_id in metadata"))?
        .to_string();
    let epoch_id = json["epoch_id"]
        .as_u64()
        .ok_or_else(|| CliError::format("Missing epoch_id in metadata"))?;
    let content_size = json["file_size"]
        .as_u64()
        .or_else(|| json["original_size"].as_u64())
        .unwrap_or(0);
    let content_chunk_size = json.get("chunk_size").and_then(|v| v.as_u64());
    let original_name = json
        .get("original_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let stored_file_path = json
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::format("Missing file_path in metadata"))?;

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let header_version = json
        .get("header_version")
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let wrapped_file_key = decode_bytes(json.get("wrapped_file_key"));
    let key_wrap_nonce = decode_bytes(json.get("key_wrap_nonce"));
    let key_wrap_aad_hash = decode_bytes(json.get("key_wrap_aad_hash"));
    let content_nonce = decode_bytes(json.get("content_nonce"));

    let created_at = json
        .get("encrypted_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|| Utc::now());
    let platform_metadata = json
        .get("platform_metadata")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .filter(|metadata: &hybridcipher_client::PlatformFileMetadata| !metadata.is_empty());
    let sparse_metadata = json
        .get("sparse_metadata")
        .and_then(|value| serde_json::from_value::<SparseFileMetadata>(value.clone()).ok())
        .filter(SparseFileMetadata::is_effectively_sparse);

    let metadata = EncryptedFileMetadata {
        file_id,
        file_path: stored_file_path,
        group_id,
        epoch_id,
        header_version,
        wrapped_file_key,
        key_wrap_nonce,
        key_wrap_aad_hash,
        content_nonce,
        content_chunk_size,
        content_size,
        encrypted_size: ciphertext.len() as u64,
        created_at,
        platform_metadata,
        sparse_metadata,
        encrypted_content: ciphertext,
    };

    Ok(ParsedEncryptedFile {
        metadata,
        original_name,
    })
}

fn decode_bytes(val: Option<&Value>) -> Option<Vec<u8>> {
    if let Some(v) = val {
        if let Some(s) = v.as_str() {
            if let Ok(bytes) = B64.decode(s) {
                return Some(bytes);
            }
        }
        if let Ok(vec_bytes) = serde_json::from_value::<Vec<u8>>(v.clone()) {
            return Some(vec_bytes);
        }
    }
    None
}

#[derive(Debug)]
pub(crate) struct DecryptFileOutcome {
    pub output_path: PathBuf,
    pub epoch_id: u64,
}

pub(crate) async fn decrypt_parsed_file_to_path(
    client: &LocalClient,
    source_path: &Path,
    parsed: ParsedEncryptedFile,
    output_override: Option<PathBuf>,
) -> Result<DecryptFileOutcome, CliError> {
    let decrypted_data = client
        .decrypt_file(&parsed.metadata)
        .await
        .map_err(|e| CliError::decryption(map_missing_welcome_error(e.to_string())))?;

    let output_path =
        output_override.unwrap_or_else(|| default_decrypted_path(source_path, &parsed));

    if let Some(parent) = output_path.parent() {
        ensure_directory(parent)?;
    }

    fs::write(&output_path, decrypted_data).map_err(|e| {
        CliError::storage(format!(
            "Failed to write decrypted file {}: {}",
            output_path.display(),
            e
        ))
    })?;

    preserve_file_mtime(source_path, &output_path)?;

    Ok(DecryptFileOutcome {
        output_path,
        epoch_id: parsed.metadata.epoch_id,
    })
}

pub(crate) fn default_encrypted_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|s| s.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.encrypted")),
        _ => {
            let mut candidate = path.to_path_buf();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
            candidate.set_file_name(format!("{name}.encrypted"));
            candidate
        }
    }
}

pub(crate) fn ensure_encrypted_suffix(candidate: PathBuf, original: &Path) -> PathBuf {
    let has_suffix = candidate
        .extension()
        .map(|ext| ext == "encrypted")
        .unwrap_or(false);
    if has_suffix {
        return candidate;
    }

    let mut adjusted = candidate;
    let fallback = original
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("encrypted");

    if adjusted.file_name().is_some() {
        let name = adjusted
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback.to_string());
        adjusted.set_file_name(format!("{name}.encrypted"));
    } else {
        adjusted.push(format!("{fallback}.encrypted"));
    }

    adjusted
}

pub(crate) fn ensure_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir_all(path).map_err(|e| {
        CliError::storage(format!(
            "Failed to create directory {}: {}",
            path.display(),
            e
        ))
    })
}

pub(crate) fn ensure_hidden_subdir(parts: &[&str]) -> Result<PathBuf, CliError> {
    let home = dirs::home_dir().ok_or_else(|| {
        CliError::storage("Unable to determine home directory for HybridCipher backups".to_string())
    })?;
    let mut path = home.join(".hybridcipher");
    ensure_directory(&path)?;
    for part in parts {
        path = path.join(part);
        ensure_directory(&path)?;
    }
    Ok(path)
}

pub(crate) fn append_timestamp_to_name(name: &str, timestamp: &str) -> String {
    let path = Path::new(name);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let ext = path.extension().and_then(|s| s.to_str());

    match ext {
        Some(ext) if !ext.is_empty() => format!("{stem}_{timestamp}.{ext}"),
        _ => format!("{stem}_{timestamp}"),
    }
}

pub(crate) fn current_timestamp() -> String {
    Utc::now().format("%Y%m%dT%H%M%S").to_string()
}

pub(crate) fn default_decrypted_path(source: &Path, parsed: &ParsedEncryptedFile) -> PathBuf {
    if let Some(original_name) = parsed.original_name.as_deref() {
        source
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(original_name)
    } else {
        source.with_extension("decrypted")
    }
}

pub(crate) fn default_in_place_decrypted_path(
    source: &Path,
    parsed: &ParsedEncryptedFile,
) -> PathBuf {
    default_decrypted_path(source, parsed)
}

pub(crate) fn detect_existing_encryption_metadata(
    file_path: &Path,
) -> Result<Option<ExistingEncryptionMetadata>, CliError> {
    let mut file = fs::File::open(file_path).map_err(|e| {
        CliError::storage(format!(
            "Failed to open {} for metadata inspection: {}",
            file_path.display(),
            e
        ))
    })?;

    let mut buffer = Vec::new();
    file.by_ref()
        .take(METADATA_SCAN_LIMIT as u64)
        .read_to_end(&mut buffer)
        .map_err(|e| {
            CliError::storage(format!(
                "Failed to read {} for metadata inspection: {}",
                file_path.display(),
                e
            ))
        })?;

    let separator = ENCRYPTED_FILE_SEPARATOR.as_bytes();
    if buffer.len() < separator.len() {
        return Ok(None);
    }

    let Some(sep_pos) = buffer
        .windows(separator.len())
        .position(|window| window == separator)
    else {
        return Ok(None);
    };

    let metadata_bytes = &buffer[..sep_pos];
    if metadata_bytes.is_empty() {
        return Ok(None);
    }

    let json: Value = match serde_json::from_slice(metadata_bytes) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };

    let file_id = match json.get("file_id").and_then(|v| v.as_str()) {
        Some(id) => id.to_string(),
        None => return Ok(None),
    };

    let epoch_id = match json.get("epoch_id").and_then(|v| v.as_u64()) {
        Some(id) => id,
        None => return Ok(None),
    };

    let group_id = json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|raw| Uuid::parse_str(raw).ok());

    Ok(Some(ExistingEncryptionMetadata {
        file_id,
        group_id,
        epoch_id,
    }))
}

pub(crate) fn scan_directory_ciphertext_groups(
    dir_path: &Path,
    mode: TraversalMode,
    warnings: &mut Vec<String>,
) -> Result<Vec<DirectoryCiphertextGroup>, CliError> {
    if !dir_path.is_dir() {
        return Ok(Vec::new());
    }

    let mut grouped: BTreeMap<(Option<Uuid>, u64), Vec<DirectoryEncryptedFile>> = BTreeMap::new();
    let mut stack = vec![dir_path.to_path_buf()];

    while let Some(current) = stack.pop() {
        let entries = match fs::read_dir(&current) {
            Ok(entries) => entries,
            Err(e) => {
                let message = format!("Failed to read directory {}: {}", current.display(), e);
                if mode.is_strict() {
                    return Err(CliError::storage(message));
                }
                warnings.push(message);
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    let message =
                        format!("Failed to read entry under {}: {}", current.display(), e);
                    if mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.push(message);
                    continue;
                }
            };

            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(e) => {
                    let message = format!("Failed to inspect {}: {}", entry.path().display(), e);
                    if mode.is_strict() {
                        return Err(CliError::storage(message));
                    }
                    warnings.push(message);
                    continue;
                }
            };

            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }

            if !file_type.is_file() {
                continue;
            }

            let metadata = match detect_existing_encryption_metadata(&path) {
                Ok(Some(metadata)) => metadata,
                Ok(None) => continue,
                Err(err) => {
                    let message = format!(
                        "Failed to inspect {} for HybridCipher metadata: {}",
                        path.display(),
                        err
                    );
                    if mode.is_strict() {
                        return Err(err);
                    }
                    warnings.push(message);
                    continue;
                }
            };

            let relative_path = match path.strip_prefix(dir_path) {
                Ok(relative_path) => relative_path,
                Err(_) => {
                    let message = format!(
                        "Encountered file {} outside root {}",
                        path.display(),
                        dir_path.display()
                    );
                    if mode.is_strict() {
                        return Err(CliError::file_operation(message));
                    }
                    warnings.push(message);
                    continue;
                }
            };
            let relative_path = relative_path.to_path_buf();

            let entry = DirectoryEncryptedFile {
                absolute_path: path,
                relative_path,
                metadata,
            };

            let key = (entry.metadata.group_id, entry.metadata.epoch_id);
            grouped.entry(key).or_default().push(entry);
        }
    }

    Ok(grouped
        .into_iter()
        .map(|((group_id, epoch_id), files)| DirectoryCiphertextGroup {
            group_id,
            epoch_id,
            files,
        })
        .collect())
}

pub(crate) fn enforce_directory_ciphertext_policy(
    ciphertext_groups: &[DirectoryCiphertextGroup],
    active_group: Option<Uuid>,
    active_epoch: Option<u64>,
) -> Result<Option<DirectoryCiphertextGroup>, DirectoryCiphertextPolicyError> {
    if ciphertext_groups.is_empty() {
        return Ok(None);
    }

    let Some(group_id) = active_group else {
        return Err(DirectoryCiphertextPolicyError::MissingActiveContext);
    };
    let Some(epoch_id) = active_epoch else {
        return Err(DirectoryCiphertextPolicyError::MissingActiveContext);
    };

    if ciphertext_groups.len() > 1 {
        return Err(DirectoryCiphertextPolicyError::Mixed(
            ciphertext_groups.to_vec(),
        ));
    }

    let candidate = ciphertext_groups[0].clone();
    if candidate.group_id == Some(group_id) && candidate.epoch_id == epoch_id {
        Ok(Some(candidate))
    } else {
        Err(DirectoryCiphertextPolicyError::ForeignContext {
            offending: candidate,
            expected_group: group_id,
            expected_epoch: epoch_id,
        })
    }
}

pub(crate) fn preserve_file_mtime(source: &Path, destination: &Path) -> Result<(), CliError> {
    let metadata = fs::metadata(source).map_err(|e| {
        CliError::storage(format!(
            "Failed to read metadata from {}: {}",
            source.display(),
            e
        ))
    })?;

    let mtime = metadata.modified().map_err(|e| {
        CliError::storage(format!(
            "Failed to get modification time from {}: {}",
            source.display(),
            e
        ))
    })?;

    let atime = metadata.accessed().unwrap_or(mtime);

    let ft_mtime = FileTime::from_system_time(mtime);
    let ft_atime = FileTime::from_system_time(atime);
    set_file_times(destination, ft_atime, ft_mtime).map_err(|e| {
        CliError::storage(format!(
            "Failed to set modification time for {}: {}",
            destination.display(),
            e
        ))
    })
}

pub(crate) fn preserve_directory_mtime(path: &Path, original_mtime: Option<SystemTime>) {
    let Some(mtime) = original_mtime else {
        return;
    };

    let _ = set_file_mtime(path, FileTime::from_system_time(mtime));
}

pub(crate) fn capture_directory_mtime(path: &Path) -> Option<SystemTime> {
    fs::metadata(path).ok()?.modified().ok()
}

pub(crate) fn default_safe_decrypt_file_path(
    parsed: &ParsedEncryptedFile,
) -> Result<PathBuf, CliError> {
    let files_dir = ensure_hidden_subdir(&["decrypted", "files"])?;
    let file_name = parsed
        .original_name
        .as_deref()
        .map(|name| append_timestamp_to_name(name, &current_timestamp()))
        .unwrap_or_else(|| format!("decrypted_{}.bin", current_timestamp()));
    Ok(files_dir.join(file_name))
}

pub(crate) fn default_safe_decrypt_dir_root(dir_path: &Path) -> Result<PathBuf, CliError> {
    let folders_dir = ensure_hidden_subdir(&["decrypted", "folders"])?;
    let name = dir_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("folder");
    let target = folders_dir.join(append_timestamp_to_name(name, &current_timestamp()));
    ensure_directory(&target)?;
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    #[test]
    fn detect_existing_encryption_metadata_finds_metadata() {
        let group_id = Uuid::new_v4();
        let mut temp = NamedTempFile::new().expect("temp file");
        let metadata = json!({
            "file_id": "abc",
            "epoch_id": 1,
            "original_size": 42,
            "file_size": 42,
            "group_id": group_id.to_string()
        });
        writeln!(temp, "{}", metadata.to_string()).expect("write metadata");
        writeln!(temp, "{}", ENCRYPTED_FILE_SEPARATOR).expect("write sep");
        writeln!(temp, "ciphertext").expect("write data");

        let result = detect_existing_encryption_metadata(temp.path()).expect("metadata");
        let Some(result) = result else {
            panic!("expected metadata");
        };
        assert_eq!(result.file_id, "abc");
        assert_eq!(result.group_id, Some(group_id));
        assert_eq!(result.epoch_id, 1);
    }

    #[test]
    fn detect_existing_encryption_metadata_ignores_plain_files() {
        let mut temp = NamedTempFile::new().expect("temp file");
        writeln!(temp, "not metadata").expect("write");
        let result = detect_existing_encryption_metadata(temp.path()).expect("metadata");
        assert!(result.is_none());
    }
}
