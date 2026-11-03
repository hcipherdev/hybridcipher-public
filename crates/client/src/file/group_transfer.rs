//! Move an encrypted file from one group to another without touching its contents.
//!
//! Contents are sealed with the file's own key and bound only to its file ID, so
//! only the header names a group: the wrapped file key, its nonce, and the hash of
//! the wrap AAD that binds file ID, name, group, epoch and header version. Moving
//! a file unwraps that key with the source group's epoch key and wraps it again
//! under the target's; the ciphertext after the header is copied byte for byte.
//! A local vault uses this to join an existing account's Personal workspace.

use crate::{
    file::encrypt::{
        build_wrap_aad, hash_wrap_aad, normalize_file_identifier, read_encrypted_header,
        ENCRYPTED_FILE_SEPARATOR,
    },
    storage::StorageError,
    ClientError,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use filetime::FileTime;
use hybridcipher_crypto::{hkdf_expand, kdf::HkdfContext, open, AeadContext, AeadKey, AeadNonce};
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Seek, Write};
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Suffix of the copy written beside a file while its header is replaced. A
/// leftover one is an unfinished copy; the original next to it is intact.
pub const TRANSFER_TEMP_SUFFIX: &str = ".hc-move.tmp";
const COPY_BUFFER_BYTES: usize = 1024 * 1024;
const OWNER_SCAN_BYTES: u64 = 8192;

/// One epoch key of a group.
#[derive(Clone)]
pub struct GroupEpochKey {
    pub group_id: Uuid,
    pub epoch_id: u64,
    pub key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for GroupEpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupEpochKey")
            .field("group_id", &self.group_id)
            .field("epoch_id", &self.epoch_id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupTransferOutcome {
    Moved,
    /// The header already names the target group, as after an interrupted run.
    AlreadyInTarget,
}

/// Who a file on disk belongs to, judged from its header alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedFileOwner {
    /// Not a HybridCipher file.
    NotEncrypted,
    Group(Uuid),
    /// Looks encrypted, but no readable header names its group.
    Unknown,
}

/// Classify a file without reading past its header.
pub fn encrypted_file_owner(path: &Path) -> io::Result<EncryptedFileOwner> {
    let mut file = File::open(path)?;
    let mut prefix = Vec::new();
    Read::by_ref(&mut file)
        .take(OWNER_SCAN_BYTES)
        .read_to_end(&mut prefix)?;
    // A folder record names its folder's group too, so it counts like a file here.
    let encrypted_extension =
        super::ciphertext::classify(path) != super::ciphertext::CiphertextKind::NotEncrypted;
    let json_prefix = prefix.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{');
    if !encrypted_extension && !json_prefix {
        return Ok(EncryptedFileOwner::NotEncrypted);
    }
    file.rewind()?;
    match read_encrypted_header(&mut BufReader::new(file)) {
        Ok(header) => Ok(serde_json::from_slice::<Value>(&header)
            .ok()
            .and_then(|json| {
                json.get("group_id")
                    .and_then(Value::as_str)
                    .and_then(|value| Uuid::parse_str(value).ok())
            })
            .map_or(EncryptedFileOwner::Unknown, EncryptedFileOwner::Group)),
        Err(err) if err.kind() != ErrorKind::InvalidData => Err(err),
        Err(_) => {
            let contains = |needle: &[u8]| prefix.windows(needle.len()).any(|part| part == needle);
            let looks_encrypted =
                encrypted_extension || (contains(b"\"file_id\"") && contains(b"\"epoch_id\""));
            Ok(if looks_encrypted {
                EncryptedFileOwner::Unknown
            } else {
                EncryptedFileOwner::NotEncrypted
            })
        }
    }
}

/// Rewrap one file's key from `from` to `to` and rewrite its header in place.
///
/// The new header is written with a copy of the ciphertext to a temporary file
/// beside the original, which then replaces it, so an interruption leaves either
/// the old file or the new one. A file already in `to` is left alone, which lets
/// an interrupted folder transfer simply run again.
pub fn transfer_file_to_group(
    path: &Path,
    from: &GroupEpochKey,
    to: &GroupEpochKey,
) -> Result<GroupTransferOutcome, ClientError> {
    let before = fs::metadata(path).map_err(io_error)?;
    let mut reader =
        BufReader::with_capacity(COPY_BUFFER_BYTES, File::open(path).map_err(io_error)?);
    let header_bytes = read_encrypted_header(&mut reader)
        .map_err(|err| integrity(path, &format!("its header can't be read ({err})")))?;
    let mut header: Value = serde_json::from_slice(&header_bytes)
        .map_err(|err| integrity(path, &format!("its header isn't valid ({err})")))?;
    let fields =
        KeyFields::parse(&header).ok_or_else(|| integrity(path, "its header is incomplete"))?;

    if fields.group_id == Some(to.group_id) {
        return Ok(GroupTransferOutcome::AlreadyInTarget);
    }
    if fields.group_id != Some(from.group_id) {
        return Err(ClientError::InvalidInput(format!(
            "'{}' was encrypted by another workspace, so it can't be moved. Move it out of this folder and try again.",
            path.display()
        )));
    }
    if fields.epoch_id != from.epoch_id {
        return Err(ClientError::InvalidState(format!(
            "'{}' uses a key this vault doesn't have (epoch {}).",
            path.display(),
            fields.epoch_id
        )));
    }

    let file_key = unwrap_file_key(path, &fields, from)?;
    let rewrapped = wrap_file_key(&fields, &file_key, to)?;
    header["group_id"] = Value::String(to.group_id.to_string());
    header["epoch_id"] = Value::from(to.epoch_id);
    header["wrapped_file_key"] = Value::String(STANDARD.encode(&rewrapped.wrapped));
    header["key_wrap_nonce"] = Value::String(STANDARD.encode(&rewrapped.nonce));
    header["key_wrap_aad_hash"] = Value::String(STANDARD.encode(&rewrapped.aad_hash));
    let mut new_header = serde_json::to_vec(&header)
        .map_err(|err| ClientError::SerializationError(err.to_string()))?;
    new_header.extend_from_slice(ENCRYPTED_FILE_SEPARATOR);

    let ciphertext_offset = reader.stream_position().map_err(io_error)?;
    let ciphertext_len = before
        .len()
        .checked_sub(ciphertext_offset)
        .ok_or_else(|| integrity(path, "it is shorter than its header"))?;
    let temp = temp_path(path)?;
    let parent_mtime = path.parent().and_then(directory_mtime);
    if let Err(err) = write_copy(&temp, &new_header, &mut reader, ciphertext_len, &before) {
        let _ = fs::remove_file(&temp);
        return Err(err);
    }
    drop(reader);
    // Nothing may write the folder during a move, but never replace a file that
    // changed under the copy.
    let unchanged = fs::metadata(path)
        .map(|after| after.len() == before.len() && after.modified().ok() == before.modified().ok())
        .unwrap_or(false);
    if !unchanged {
        let _ = fs::remove_file(&temp);
        return Err(ClientError::InvalidState(format!(
            "'{}' changed while it was being moved. Try again.",
            path.display()
        )));
    }
    if let Err(err) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(io_error(err));
    }
    let mtime = FileTime::from_last_modification_time(&before);
    let atime = FileTime::from_last_access_time(&before);
    if let Err(err) = filetime::set_file_times(path, atime, mtime) {
        log::warn!(
            "Kept new header but not the times of {}: {}",
            path.display(),
            err
        );
    }
    if let (Some(parent), Some(mtime)) = (path.parent(), parent_mtime) {
        let _ = filetime::set_file_mtime(parent, mtime);
        sync_directory(parent);
    }
    Ok(GroupTransferOutcome::Moved)
}

/// The header fields that hold and bind the wrapped file key.
struct KeyFields {
    file_id: String,
    file_path: String,
    group_id: Option<Uuid>,
    epoch_id: u64,
    header_version: u32,
    wrapped_file_key: Vec<u8>,
    key_wrap_nonce: Vec<u8>,
    key_wrap_aad_hash: Vec<u8>,
}

impl KeyFields {
    fn parse(header: &Value) -> Option<Self> {
        let header_version = match header.get("header_version") {
            None | Some(Value::Null) => 1,
            Some(value) => u32::try_from(value.as_u64()?).ok()?,
        };
        Some(Self {
            file_id: header.get("file_id")?.as_str()?.to_string(),
            file_path: header
                .get("file_path")?
                .as_str()
                .filter(|value| !value.trim().is_empty())?
                .to_string(),
            group_id: header
                .get("group_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok()),
            epoch_id: header.get("epoch_id")?.as_u64()?,
            header_version,
            wrapped_file_key: decode_bytes(header.get("wrapped_file_key")?)?,
            key_wrap_nonce: decode_bytes(header.get("key_wrap_nonce")?)?,
            key_wrap_aad_hash: decode_bytes(header.get("key_wrap_aad_hash")?)?,
        })
    }

    fn wrap_aad(&self, group_id: Uuid, epoch_id: u64) -> Vec<u8> {
        build_wrap_aad(
            &self.file_id,
            &normalize_file_identifier(&self.file_path),
            Some(group_id),
            epoch_id,
            self.header_version,
        )
    }
}

/// Header byte fields are base64 strings; early headers stored number arrays.
fn decode_bytes(value: &Value) -> Option<Vec<u8>> {
    match value {
        Value::String(encoded) => STANDARD.decode(encoded).ok(),
        other => serde_json::from_value::<Vec<u8>>(other.clone()).ok(),
    }
}

fn key_wrapping_key(epoch_key: &[u8; 32]) -> Result<AeadKey, ClientError> {
    let bytes = Zeroizing::new(
        hkdf_expand(epoch_key, HkdfContext::KeyWrapping, 32).map_err(|err| {
            ClientError::EncryptionError(format!("HKDF(KeyWrapping) failed: {err}"))
        })?,
    );
    AeadKey::from_bytes(&bytes).map_err(|err| ClientError::EncryptionError(err.to_string()))
}

fn unwrap_file_key(
    path: &Path,
    fields: &KeyFields,
    from: &GroupEpochKey,
) -> Result<Zeroizing<Vec<u8>>, ClientError> {
    let aad = fields.wrap_aad(from.group_id, from.epoch_id);
    if hash_wrap_aad(&aad) != fields.key_wrap_aad_hash {
        return Err(integrity(path, "its key binding doesn't match its header"));
    }
    let nonce = AeadNonce::from_bytes(&fields.key_wrap_nonce)
        .map_err(|_| integrity(path, "its key nonce is invalid"))?;
    let kek = key_wrapping_key(&from.key)?;
    open(
        &kek,
        &nonce,
        AeadContext::FileData,
        &aad,
        &fields.wrapped_file_key,
    )
    .map(Zeroizing::new)
    .map_err(|_| {
        ClientError::DecryptionError(format!(
            "The key of '{}' doesn't open with this vault's key",
            path.display()
        ))
    })
}

struct Rewrapped {
    wrapped: Vec<u8>,
    nonce: Vec<u8>,
    aad_hash: Vec<u8>,
}

/// Wrap the unchanged key envelope for the target, and prove it opens again.
fn wrap_file_key(
    fields: &KeyFields,
    envelope: &[u8],
    to: &GroupEpochKey,
) -> Result<Rewrapped, ClientError> {
    let aad = fields.wrap_aad(to.group_id, to.epoch_id);
    let kek = key_wrapping_key(&to.key)?;
    let (wrapped, nonce) = crate::file::content_manifest::rewrap(envelope, &kek, &aad)
        .map_err(|err| ClientError::EncryptionError(err.to_string()))?;
    let check_nonce = AeadNonce::from_bytes(&nonce)
        .map_err(|err| ClientError::EncryptionError(err.to_string()))?;
    let reopened = Zeroizing::new(
        open(&kek, &check_nonce, AeadContext::FileData, &aad, &wrapped).map_err(|_| {
            ClientError::EncryptionError("The new file key wrap didn't verify".into())
        })?,
    );
    if reopened.as_slice() != envelope {
        return Err(ClientError::EncryptionError(
            "The new file key wrap didn't verify".into(),
        ));
    }
    Ok(Rewrapped {
        wrapped,
        nonce,
        aad_hash: hash_wrap_aad(&aad),
    })
}

fn temp_path(path: &Path) -> Result<PathBuf, ClientError> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            ClientError::InvalidInput(format!("'{}' has no usable name", path.display()))
        })?;
    Ok(path.with_file_name(format!(".{name}{TRANSFER_TEMP_SUFFIX}")))
}

fn write_copy(
    temp: &Path,
    header: &[u8],
    ciphertext: &mut BufReader<File>,
    ciphertext_len: u64,
    original: &fs::Metadata,
) -> Result<(), ClientError> {
    match fs::remove_file(temp) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(io_error(err)),
    }
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(temp)
        .map_err(io_error)?;
    let mut writer = BufWriter::with_capacity(COPY_BUFFER_BYTES, file);
    writer.write_all(header).map_err(io_error)?;
    let copied = io::copy(&mut ciphertext.take(ciphertext_len), &mut writer).map_err(io_error)?;
    if copied != ciphertext_len {
        return Err(ClientError::InvalidState(
            "The file ended early while it was being moved".into(),
        ));
    }
    let file = writer
        .into_inner()
        .map_err(|err| io_error(err.into_error()))?;
    file.set_permissions(original.permissions())
        .map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn directory_mtime(path: &Path) -> Option<FileTime> {
    fs::metadata(path)
        .ok()
        .map(|meta| FileTime::from_last_modification_time(&meta))
}

fn sync_directory(path: &Path) {
    #[cfg(unix)]
    if let Ok(dir) = File::open(path) {
        let _ = dir.sync_all();
    }
    #[cfg(not(unix))]
    let _ = path;
}

fn io_error(err: io::Error) -> ClientError {
    ClientError::from(StorageError::Io(err))
}

fn integrity(path: &Path, reason: &str) -> ClientError {
    ClientError::FileIntegrity(format!("'{}' can't be moved: {reason}", path.display()))
}
