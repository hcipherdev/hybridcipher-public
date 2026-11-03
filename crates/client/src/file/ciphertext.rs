//! The one place that decides what a `.encrypted` name is.
//!
//! A folder record (`.hybridcipher_dir.encrypted`) ends in `.encrypted` so sync
//! tools and the mount providers carry it with the files, but it holds a
//! folder's ID and details, not file contents. Every walker of a protected
//! folder must say what it does with each kind, so new code goes through
//! [`classify`] rather than checking the suffix itself; a guard test fails
//! the build otherwise.
//!
//! A name is only a hint: anyone can add or remove `.encrypted`. Whether a
//! file's bytes are HybridCipher ciphertext is decided by [`inspect_bytes`] and
//! [`inspect_path`], which read its header instead of trusting the name.
use crate::file::encrypt::{
    chunked_encrypted_size, normalize_file_identifier, read_encrypted_header, SparseFileMetadata,
    AEAD_TAG_SIZE, MAX_CONTENT_CHUNK_SIZE,
};
use crate::file::PlatformFileMetadata;
use crate::state::EncryptedFileMetadata;
use base64::{engine::general_purpose, Engine as _};
use serde_json::Value;
use std::io::{BufRead, BufReader, Seek};
use std::path::Path;
use uuid::Uuid;

/// Suffix of every HybridCipher ciphertext name, compared ignoring ASCII case.
pub const ENCRYPTED_SUFFIX: &str = ".encrypted";

/// Name of the record each protected folder keeps for itself.
pub const FOLDER_RECORD_FILE_NAME: &str = ".hybridcipher_dir.encrypted";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiphertextKind {
    /// An encrypted file; its plaintext name is the name without `.encrypted`.
    File,
    /// A folder record: never restored, listed or counted as a file.
    FolderRecord,
    /// Not named like HybridCipher ciphertext.
    NotEncrypted,
}

/// Classify a path by its file name.
pub fn classify(path: &Path) -> CiphertextKind {
    match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => classify_name(name),
        None => CiphertextKind::NotEncrypted,
    }
}

/// Classify a relative path as stored in the file index (`/` or `\` separated).
pub fn classify_relative(relative_path: &str) -> CiphertextKind {
    let name = relative_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(relative_path);
    classify_name(name)
}

/// Classify a single file name.
pub fn classify_name(name: &str) -> CiphertextKind {
    if name.eq_ignore_ascii_case(FOLDER_RECORD_FILE_NAME) {
        CiphertextKind::FolderRecord
    } else if strip_encrypted_suffix(name).is_some() {
        CiphertextKind::File
    } else {
        CiphertextKind::NotEncrypted
    }
}

/// `value` without one trailing `.encrypted`, or `None` when it has none.
/// A bare `.encrypted` has no name left, so it is not ciphertext.
pub fn strip_encrypted_suffix(value: &str) -> Option<&str> {
    if value.len() <= ENCRYPTED_SUFFIX.len() {
        return None;
    }
    let split = value.len() - ENCRYPTED_SUFFIX.len();
    if !value.is_char_boundary(split) {
        return None;
    }
    let (body, suffix) = value.split_at(split);
    suffix
        .eq_ignore_ascii_case(ENCRYPTED_SUFFIX)
        .then_some(body)
}

/// What a file's bytes are, whatever its name says.
#[derive(Debug)]
pub enum ContentKind {
    /// No HybridCipher header, so plaintext even when named `.encrypted`.
    NotCiphertext,
    /// Starts like a HybridCipher header, but its fields or sizes do not hold up,
    /// e.g. truncated ciphertext. It can be neither decrypted nor checked.
    Damaged(HeaderIdentity),
    /// A complete header whose sizes match the contents. Anyone can write one, so
    /// it is not proof until a key unwraps it. `encrypted_content` is left empty.
    Ciphertext(Box<EncryptedFileMetadata>),
}

/// Which file, key version and group a header claims to be from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderIdentity {
    pub file_id: String,
    pub epoch_id: u64,
    pub group_id: Option<Uuid>,
}

impl ContentKind {
    /// What the header claims, damaged or not; `None` for plaintext.
    pub fn identity(&self) -> Option<HeaderIdentity> {
        match self {
            Self::NotCiphertext => None,
            Self::Damaged(identity) => Some(identity.clone()),
            Self::Ciphertext(metadata) => Some(HeaderIdentity {
                file_id: metadata.file_id.clone(),
                epoch_id: metadata.epoch_id,
                group_id: metadata.group_id,
            }),
        }
    }
}

/// Inspect a file's contents already in memory.
pub fn inspect_bytes(contents: &[u8]) -> ContentKind {
    if contents.first() != Some(&b'{') {
        return ContentKind::NotCiphertext;
    }
    let mut reader = std::io::Cursor::new(contents);
    match read_header(&mut reader) {
        Some(header) => {
            let encrypted_size = (contents.len() as u64).saturating_sub(reader.position());
            classify_header(&header, encrypted_size)
        }
        None => ContentKind::NotCiphertext,
    }
}

/// Inspect a file on disk, reading only its header.
pub fn inspect_path(path: &Path) -> std::io::Result<ContentKind> {
    let file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut reader = BufReader::new(file);
    if reader.fill_buf()?.first() != Some(&b'{') {
        return Ok(ContentKind::NotCiphertext);
    }
    let Some(header) = read_header(&mut reader) else {
        return Ok(ContentKind::NotCiphertext);
    };
    let encrypted_size = file_len.saturating_sub(reader.stream_position()?);
    Ok(classify_header(&header, encrypted_size))
}

/// The header JSON before the separator line, if there is one.
fn read_header<R: BufRead>(reader: &mut R) -> Option<Value> {
    let bytes = read_encrypted_header(reader).ok()?;
    serde_json::from_slice::<Value>(&bytes)
        .ok()
        .filter(Value::is_object)
}

fn classify_header(header: &Value, encrypted_size: u64) -> ContentKind {
    if let Some(metadata) = parse_header_metadata(header, encrypted_size) {
        return ContentKind::Ciphertext(Box::new(metadata));
    }
    let file_id = header.get("file_id").and_then(Value::as_str);
    let epoch_id = header.get("epoch_id").and_then(Value::as_u64);
    match (file_id, epoch_id) {
        (Some(file_id), Some(epoch_id)) => ContentKind::Damaged(HeaderIdentity {
            file_id: file_id.to_string(),
            epoch_id,
            group_id: header
                .get("group_id")
                .and_then(Value::as_str)
                .and_then(|raw| Uuid::parse_str(raw).ok()),
        }),
        _ => ContentKind::NotCiphertext,
    }
}

/// Header bytes stored as base64, or as a JSON array by older clients.
pub fn decode_header_bytes(val: Option<&Value>) -> Option<Vec<u8>> {
    if let Some(v) = val {
        if let Some(s) = v.as_str() {
            if let Ok(bytes) = general_purpose::STANDARD.decode(s) {
                return Some(bytes);
            }
        }
        if let Ok(vec_bytes) = serde_json::from_value::<Vec<u8>>(v.clone()) {
            return Some(vec_bytes);
        }
    }
    None
}

/// File metadata from a header, given the length of the ciphertext after it.
/// Every field decryption needs must be present and the sizes must agree, but
/// nothing is limited to what fits in memory: large files decrypt by streaming.
pub fn parse_header_metadata(
    header_json: &Value,
    encrypted_size: u64,
) -> Option<EncryptedFileMetadata> {
    let file_id = header_json.get("file_id")?.as_str()?.to_string();
    let epoch_id = header_json.get("epoch_id")?.as_u64()?;
    let header_version = match header_json.get("header_version") {
        None => 1,
        Some(value) => u32::try_from(value.as_u64()?).ok()?,
    };

    let group_id = header_json
        .get("group_id")
        .and_then(|v| v.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());

    let wrapped_file_key = decode_header_bytes(header_json.get("wrapped_file_key"))?;
    let key_wrap_nonce = decode_header_bytes(header_json.get("key_wrap_nonce"))?;
    let key_wrap_aad_hash = decode_header_bytes(header_json.get("key_wrap_aad_hash"))?;
    let content_nonce = decode_header_bytes(header_json.get("content_nonce"))?;

    let created_at = header_json
        .get("encrypted_at")
        .and_then(|v| v.as_str())
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .unwrap_or_else(chrono::Utc::now);

    let content_size_field = header_json
        .get("file_size")
        .and_then(|v| v.as_u64())
        .or_else(|| header_json.get("original_size").and_then(|v| v.as_u64()));
    if header_version >= 3 && content_size_field.is_none() {
        return None;
    }
    let content_size = content_size_field.unwrap_or(0);
    let content_chunk_size = match header_json.get("chunk_size") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64()?),
    };
    let platform_metadata = header_json
        .get("platform_metadata")
        .and_then(|value| serde_json::from_value::<PlatformFileMetadata>(value.clone()).ok())
        .filter(|metadata| !metadata.is_empty());
    let parsed_sparse_metadata = match header_json.get("sparse_metadata") {
        None | Some(Value::Null) => None,
        Some(value) => Some(serde_json::from_value::<SparseFileMetadata>(value.clone()).ok()?),
    };
    if let Some(layout) = parsed_sparse_metadata.as_ref() {
        layout.validated_packed_size(content_size)?;
    }
    let sparse_metadata = parsed_sparse_metadata.filter(SparseFileMetadata::is_effectively_sparse);
    let packed_size = match sparse_metadata.as_ref() {
        Some(layout) => layout.validated_packed_size(content_size)?,
        None => content_size,
    };
    if let Some(chunk_size) = content_chunk_size {
        let chunk_size = usize::try_from(chunk_size).ok()?;
        if chunk_size == 0 || chunk_size > MAX_CONTENT_CHUNK_SIZE {
            return None;
        }
        if chunked_encrypted_size(packed_size, chunk_size).ok()? != encrypted_size {
            return None;
        }
    } else if content_size_field.is_some()
        && encrypted_size != packed_size.checked_add(12 + AEAD_TAG_SIZE as u64)?
    {
        return None;
    }

    let stored_file_path = header_json
        .get("file_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|value| !value.trim().is_empty())?;

    Some(EncryptedFileMetadata {
        file_id,
        file_path: normalize_file_identifier(&stored_file_path),
        group_id,
        epoch_id,
        header_version: Some(header_version),
        wrapped_file_key: Some(wrapped_file_key),
        key_wrap_nonce: Some(key_wrap_nonce),
        key_wrap_aad_hash: Some(key_wrap_aad_hash),
        content_nonce: Some(content_nonce),
        content_chunk_size,
        content_size,
        encrypted_size,
        created_at,
        platform_metadata,
        sparse_metadata,
        encrypted_content: Vec::new(),
    })
}

#[cfg(test)]
#[path = "../../tests/file/test_ciphertext_classifier.rs"]
mod tests;

#[cfg(test)]
#[path = "../../tests/architecture/test_ciphertext_name_guard.rs"]
mod name_guard_tests;
