//! Version 3 binds content layout inside the authenticated wrapped-key envelope.
//! Rekeying rewraps the complete envelope unchanged. It never recomputes a
//! commitment from potentially attacker-modified file headers.
use crate::{
    file::encrypt::{EncryptionError, SparseFileMetadata},
    state::EncryptedFileMetadata,
    ClientError,
};
use hybridcipher_crypto::{seal, AeadContext, AeadKey, AeadNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Version supporting an authenticated size, chunking mode, nonce and layout.
pub const VERSION: u32 = 3;

/// A caller's explicit legacy-read decision. This never relaxes v3 verification.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyReadPolicy {
    #[default]
    Strict,
    AllowLegacyUnverified,
}

pub fn requires_legacy_compatibility(metadata: &EncryptedFileMetadata) -> bool {
    matches!(metadata.header_version.unwrap_or(1), 1 | 2)
        && (metadata.header_version == Some(2)
            || metadata.content_chunk_size.is_some()
            || metadata.sparse_metadata.is_some())
}

impl LegacyReadPolicy {
    pub fn check(self, metadata: &EncryptedFileMetadata) -> Result<(), ClientError> {
        if self == Self::Strict && requires_legacy_compatibility(metadata) {
            Err(ClientError::LegacyCompatibilityRequired)
        } else {
            Ok(())
        }
    }
}

/// Canonical commitment to immutable content interpretation (not epoch/group).
pub fn digest(
    size: u64,
    encrypted_size: u64,
    chunk: Option<u64>,
    nonce: &[u8],
    sparse: Option<&SparseFileMetadata>,
) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(b"hybridcipher/content-manifest/v3\0");
    hash.update(size.to_le_bytes());
    hash.update(encrypted_size.to_le_bytes());
    hash.update([u8::from(chunk.is_some())]);
    hash.update(chunk.unwrap_or(0).to_le_bytes());
    hash.update((nonce.len() as u64).to_le_bytes());
    hash.update(nonce);
    hash.update([u8::from(sparse.is_some())]);
    if let Some(sparse) = sparse {
        hash.update(sparse.logical_size.to_le_bytes());
        hash.update((sparse.extents.len() as u64).to_le_bytes());
        for extent in &sparse.extents {
            hash.update(extent.offset.to_le_bytes());
            hash.update(extent.length.to_le_bytes());
        }
    }
    hash.finalize().to_vec()
}

/// Wrap a key and its manifest as one AEAD-protected envelope.
pub fn wrap(
    key: &AeadKey,
    kek: &AeadKey,
    aad: &[u8],
    manifest: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    let mut envelope = Zeroizing::new(key.as_bytes().to_vec());
    envelope.extend_from_slice(manifest);
    rewrap(&envelope, kek, aad)
}

/// Rewrap a verified envelope without dropping or changing its commitment.
pub fn rewrap(
    envelope: &[u8],
    kek: &AeadKey,
    aad: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), EncryptionError> {
    if !matches!(envelope.len(), 32 | 64) {
        return Err(EncryptionError::EncryptionFailure(
            "Invalid key envelope".into(),
        ));
    }
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let nonce_key = AeadNonce::from_bytes(&nonce)
        .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;
    let wrapped = seal(kek, &nonce_key, AeadContext::FileData, aad, envelope)
        .map_err(|e| EncryptionError::EncryptionFailure(e.to_string()))?;
    Ok((wrapped, nonce.to_vec()))
}

/// Check completeness/layout before allocation or plaintext publication.
pub fn verify(
    metadata: &EncryptedFileMetadata,
    envelope: &[u8],
    allow_legacy: bool,
) -> Result<AeadKey, ClientError> {
    let fail = |message: &str| ClientError::FileIntegrity(message.into());
    match metadata.header_version.unwrap_or(1) {
        VERSION => {
            if envelope.len() != 64
                || envelope[32..]
                    != digest(
                        metadata.content_size,
                        metadata.encrypted_size,
                        metadata.content_chunk_size,
                        metadata.content_nonce.as_deref().unwrap_or(&[]),
                        metadata.sparse_metadata.as_ref(),
                    )
            {
                return Err(fail(
                    "Authenticated content manifest mismatch; file may be incomplete or modified",
                ));
            }
            AeadKey::from_bytes(&envelope[..32]).map_err(|e| fail(&e.to_string()))
        }
        1 | 2 => {
            if !allow_legacy
                && (metadata.header_version == Some(2)
                    || metadata.content_chunk_size.is_some()
                    || metadata.sparse_metadata.is_some())
            {
                return Err(ClientError::LegacyCompatibilityRequired);
            }
            AeadKey::from_bytes(envelope).map_err(|e| fail(&e.to_string()))
        }
        _ => Err(fail("Unsupported encrypted-file version")),
    }
}
