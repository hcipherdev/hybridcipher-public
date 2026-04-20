// File encryption/decryption using ChaCha20-Poly1305 AEAD
// Implements secure file operations with authenticated encryption

use hybridcipher_crypto::aead::{AeadContext, Key as AeadKey, Nonce as AeadNonce};
use hybridcipher_crypto::{open, seal};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Metadata stored with encrypted files
#[derive(Debug, Serialize, Deserialize)]
pub struct EncryptedFileMetadata {
    /// Unique file identifier
    pub file_id: String,
    /// Original filename
    pub original_name: String,
    /// File size (original)
    pub original_size: u64,
    /// Encryption timestamp
    pub encrypted_at: i64,
    /// Nonce used for encryption (12 bytes, hex encoded)
    pub nonce: String,
    /// Version of encryption format
    pub version: u8,
}

/// Encrypted file format:
/// [metadata_len: 4 bytes][metadata: JSON][ciphertext: remaining bytes]
pub struct FileEncryptor;

impl FileEncryptor {
    /// Encrypt a file with ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `input_path` - Path to plaintext file
    /// * `output_path` - Path to write encrypted file
    /// * `file_id` - Unique identifier for this file (used as AAD)
    ///
    /// # Returns
    /// Tuple of (file_id, encryption_key) - key must be stored securely!
    pub fn encrypt_file(
        input_path: &Path,
        output_path: &Path,
        file_id: Option<String>,
    ) -> Result<(String, Zeroizing<Vec<u8>>), String> {
        // Read plaintext file
        let plaintext =
            fs::read(input_path).map_err(|e| format!("Failed to read input file: {}", e))?;

        // Generate file ID if not provided
        let file_id = file_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        // Generate random encryption key
        let mut key_bytes = Zeroizing::new(vec![0u8; 32]);
        OsRng.fill_bytes(&mut key_bytes);
        let key =
            AeadKey::from_bytes(&key_bytes).map_err(|e| format!("Failed to create key: {}", e))?;

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = AeadNonce::from_bytes(&nonce_bytes)
            .map_err(|e| format!("Failed to create nonce: {}", e))?;

        // Create metadata
        let original_name = input_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let metadata = EncryptedFileMetadata {
            file_id: file_id.clone(),
            original_name,
            original_size: plaintext.len() as u64,
            encrypted_at: chrono::Utc::now().timestamp(),
            nonce: hex::encode(&nonce_bytes),
            version: 1,
        };

        // Serialize metadata
        let metadata_json = serde_json::to_vec(&metadata)
            .map_err(|e| format!("Failed to serialize metadata: {}", e))?;

        // Encrypt plaintext with file_id as AAD
        let ciphertext = seal(
            &key,
            &nonce,
            AeadContext::FileData,
            file_id.as_bytes(),
            &plaintext,
        )
        .map_err(|e| format!("Encryption failed: {}", e))?;

        // Build encrypted file format: [metadata_len][metadata][ciphertext]
        let metadata_len = (metadata_json.len() as u32).to_le_bytes();
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&metadata_len);
        encrypted_data.extend_from_slice(&metadata_json);
        encrypted_data.extend_from_slice(&ciphertext);

        // Write encrypted file
        fs::write(output_path, encrypted_data)
            .map_err(|e| format!("Failed to write encrypted file: {}", e))?;

        tracing::info!(
            "File encrypted: {} -> {} ({} bytes)",
            input_path.display(),
            output_path.display(),
            ciphertext.len()
        );

        Ok((file_id, key_bytes))
    }

    /// Decrypt a file with ChaCha20-Poly1305
    ///
    /// # Arguments
    /// * `input_path` - Path to encrypted file
    /// * `output_path` - Path to write decrypted file
    /// * `key_bytes` - Encryption key (32 bytes)
    ///
    /// # Returns
    /// Metadata of decrypted file
    pub fn decrypt_file(
        input_path: &Path,
        output_path: &Path,
        key_bytes: &[u8],
    ) -> Result<EncryptedFileMetadata, String> {
        // Read encrypted file
        let encrypted_data =
            fs::read(input_path).map_err(|e| format!("Failed to read encrypted file: {}", e))?;

        if encrypted_data.len() < 4 {
            return Err("Encrypted file too short".to_string());
        }

        // Parse metadata length
        let metadata_len = u32::from_le_bytes([
            encrypted_data[0],
            encrypted_data[1],
            encrypted_data[2],
            encrypted_data[3],
        ]) as usize;

        if encrypted_data.len() < 4 + metadata_len {
            return Err("Encrypted file corrupted: invalid metadata length".to_string());
        }

        // Parse metadata
        let metadata_json = &encrypted_data[4..4 + metadata_len];
        let metadata: EncryptedFileMetadata = serde_json::from_slice(metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))?;

        // Extract ciphertext
        let ciphertext = &encrypted_data[4 + metadata_len..];

        // Reconstruct nonce
        let nonce_bytes =
            hex::decode(&metadata.nonce).map_err(|e| format!("Failed to decode nonce: {}", e))?;
        let nonce = AeadNonce::from_bytes(&nonce_bytes)
            .map_err(|e| format!("Failed to create nonce: {}", e))?;

        // Create key
        let key = AeadKey::from_bytes(key_bytes).map_err(|e| format!("Invalid key: {}", e))?;

        // Decrypt with file_id as AAD
        let plaintext = open(
            &key,
            &nonce,
            AeadContext::FileData,
            metadata.file_id.as_bytes(),
            ciphertext,
        )
        .map_err(|e| format!("Decryption failed: {}", e))?;

        // Verify size matches
        if plaintext.len() != metadata.original_size as usize {
            return Err(format!(
                "Decrypted size mismatch: expected {}, got {}",
                metadata.original_size,
                plaintext.len()
            ));
        }

        // Write decrypted file
        fs::write(output_path, plaintext)
            .map_err(|e| format!("Failed to write decrypted file: {}", e))?;

        tracing::info!(
            "File decrypted: {} -> {} ({} bytes)",
            input_path.display(),
            output_path.display(),
            metadata.original_size
        );

        Ok(metadata)
    }

    /// Read metadata from encrypted file without decrypting
    pub fn read_metadata(input_path: &Path) -> Result<EncryptedFileMetadata, String> {
        let encrypted_data =
            fs::read(input_path).map_err(|e| format!("Failed to read encrypted file: {}", e))?;

        if encrypted_data.len() < 4 {
            return Err("Encrypted file too short".to_string());
        }

        let metadata_len = u32::from_le_bytes([
            encrypted_data[0],
            encrypted_data[1],
            encrypted_data[2],
            encrypted_data[3],
        ]) as usize;

        if encrypted_data.len() < 4 + metadata_len {
            return Err("Encrypted file corrupted".to_string());
        }

        let metadata_json = &encrypted_data[4..4 + metadata_len];
        serde_json::from_slice(metadata_json)
            .map_err(|e| format!("Failed to parse metadata: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        // Create temporary plaintext file
        let mut plaintext_file = NamedTempFile::new().unwrap();
        let test_data = b"Hello, HybridCipher! This is a test file.";
        plaintext_file.write_all(test_data).unwrap();

        // Create temporary paths
        let encrypted_path = NamedTempFile::new().unwrap().into_temp_path();
        let decrypted_path = NamedTempFile::new().unwrap().into_temp_path();

        // Encrypt
        let (file_id, key) =
            FileEncryptor::encrypt_file(plaintext_file.path(), &encrypted_path, None).unwrap();

        // Decrypt
        let metadata = FileEncryptor::decrypt_file(&encrypted_path, &decrypted_path, &key).unwrap();

        // Verify
        assert_eq!(metadata.file_id, file_id);
        assert_eq!(metadata.original_size, test_data.len() as u64);

        let decrypted_data = fs::read(&decrypted_path).unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn test_read_metadata() {
        let mut plaintext_file = NamedTempFile::new().unwrap();
        plaintext_file.write_all(b"test data").unwrap();

        let encrypted_path = NamedTempFile::new().unwrap().into_temp_path();

        let (file_id, _key) = FileEncryptor::encrypt_file(
            plaintext_file.path(),
            &encrypted_path,
            Some("test-file-id".to_string()),
        )
        .unwrap();

        let metadata = FileEncryptor::read_metadata(&encrypted_path).unwrap();
        assert_eq!(metadata.file_id, "test-file-id");
        assert_eq!(file_id, "test-file-id");
    }
}
