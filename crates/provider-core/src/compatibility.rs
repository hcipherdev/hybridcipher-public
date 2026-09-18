use crate::{ProviderCoreError, ProviderEntry, ProviderFileErrorCode, Result};
use hybridcipher_client::file::content_manifest::{
    requires_legacy_compatibility, LegacyReadPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    },
};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultCompatibilityStatus {
    pub root_id: Uuid,
    pub enabled: bool,
    pub legacy_file_count: usize,
    pub last_read_error: Option<ProviderFileErrorCode>,
    pub encrypted_backup_directory: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPolicy {
    schema_version: u16,
    root_id: Uuid,
    enabled: bool,
}

/// Account-local preferences and encrypted originals deliberately outlive mounts.
pub struct VaultCompatibility {
    root_id: Uuid,
    policy_path: PathBuf,
    backup_directory: PathBuf,
    enabled: AtomicBool,
    legacy_files: AtomicUsize,
    last_read_error: AtomicUsize,
    writer: Mutex<()>,
}

impl VaultCompatibility {
    pub fn load(user_directory: &Path, root_id: Uuid) -> Result<Self> {
        let policy_path = user_directory
            .join("vault_compatibility")
            .join(format!("{root_id}.json"));
        let enabled = match fs::read(&policy_path) {
            Ok(bytes) => {
                let saved: SavedPolicy = serde_json::from_slice(&bytes)?;
                if saved.schema_version != 1 || saved.root_id != root_id {
                    return Err(ProviderCoreError::InvalidIdentity(
                        "Invalid vault compatibility preference".into(),
                    ));
                }
                saved.enabled
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            root_id,
            policy_path,
            backup_directory: user_directory
                .join("recovery")
                .join("legacy_ciphertext")
                .join(root_id.to_string()),
            enabled: AtomicBool::new(enabled),
            legacy_files: AtomicUsize::new(0),
            last_read_error: AtomicUsize::new(0),
            writer: Mutex::new(()),
        })
    }

    pub fn policy(&self) -> LegacyReadPolicy {
        if self.enabled.load(Ordering::Acquire) {
            LegacyReadPolicy::AllowLegacyUnverified
        } else {
            LegacyReadPolicy::Strict
        }
    }

    pub fn status(&self) -> VaultCompatibilityStatus {
        VaultCompatibilityStatus {
            root_id: self.root_id,
            enabled: self.enabled.load(Ordering::Acquire),
            legacy_file_count: self.legacy_files.load(Ordering::Acquire),
            last_read_error: match self.last_read_error.load(Ordering::Acquire) {
                1 => Some(ProviderFileErrorCode::LegacyConsentRequired),
                2 => Some(ProviderFileErrorCode::IntegrityFailure),
                _ => None,
            },
            encrypted_backup_directory: self.backup_directory.clone(),
        }
    }

    pub fn set_enabled(&self, enabled: bool) -> Result<VaultCompatibilityStatus> {
        let _writer = self.writer.lock().map_err(|_| {
            ProviderCoreError::InvalidIdentity("Compatibility preference lock poisoned".into())
        })?;
        let parent = self.policy_path.parent().unwrap();
        fs::create_dir_all(parent)?;
        let parent = fs::canonicalize(parent)?;
        let destination = parent.join(self.policy_path.file_name().unwrap());
        let mut temporary = tempfile::NamedTempFile::new_in(&parent)?;
        serde_json::to_writer(
            &mut temporary,
            &SavedPolicy {
                schema_version: 1,
                root_id: self.root_id,
                enabled,
            },
        )?;
        temporary.as_file().sync_all()?;
        persist_durably(temporary, &destination, true)?;
        self.enabled.store(enabled, Ordering::Release);
        self.last_read_error.store(0, Ordering::Release);
        Ok(self.status())
    }

    pub(crate) fn record_read_result<T>(
        &self,
        result: &std::result::Result<T, hybridcipher_mount_sync::MountSyncError>,
    ) {
        use hybridcipher_mount_sync::MountSyncError;
        let code = match result {
            Err(MountSyncError::LegacyCompatibilityRequired) => 1,
            Err(MountSyncError::FileIntegrity(_)) => 2,
            _ => return,
        };
        self.last_read_error.store(code, Ordering::Release);
    }

    pub(crate) fn observe(&self, entries: &[ProviderEntry]) {
        self.legacy_files.store(
            entries
                .iter()
                .filter(|e| {
                    e.metadata
                        .as_ref()
                        .is_some_and(requires_legacy_compatibility)
                })
                .count(),
            Ordering::Release,
        );
    }

    /// Snapshot ciphertext before a destructive operation; never archive plaintext.
    pub(crate) fn preserve(
        &self,
        root_id: Uuid,
        encrypted_path: &Path,
    ) -> Result<Option<PreservedCiphertext>> {
        self.preserve_with_copy(root_id, encrypted_path, |input, output| {
            copy_and_digest(input, output)
        })
    }

    pub(crate) fn preserve_with_copy(
        &self,
        root_id: Uuid,
        encrypted_path: &Path,
        copy: impl FnOnce(&mut fs::File, &mut tempfile::NamedTempFile) -> std::io::Result<String>,
    ) -> Result<Option<PreservedCiphertext>> {
        if root_id != self.root_id {
            return Err(ProviderCoreError::InvalidIdentity(
                "Backup belongs to another vault".into(),
            ));
        }
        if !encrypted_path.exists() {
            return Ok(None);
        }
        let parsed = hybridcipher_mount_sync::parse_encrypted_file(encrypted_path)?;
        if !requires_legacy_compatibility(&parsed.metadata) {
            return Ok(None);
        }
        let object = digest_bytes(parsed.metadata.file_id.as_bytes());
        let directory = self.backup_directory.join(object);
        fs::create_dir_all(&directory)?;
        let directory = fs::canonicalize(directory)?;
        let mut source = fs::File::open(encrypted_path)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        let digest = copy(&mut source, &mut temporary)?;
        temporary.as_file().sync_all()?;
        let destination = directory.join(format!("{digest}.encrypted"));
        match persist_durably(temporary, &destination, false) {
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if digest_file(&destination)? != digest {
                    return Err(ProviderCoreError::InvalidIdentity(
                        "Encrypted recovery copy failed verification".into(),
                    ));
                }
            }
            Err(e) => return Err(e.into()),
        }
        let preserved = PreservedCiphertext {
            source: encrypted_path.to_owned(),
            digest,
        };
        preserved.verify_current()?;
        Ok(Some(preserved))
    }
}

pub(crate) struct PreservedCiphertext {
    source: PathBuf,
    digest: String,
}
impl PreservedCiphertext {
    pub fn verify_current(&self) -> Result<()> {
        if digest_file(&self.source)? != self.digest {
            return Err(ProviderCoreError::ContentConflict {
                path: self.source.to_string_lossy().into_owned(),
                expected: None,
                actual: None,
            });
        }
        Ok(())
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn copy_and_digest(input: &mut impl Read, output: &mut impl Write) -> std::io::Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
        output.write_all(&buffer[..n])?;
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn digest_file(path: &Path) -> std::io::Result<String> {
    copy_and_digest(&mut fs::File::open(path)?, &mut std::io::sink())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledgment_is_persistent_and_vault_scoped() {
        let account = tempfile::tempdir().unwrap();
        let root = Uuid::new_v4();
        let policy = VaultCompatibility::load(account.path(), root).unwrap();
        assert_eq!(policy.policy(), LegacyReadPolicy::Strict);
        policy.set_enabled(true).unwrap();
        assert_eq!(policy.policy(), LegacyReadPolicy::AllowLegacyUnverified);
        assert!(
            VaultCompatibility::load(account.path(), root)
                .unwrap()
                .status()
                .enabled
        );
        assert!(
            !VaultCompatibility::load(account.path(), Uuid::new_v4())
                .unwrap()
                .status()
                .enabled
        );
        policy.set_enabled(false).unwrap();
        assert!(
            !VaultCompatibility::load(account.path(), root)
                .unwrap()
                .status()
                .enabled
        );
    }
}

/// Complete the directory-entry update before allowing replacement of an original.
fn persist_durably(
    temporary: tempfile::NamedTempFile,
    destination: &Path,
    replace: bool,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::core::PCWSTR;
        use windows::Win32::Storage::FileSystem::{
            MoveFileExW, SetFileAttributesW, FILE_ATTRIBUTE_NORMAL, MOVEFILE_REPLACE_EXISTING,
            MOVEFILE_WRITE_THROUGH,
        };
        let source: Vec<_> = temporary
            .path()
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let destination: Vec<_> = destination
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let mut flags = MOVEFILE_WRITE_THROUGH;
        if replace {
            flags |= MOVEFILE_REPLACE_EXISTING;
        }
        unsafe {
            SetFileAttributesW(PCWSTR(source.as_ptr()), FILE_ATTRIBUTE_NORMAL)
                .map_err(|_| std::io::Error::last_os_error())?;
            MoveFileExW(PCWSTR(source.as_ptr()), PCWSTR(destination.as_ptr()), flags)
                .map_err(|_| std::io::Error::last_os_error())?;
        }
        temporary.as_file().sync_all()?;
    }
    #[cfg(not(windows))]
    {
        if replace {
            temporary.persist(destination).map_err(|e| e.error)?;
        } else {
            temporary
                .persist_noclobber(destination)
                .map_err(|e| e.error)?;
        }
        fs::File::open(destination.parent().unwrap())?.sync_all()?;
    }
    Ok(())
}
