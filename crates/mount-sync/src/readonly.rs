//! Reversible OS permissions for a mounted view; journals allow recovery after a crash.

use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
struct Journal {
    root: PathBuf,
    originals: BTreeMap<PathBuf, String>,
}

pub struct ReadOnlyMount {
    applied: bool,
    journal_path: PathBuf,
    journal: Journal,
}

impl ReadOnlyMount {
    pub fn open(root: &Path, journal_path: PathBuf) -> io::Result<Self> {
        let root = root.canonicalize()?;
        if journal_path.starts_with(&root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Permission journal must be outside the mounted view",
            ));
        }
        let journal = match fs::read(&journal_path) {
            Ok(raw) => {
                let journal: Journal = serde_json::from_slice(&raw)?;
                if journal.root != root || journal.originals.keys().any(|path| !safe_relative(path))
                {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Permission journal belongs to another mount",
                    ));
                }
                journal
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Journal {
                root,
                originals: BTreeMap::new(),
            },
            Err(err) => return Err(err),
        };
        Ok(Self {
            journal_path,
            journal,
            applied: false,
        })
    }

    /// Include newly hydrated files without replacing their original permissions.
    pub fn set_read_only(&mut self, enabled: bool) -> io::Result<()> {
        if !enabled {
            return self.restore();
        }
        if self.applied {
            return Ok(());
        }
        let mut stack = vec![self.journal.root.clone()];
        let mut paths = Vec::new();
        while let Some(path) = stack.pop() {
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                for entry in fs::read_dir(&path)? {
                    stack.push(entry?.path());
                }
            }
            let relative = path
                .strip_prefix(&self.journal.root)
                .map_err(io::Error::other)?
                .to_path_buf();
            if !self.journal.originals.contains_key(&relative) {
                self.journal
                    .originals
                    .insert(relative.clone(), permissions::capture(&path)?);
            }
            paths.push((path, relative));
        }
        // Persist every original before changing any permission.
        self.save()?;
        for (path, relative) in paths {
            permissions::deny_write(&path, &self.journal.originals[&relative])?;
        }
        self.applied = true;
        Ok(())
    }

    pub fn restore(&mut self) -> io::Result<()> {
        if self.journal.originals.is_empty() {
            self.applied = false;
            return Ok(());
        }
        for (relative, original) in &self.journal.originals {
            let path = self.journal.root.join(relative);
            // Refuse symlinks and replaced ancestors when replaying a journal.
            let mut ancestor = Some(path.as_path());
            while let Some(current) = ancestor {
                if !current.starts_with(&self.journal.root) {
                    break;
                }
                match fs::symlink_metadata(current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Permission recovery refuses a symlink",
                        ))
                    }
                    Ok(_) => {}
                    Err(err) if err.kind() == io::ErrorKind::NotFound => break,
                    Err(err) => return Err(err),
                }
                ancestor = current.parent();
            }
            if path.exists() {
                permissions::restore(&path, original)?;
            }
        }
        self.journal.originals.clear();
        self.applied = false;
        match fs::remove_file(&self.journal_path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.journal_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self
            .journal_path
            .with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let raw = serde_json::to_vec(&self.journal)?;
        let result = (|| {
            use std::io::Write;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            file.write_all(&raw)?;
            file.sync_all()?;
            fs::rename(&tmp, &self.journal_path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}

fn safe_relative(path: &Path) -> bool {
    path.components().all(|part| {
        matches!(
            part,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    })
}

#[cfg(unix)]
mod permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    pub fn capture(path: &Path) -> io::Result<String> {
        Ok(fs::metadata(path)?.permissions().mode().to_string())
    }
    fn mode(original: &str) -> io::Result<u32> {
        original
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid permission mode"))
    }
    pub fn deny_write(path: &Path, original: &str) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode(original)? & !0o222))
    }
    pub fn restore(path: &Path, original: &str) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode(original)?))
    }
}

#[cfg(target_os = "windows")]
mod permissions {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::{PCWSTR, PWSTR},
        Win32::{
            Foundation::{LocalFree, HLOCAL},
            Security::{
                Authorization::{
                    ConvertSecurityDescriptorToStringSecurityDescriptorW,
                    ConvertStringSecurityDescriptorToSecurityDescriptorW,
                },
                GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION,
                PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
                UNPROTECTED_DACL_SECURITY_INFORMATION,
            },
        },
    };
    fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }
    pub fn capture(path: &Path) -> io::Result<String> {
        let path = wide(path);
        unsafe {
            let mut size = 0;
            let _ = GetFileSecurityW(
                PCWSTR(path.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                None,
                0,
                &mut size,
            );
            if size == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut buffer = vec![0u8; size as usize];
            let descriptor = PSECURITY_DESCRIPTOR(buffer.as_mut_ptr().cast());
            if !GetFileSecurityW(
                PCWSTR(path.as_ptr()),
                DACL_SECURITY_INFORMATION.0,
                Some(descriptor),
                size,
                &mut size,
            )
            .as_bool()
            {
                return Err(io::Error::last_os_error());
            }
            let mut text = PWSTR::null();
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                None,
            )
            .map_err(io::Error::other)?;
            let result = text.to_string().map_err(io::Error::other);
            let _ = LocalFree(Some(HLOCAL(text.0.cast())));
            result
        }
    }
    fn apply(path: &Path, sddl: &str, protected: bool) -> io::Result<()> {
        let path = wide(path);
        let sddl: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        unsafe {
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                1,
                &mut descriptor,
                None,
            )
            .map_err(io::Error::other)?;
            let flags = DACL_SECURITY_INFORMATION
                | if protected {
                    PROTECTED_DACL_SECURITY_INFORMATION
                } else {
                    UNPROTECTED_DACL_SECURITY_INFORMATION
                };
            let ok = SetFileSecurityW(PCWSTR(path.as_ptr()), flags, descriptor).as_bool();
            let error = if ok {
                None
            } else {
                Some(io::Error::last_os_error())
            };
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            match error {
                Some(error) => Err(error),
                None => Ok(()),
            }
        }
    }
    pub fn deny_write(path: &Path, original: &str) -> io::Result<()> {
        let (_, aces) = original
            .split_once('(')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing mount DACL"))?;
        // Deny data/append/create/delete to every interactive writer. Attribute
        // writes stay available for Cloud Files hydration and synchronization.
        apply(path, &format!("D:P(D;;0x10046;;;WD)({aces}"), true)
    }
    pub fn restore(path: &Path, original: &str) -> io::Result<()> {
        let protected = original.split('(').next().unwrap_or_default().contains('P');
        apply(path, original, protected)
    }
}

#[cfg(not(any(unix, target_os = "windows")))]
mod permissions {
    use super::*;
    pub fn capture(_: &Path) -> io::Result<String> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Read-only mounts unsupported",
        ))
    }
    pub fn deny_write(_: &Path, _: &str) -> io::Result<()> {
        capture(Path::new("")).map(|_| ())
    }
    pub fn restore(_: &Path, _: &str) -> io::Result<()> {
        capture(Path::new("")).map(|_| ())
    }
}

#[cfg(test)]
#[path = "../tests/licensing/test_readonly.rs"]
mod tests;
