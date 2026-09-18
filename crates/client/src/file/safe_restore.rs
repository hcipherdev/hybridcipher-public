//! Confined, non-overwriting plaintext restoration.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Component, Path, PathBuf},
};

/// Validate a portable single filename, including Windows device/stream rules.
pub fn validate_name(name: &str) -> io::Result<()> {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|c| c.is_control() || "\\/:<>\"|?*".contains(c))
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || ["COM", "LPT"].iter().any(|p| {
            stem.strip_prefix(p).is_some_and(|n| {
                matches!(
                    n,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unsafe restored filename",
        ));
    }
    Ok(())
}

/// Resolve a restored filename in the source's parent directory.
pub fn destination(source: &Path, name: Option<&str>) -> io::Result<PathBuf> {
    match name {
        Some(name) => {
            validate_name(name)?;
            Ok(source.parent().unwrap_or(Path::new(".")).join(name))
        }
        None => Ok(source.with_extension("decrypted")),
    }
}

/// Create a new plaintext file. Windows ancestor handles prevent directory
/// replacement while writing; reparse points and existing outputs are rejected.
pub fn write_new(path: &Path, data: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Invalid output filename"))?;
    validate_name(name)?;
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Missing output directory"))?;
    let mut current = PathBuf::new();
    let mut directory_guards = Vec::<File>::new();
    for component in parent.components() {
        if component == Component::ParentDir {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Traversal in output directory",
            ));
        }
        current.push(component);
        if matches!(
            component,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            // Open the directory itself, without following a reparse point.
            // Omit FILE_SHARE_DELETE so it cannot be renamed/replaced until done.
            let guard = OpenOptions::new()
                .access_mode(0)
                .share_mode(3)
                .custom_flags(0x02000000 | 0x00200000)
                .open(&current)?;
            let metadata = guard.metadata()?;
            let mut redirects = false;
            if metadata.file_attributes() & 0x400 != 0 {
                use std::os::windows::io::AsRawHandle;
                use winapi::um::{
                    fileapi::FILE_ATTRIBUTE_TAG_INFO, minwinbase::FileAttributeTagInfo,
                    winbase::GetFileInformationByHandleEx,
                };
                // This is a pair of DWORDs; winapi 0.3 misnames the first field.
                let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
                // The handle pins this exact directory; name-surrogate tags can
                // redirect resolution. Cloud Files tags do not redirect names.
                let ok = unsafe {
                    GetFileInformationByHandleEx(
                        guard.as_raw_handle().cast(),
                        FileAttributeTagInfo,
                        (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                        std::mem::size_of_val(&tag) as u32,
                    )
                };
                if ok == 0 {
                    return Err(io::Error::last_os_error());
                }
                redirects = tag.ReparseTag & 0x20000000 != 0;
            }
            if !metadata.is_dir() || redirects {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Reparse point in output directory",
                ));
            }
            directory_guards.push(guard);
        }
        #[cfg(not(windows))]
        {
            let metadata = fs::symlink_metadata(&current)?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Symlink in output directory",
                ));
            }
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&absolute)?;
    // Retain ciphertext on every error. A partial output is a visible conflict
    // for recovery, and must never cause the source to be removed.
    file.write_all(data)?;
    file.sync_all()?;
    drop(directory_guards);
    Ok(())
}

#[cfg(test)]
mod security_regression {
    use super::*;
    #[test]
    fn rejects_windows_escape_and_device_names() {
        for name in [
            "../secret",
            "..\\secret",
            "C:\\secret",
            "\\\\host\\share",
            "file:stream",
            "CON.txt",
            "CON .txt",
            "LPT1",
            "COM¹.txt",
            "x.",
            "x ",
            "",
            "..",
        ] {
            assert!(validate_name(name).is_err(), "{name}");
        }
        assert!(validate_name("my report.v2.txt").is_ok());
    }
    #[test]
    fn restores_without_overwriting_existing_data() {
        let root = std::env::temp_dir().join(format!("hc-restore-{}", uuid::Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let output = root.join("file.txt");
        write_new(&output, b"original").unwrap();
        assert!(write_new(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"original");
        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_windows_junction_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let junction = root.path().join("redirect");
        let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32").join("cmd.exe");
        let result = std::process::Command::new(command)
            .args(["/d", "/c", "mklink", "/J"])
            .arg(junction.to_string_lossy().trim_start_matches("\\\\?\\"))
            .arg(outside.to_string_lossy().trim_start_matches("\\\\?\\"))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(write_new(&junction.join("escaped.txt"), b"secret").unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert!(!outside.join("escaped.txt").exists());
        fs::remove_dir(&junction).unwrap();
    }
}
