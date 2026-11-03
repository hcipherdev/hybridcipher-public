//! Confined, non-overwriting plaintext restoration.
use super::durability::OutputDurability;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
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
    write_new_with(path, data, OutputDurability::Full)
}

/// As [`write_new`], with the caller choosing how the output is synced.
pub fn write_new_with(path: &Path, data: &[u8], durability: OutputDurability) -> io::Result<()> {
    write_new_from_reader(path, &mut io::Cursor::new(data), durability)
}

/// Publish a fully authenticated private restore through the same guarded,
/// non-overwriting destination check as write_new, without loading it in memory.
pub fn publish_new(path: &Path, authenticated_private_path: &Path) -> io::Result<()> {
    publish_new_with(path, authenticated_private_path, OutputDurability::Full)
}

/// As [`publish_new`], with the caller choosing how the output is synced.
pub fn publish_new_with(
    path: &Path,
    authenticated_private_path: &Path,
    durability: OutputDurability,
) -> io::Result<()> {
    let mut source = File::open(authenticated_private_path)?;
    write_new_from_reader(path, &mut source, durability)
}

fn write_new_from_reader(
    path: &Path,
    source: &mut impl Read,
    durability: OutputDurability,
) -> io::Result<()> {
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
            let mut metadata = fs::symlink_metadata(&current)?;
            if metadata.file_type().is_symlink() && is_trusted_system_link(&current)? {
                // e.g. macOS /var -> private/var: follow it and keep checking from its target.
                current = fs::canonicalize(&current)?;
                metadata = fs::symlink_metadata(&current)?;
            }
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Symlink in output directory",
                ));
            }
        }
    }
    // Create the file in the folder that was checked, not through the original path.
    let output = current.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)?;
    // Retain ciphertext on every error. A partial output is a visible conflict
    // for recovery, and must never cause the source to be removed.
    let result = io::copy(source, &mut file).and_then(|_| durability.apply(&file));
    drop(file);
    if let Err(err) = result {
        let _ = fs::remove_file(&output);
        return Err(err);
    }
    drop(directory_guards);
    Ok(())
}

/// A link only root could have made or changed: owned by root, in a root-owned folder that
/// no one else can write to. Operating-system links such as macOS `/var`, `/tmp` and `/etc`
/// qualify; links a user or another program planted do not.
#[cfg(unix)]
fn is_trusted_system_link(link: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = link.parent() else {
        return Ok(false);
    };
    let link_metadata = fs::symlink_metadata(link)?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    Ok(link_metadata.uid() == 0
        && parent_metadata.is_dir()
        && parent_metadata.uid() == 0
        && parent_metadata.mode() & 0o022 == 0)
}

#[cfg(all(not(unix), not(windows)))]
fn is_trusted_system_link(_link: &Path) -> io::Result<bool> {
    Ok(false)
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

    #[test]
    fn publishes_authenticated_private_file_without_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let private = root.path().join("private.plain");
        let output = root.path().join("published.txt");
        fs::write(&private, b"authenticated").unwrap();
        publish_new(&output, &private).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"authenticated");
        assert!(publish_new(&output, &private).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"authenticated");
        assert_eq!(fs::read(&private).unwrap(), b"authenticated");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_a_symlink_planted_inside_the_output_path() {
        let root = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let link = root.path().join("redirect");
        std::os::unix::fs::symlink(elsewhere.path(), &link).unwrap();
        let err = write_new(&link.join("file.txt"), b"data").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(!elsewhere.path().join("file.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn only_root_owned_links_in_protected_folders_are_trusted() {
        let root = tempfile::tempdir().unwrap();
        let link = root.path().join("mine");
        std::os::unix::fs::symlink(root.path(), &link).unwrap();
        assert!(!is_trusted_system_link(&link).unwrap());
        #[cfg(target_os = "macos")]
        assert!(is_trusted_system_link(Path::new("/var")).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn refuses_windows_junction_escape() {
        let root = tempfile::tempdir().unwrap();
        let outside = root.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let junction = root.path().join("redirect");
        let command = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32")
            .join("cmd.exe");
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
        assert_eq!(
            write_new(&junction.join("escaped.txt"), b"secret")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!outside.join("escaped.txt").exists());
        fs::remove_dir(&junction).unwrap();
    }
}
