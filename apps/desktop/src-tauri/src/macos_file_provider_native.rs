use hybridcipher_macos_file_provider::FileProviderDomainRegistration;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};

extern "C" {
    fn HCFileProviderRegisterDomain(
        domain_id: *const c_char,
        display_name: *const c_char,
    ) -> *mut c_char;
    fn HCFileProviderSignalDomain(
        domain_id: *const c_char,
        container_ids: *const c_char,
    ) -> *mut c_char;
    fn HCFileProviderUnregisterDomain(
        domain_id: *const c_char,
        preserved_path_out: *mut *mut c_char,
    ) -> *mut c_char;
    fn HCFileProviderWaitForPendingChanges(
        domain_id: *const c_char,
        timeout_secs: std::os::raw::c_uint,
    ) -> *mut c_char;
    fn HCFileProviderResolveServerUnreachable(domain_id: *const c_char) -> *mut c_char;
    fn HCFileProviderUserVisibleURL(
        domain_id: *const c_char,
        path_out: *mut *mut c_char,
    ) -> *mut c_char;
    fn HCFileProviderFreeCString(value: *mut c_char);
}

pub fn register_domain(registration: &FileProviderDomainRegistration) -> Result<(), String> {
    let domain_id = cstring("domain identifier", &registration.domain_identifier)?;
    let display_name = cstring("display name", &registration.display_name)?;
    unsafe {
        error_ptr_to_result(HCFileProviderRegisterDomain(
            domain_id.as_ptr(),
            display_name.as_ptr(),
        ))
    }
}

/// Removes the domain. Edits macOS had not yet handed to the extension are
/// moved to a preserved folder, which is logged and opened in Finder.
pub fn unregister_domain(registration: &FileProviderDomainRegistration) -> Result<(), String> {
    let domain_id = cstring("domain identifier", &registration.domain_identifier)?;
    let mut preserved_path: *mut c_char = std::ptr::null_mut();
    let result = unsafe {
        error_ptr_to_result(HCFileProviderUnregisterDomain(
            domain_id.as_ptr(),
            &mut preserved_path,
        ))
    };
    let preserved_path = unsafe { take_c_string(preserved_path) }.map(PathBuf::from);
    if let Some(path) = preserved_path.filter(|path| directory_has_entries(path)) {
        tracing::warn!(
            "macOS kept unsynced File Provider edits for {} ({}) at {}",
            registration.display_name,
            registration.root_id,
            path.display()
        );
        if let Err(err) = std::process::Command::new("open").arg(&path).spawn() {
            tracing::warn!(
                "Failed to open preserved File Provider edits at {}: {}",
                path.display(),
                err
            );
        }
    }
    result
}

/// Waits up to `timeout_secs` for macOS to hand the domain's pending edits to
/// the extension. Blocks; call it off the async runtime.
pub fn wait_for_pending_changes(domain_identifier: &str, timeout_secs: u32) -> Result<(), String> {
    let domain_id = cstring("domain identifier", domain_identifier)?;
    unsafe {
        error_ptr_to_result(HCFileProviderWaitForPendingChanges(
            domain_id.as_ptr(),
            timeout_secs,
        ))
    }
}

/// Lifts the backoff macOS applies after the extension reported the bridge as
/// unreachable, so the domain syncs again now that the bridge is up. Blocks;
/// call it off the async runtime.
pub fn resolve_server_unreachable(domain_identifier: &str) -> Result<(), String> {
    let domain_id = cstring("domain identifier", domain_identifier)?;
    unsafe { error_ptr_to_result(HCFileProviderResolveServerUnreachable(domain_id.as_ptr())) }
}

/// Lifts the "server unreachable" backoff, then asks macOS to check the
/// domain for changes, which connects the extension to the bridge. A signal
/// alone is ignored while macOS backs the domain off. Blocks.
pub fn wake_domain(domain_identifier: &str) -> Result<(), String> {
    let resolved = resolve_server_unreachable(domain_identifier);
    if let Err(err) = &resolved {
        tracing::warn!(
            "Could not clear the File Provider backoff for {}: {}",
            domain_identifier,
            err
        );
    }
    let signalled = signal_domain(domain_identifier, &[]);
    resolved.and(signalled)
}

/// The folder macOS created for the domain, e.g. under ~/Library/CloudStorage.
pub fn user_visible_url(domain_identifier: &str) -> Result<PathBuf, String> {
    let domain_id = cstring("domain identifier", domain_identifier)?;
    let mut path: *mut c_char = std::ptr::null_mut();
    let result =
        unsafe { error_ptr_to_result(HCFileProviderUserVisibleURL(domain_id.as_ptr(), &mut path)) };
    let path = unsafe { take_c_string(path) };
    result?;
    path.map(PathBuf::from)
        .ok_or_else(|| "File Provider returned no location for the domain".to_string())
}

fn directory_has_entries(path: &Path) -> bool {
    std::fs::read_dir(path)
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

pub fn signal_domain(domain_identifier: &str, container_ids: &[String]) -> Result<(), String> {
    let domain_id = cstring("domain identifier", domain_identifier)?;
    let encoded_container_ids = cstring("container identifiers", &container_ids.join("\n"))?;
    unsafe {
        error_ptr_to_result(HCFileProviderSignalDomain(
            domain_id.as_ptr(),
            encoded_container_ids.as_ptr(),
        ))
    }
}

pub fn install_domain_signal_handler() {
    hybridcipher_macos_file_provider::set_domain_signal_handler(
        |domain_identifier, container_ids| signal_domain(domain_identifier, container_ids),
    );
}

fn cstring(label: &str, value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("File Provider {label} contains an interior NUL byte"))
}

unsafe fn error_ptr_to_result(error: *mut c_char) -> Result<(), String> {
    match take_c_string(error) {
        Some(message) => Err(message),
        None => Ok(()),
    }
}

unsafe fn take_c_string(value: *mut c_char) -> Option<String> {
    if value.is_null() {
        return None;
    }
    let text = CStr::from_ptr(value).to_string_lossy().into_owned();
    HCFileProviderFreeCString(value);
    Some(text)
}
