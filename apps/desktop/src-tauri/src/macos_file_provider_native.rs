use hybridcipher_macos_file_provider::FileProviderDomainRegistration;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn HCFileProviderRegisterDomain(
        domain_id: *const c_char,
        display_name: *const c_char,
    ) -> *mut c_char;
    fn HCFileProviderSignalDomain(
        domain_id: *const c_char,
        container_ids: *const c_char,
    ) -> *mut c_char;
    fn HCFileProviderUnregisterDomain(domain_id: *const c_char) -> *mut c_char;
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

pub fn unregister_domain(registration: &FileProviderDomainRegistration) -> Result<(), String> {
    let domain_id = cstring("domain identifier", &registration.domain_identifier)?;
    unsafe { error_ptr_to_result(HCFileProviderUnregisterDomain(domain_id.as_ptr())) }
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
    hybridcipher_macos_file_provider::set_domain_signal_handler(|domain_identifier, container_ids| {
        signal_domain(domain_identifier, container_ids)
    });
}

fn cstring(label: &str, value: &str) -> Result<CString, String> {
    CString::new(value).map_err(|_| format!("File Provider {label} contains an interior NUL byte"))
}

unsafe fn error_ptr_to_result(error: *mut c_char) -> Result<(), String> {
    if error.is_null() {
        return Ok(());
    }
    let message = CStr::from_ptr(error).to_string_lossy().into_owned();
    HCFileProviderFreeCString(error);
    Err(message)
}
