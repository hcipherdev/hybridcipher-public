// Tests device_trust_hint() in src/ui/error.rs and CliError::network_from() in src/error.rs.
use super::*;

#[test]
fn unverified_device_refusals_get_a_verification_hint() {
    for message in [
        "Server returned 428 Precondition Required",
        "Add member failed: 428",
        r#"{"code":"device_trust_required","error":"Team administration needs a verified device."}"#,
    ] {
        assert!(
            device_trust_hint(message)
                .unwrap()
                .contains("confirm-trust"),
            "{message}"
        );
    }
    assert!(device_trust_hint("Server returned 403 Forbidden").is_none());
    assert!(device_trust_hint("Upload of file 14281 failed: 500").is_none());
}

#[derive(Debug)]
struct Layer(&'static str, Option<Box<Layer>>);
impl std::fmt::Display for Layer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Layer {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.1
            .as_deref()
            .map(|cause| cause as &(dyn std::error::Error + 'static))
    }
}

#[test]
fn network_errors_keep_their_underlying_cause_once() {
    let error = Layer(
        "error sending request for url (https://api.example.test/verify)",
        Some(Box::new(Layer(
            "client error (SendRequest)",
            Some(Box::new(Layer("connection reset by peer", None))),
        ))),
    );
    assert_eq!(
        crate::error::CliError::network_from(&error).to_string(),
        "Network error: error sending request for url (https://api.example.test/verify): client error (SendRequest): connection reset by peer"
    );
    let repeated = Layer("timed out", Some(Box::new(Layer("timed out", None))));
    assert_eq!(
        crate::error::CliError::network_from(&repeated).to_string(),
        "Network error: timed out"
    );
}
