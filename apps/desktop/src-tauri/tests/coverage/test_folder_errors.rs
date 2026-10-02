// Verify missing-workspace messages do not conceal folder ownership and other actionable errors.
use super::*;

#[test]
fn actual_missing_group_errors_receive_the_workspace_message() {
    for message in [
        "Cannot enroll coverage root without an active group. Run 'hybridcipher switch-group <group-id>' first.",
        "No active group selected. Run 'hybridcipher switch-group <group-id>' and retry.",
    ] {
        assert_eq!(desktop_safe_client_error(message), NO_WORKSPACE_AVAILABLE_MESSAGE);
    }
}

#[test]
fn ownership_and_encryption_errors_are_preserved() {
    for message in [
        "Coverage root belongs to group 123. Run 'hybridcipher switch-group 123' to manage it.",
        "Cannot protect folder: it overlaps an active protected folder in another workspace.",
        "Cannot protect folder: encrypted data remains. Remove protection with decryption first.",
    ] {
        assert_eq!(desktop_safe_client_error(message), message);
    }
}
