// Tests the CLI recovery artifact adapter for shared-format compatibility and authenticated unlock errors.
use super::*;

#[test]
fn test_cli_artifact_roundtrips_shared_format_and_returns_cli_errors() {
    let original = BackupArtifact::new("test-password", &[7; 32]).unwrap();
    let encoded = original.to_base64().unwrap();
    let shared = shared::BackupArtifact::from_base64(&encoded).unwrap();
    let adapted = BackupArtifact::from_base64(&shared.to_base64().unwrap()).unwrap();
    assert_eq!(
        adapted
            .unwrap_file_key("test-password", &[7; 32])
            .unwrap()
            .as_ref(),
        shared
            .unwrap_file_key("test-password", &[7; 32])
            .unwrap()
            .as_ref()
    );
    assert!(adapted.unlock("test-password", &[8; 32]).is_err());
}
