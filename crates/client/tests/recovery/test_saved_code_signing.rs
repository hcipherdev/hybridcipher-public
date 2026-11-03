// Tests recovery signing separates raw code authority by account, credential, generation, and salt.
use super::*;

fn credential() -> RecoveryCredential {
    RecoveryCredential {
        credential_id: Uuid::new_v4().to_string(),
        generation: 1,
        salt_b64: STANDARD.encode([7u8; 32]),
        public_key_b64: String::new(),
        recovery_envelope_sha256: "ab".repeat(32),
    }
}

#[test]
fn raw_code_authority_is_domain_and_generation_separated() {
    let credential = credential();
    let code = [11u8; 32];
    let baseline = recovery_signing_identity(&code, "account-a", &credential)
        .unwrap()
        .public_key_bytes();
    assert_eq!(
        baseline,
        recovery_signing_identity(&code, "account-a", &credential)
            .unwrap()
            .public_key_bytes()
    );
    assert_ne!(
        baseline,
        recovery_signing_identity(&code, "account-b", &credential)
            .unwrap()
            .public_key_bytes()
    );
    assert_ne!(
        baseline,
        recovery_signing_identity(&[12u8; 32], "account-a", &credential)
            .unwrap()
            .public_key_bytes()
    );
    let mut rotated = credential.clone();
    rotated.generation += 1;
    assert_ne!(
        baseline,
        recovery_signing_identity(&code, "account-a", &rotated)
            .unwrap()
            .public_key_bytes()
    );
    rotated = credential.clone();
    rotated.credential_id = Uuid::new_v4().to_string();
    assert_ne!(
        baseline,
        recovery_signing_identity(&code, "account-a", &rotated)
            .unwrap()
            .public_key_bytes()
    );
    rotated = credential.clone();
    rotated.salt_b64 = STANDARD.encode([8u8; 32]);
    assert_ne!(
        baseline,
        recovery_signing_identity(&code, "account-a", &rotated)
            .unwrap()
            .public_key_bytes()
    );
}

#[test]
fn malformed_recovery_credential_cannot_derive_signing_authority() {
    let mut credential = credential();
    assert!(recovery_signing_identity(&[1u8; 31], "account", &credential).is_err());
    credential.generation = 0;
    assert!(recovery_signing_identity(&[1u8; 32], "account", &credential).is_err());
    credential.generation = 1;
    credential.credential_id = "not-a-uuid".into();
    assert!(recovery_signing_identity(&[1u8; 32], "account", &credential).is_err());
    credential.credential_id = Uuid::new_v4().to_string();
    credential.salt_b64 = STANDARD.encode([1u8; 16]);
    assert!(recovery_signing_identity(&[1u8; 32], "account", &credential).is_err());
}
