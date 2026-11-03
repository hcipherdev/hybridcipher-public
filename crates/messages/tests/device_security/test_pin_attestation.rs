// Tests PinAttestation::sign() and verify() in crates/messages/src/pin_attestation.rs: only the verifier's identity key validates a statement, and any change to it breaks the signature.
use super::*;

fn signed(verifier: &Ed25519KeyPair) -> PinAttestation {
    PinAttestation::sign(
        verifier,
        "user-chen",
        "device_mac",
        "user-xing",
        "device_97209c",
        &[7u8; 32],
        Utc::now(),
    )
    .expect("sign")
}

#[test]
fn the_verifiers_key_validates_its_statement() {
    let verifier = Ed25519KeyPair::generate();
    let attestation = signed(&verifier);
    attestation
        .verify(&verifier.public_key_bytes())
        .expect("verifies with the verifier's key");
    // Round-trips through the server's JSON unchanged.
    let relayed: PinAttestation =
        serde_json::from_value(serde_json::to_value(&attestation).unwrap()).unwrap();
    relayed.verify(&verifier.public_key_bytes()).expect("still verifies");
}

#[test]
fn another_key_or_any_change_is_rejected() {
    let verifier = Ed25519KeyPair::generate();
    let attestation = signed(&verifier);
    assert!(attestation
        .verify(&Ed25519KeyPair::generate().public_key_bytes())
        .is_err());

    let mut swapped_key = attestation.clone();
    swapped_key.subject_identity_public_key = vec![8u8; 32];
    assert!(swapped_key.verify(&verifier.public_key_bytes()).is_err());

    let mut other_device = attestation.clone();
    other_device.subject_device_id = "device_other".to_string();
    assert!(other_device.verify(&verifier.public_key_bytes()).is_err());

    let mut other_verifier = attestation;
    other_verifier.verifier_user_id = "user-mallory".to_string();
    assert!(other_verifier.verify(&verifier.public_key_bytes()).is_err());
}

#[test]
fn malformed_statements_are_refused_before_signing() {
    let verifier = Ed25519KeyPair::generate();
    let now = Utc::now();
    assert!(PinAttestation::sign(&verifier, "u", "d", "u2", "d", &[7u8; 32], now).is_err());
    assert!(PinAttestation::sign(&verifier, "u", "d", "u2", "d2", &[7u8; 31], now).is_err());
    assert!(PinAttestation::sign(&verifier, "", "d", "u2", "d2", &[7u8; 32], now).is_err());
}
