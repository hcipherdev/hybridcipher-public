// Tests attestation_vouches_for() in src/session/mod.rs: a pin attestation verifies a join card only when another device of this account, verified directly on this computer, signed exactly that device's key.
use super::*;
use hybridcipher_client::invitation::InvitationKeyPair;
use hybridcipher_client::pinning::PinnedKey;
use hybridcipher_crypto::signatures::Ed25519KeyPair;
use uuid::Uuid;

const ME: &str = "user-chen";
const THIS_DEVICE: &str = "device_windows";
const MAC: &str = "device_mac";

fn member_card() -> ClientJoinCard {
    InvitationKeyPair::generate("device_97209c".to_string())
        .unwrap()
        .create_join_card(Uuid::new_v4())
        .unwrap()
}

fn mac_pin(identity: &Ed25519KeyPair, method: PinningMethod, verified: bool) -> PinnedKey {
    PinnedKey {
        user_id: ME.to_string(),
        device_id: MAC.to_string(),
        identity_public_key: identity.public_key_bytes(),
        fingerprint: String::new(),
        pinned_at: Utc::now(),
        verified,
        verified_at: verified.then(Utc::now),
        verification_method: method,
        notes: None,
    }
}

fn attestation(signer: &Ed25519KeyPair, verifier_user: &str, card: &ClientJoinCard) -> PinAttestation {
    PinAttestation::sign(
        signer,
        verifier_user,
        MAC,
        &card.user_id.to_string(),
        &card.device_id,
        &card.identity_public,
        Utc::now(),
    )
    .unwrap()
}

#[test]
fn a_verification_by_my_directly_verified_mac_counts() {
    let mac = Ed25519KeyPair::generate();
    let card = member_card();
    let pin = mac_pin(&mac, PinningMethod::Manual, true);
    assert!(attestation_vouches_for(&attestation(&mac, ME, &card), ME, THIS_DEVICE, &card, Some(&pin)));
}

#[test]
fn anything_this_computer_cannot_check_itself_does_not_count() {
    let mac = Ed25519KeyPair::generate();
    let card = member_card();
    let good = attestation(&mac, ME, &card);
    let pin = mac_pin(&mac, PinningMethod::Manual, true);

    // The verifier is not pinned here, or only auto-pinned, or itself trusted second-hand.
    assert!(!attestation_vouches_for(&good, ME, THIS_DEVICE, &card, None));
    for (method, verified) in [
        (PinningMethod::Unverified, false),
        (PinningMethod::Manual, false),
        (PinningMethod::OwnDevice, true),
    ] {
        let weak = mac_pin(&mac, method, verified);
        assert!(!attestation_vouches_for(&good, ME, THIS_DEVICE, &card, Some(&weak)));
    }
    // Signed by a key other than the one pinned for the Mac (a server substituting its own).
    let impostor = Ed25519KeyPair::generate();
    assert!(!attestation_vouches_for(&attestation(&impostor, ME, &card), ME, THIS_DEVICE, &card, Some(&pin)));
    // Another account's device, or this device itself.
    assert!(!attestation_vouches_for(&attestation(&mac, "user-other", &card), ME, THIS_DEVICE, &card, Some(&pin)));
    assert!(!attestation_vouches_for(&good, ME, MAC, &card, Some(&pin)));
    // A card for the same device with a different key (the device was replaced).
    let mut replaced = card.clone();
    replaced.identity_public = Ed25519KeyPair::generate().public_key_bytes().to_vec();
    assert!(!attestation_vouches_for(&good, ME, THIS_DEVICE, &replaced, Some(&pin)));
}
