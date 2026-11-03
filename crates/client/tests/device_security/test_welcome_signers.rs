// Tests SignerIntroduction and GroupSignerTrust (seeded, absorb, introduce) in crates/client/src/welcome_signers.rs: only keys introduced by an already trusted key, for the same group, become trusted Welcome signers (HC-02).
use super::*;

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_bytes(&[seed; 32]).unwrap()
}

#[test]
fn an_introduction_from_a_trusted_key_adds_the_introduced_key() {
    let group = Uuid::new_v4();
    let (admin, device) = (key(1), key(2));
    let mut trust = GroupSignerTrust::seeded(group, [&admin.public_key_bytes()[..]]);

    let introduction = SignerIntroduction::new(&admin, group, &device.public_key_bytes());
    assert!(trust.absorb(&[introduction]));
    assert!(trust.trusts(&device.public_key_bytes()));
}

#[test]
fn introductions_chain_in_any_order() {
    let group = Uuid::new_v4();
    let (admin, first, second) = (key(1), key(2), key(3));
    let mut trust = GroupSignerTrust::seeded(group, [&admin.public_key_bytes()[..]]);

    // `second` was introduced by `first`, which `admin` introduced; listed out of order.
    let introductions = [
        SignerIntroduction::new(&first, group, &second.public_key_bytes()),
        SignerIntroduction::new(&admin, group, &first.public_key_bytes()),
    ];
    trust.absorb(&introductions);
    assert!(trust.trusts(&second.public_key_bytes()));
    assert_eq!(trust.introductions().len(), 2);
}

#[test]
fn untrusted_forged_or_foreign_introductions_are_ignored() {
    let group = Uuid::new_v4();
    let (admin, server_key, device) = (key(1), key(66), key(2));
    let mut trust = GroupSignerTrust::seeded(group, [&admin.public_key_bytes()[..]]);

    // Signed by a key nobody trusts.
    let untrusted = SignerIntroduction::new(&server_key, group, &device.public_key_bytes());
    // Claims to be from the admin but the signature is not the admin's.
    let mut forged = SignerIntroduction::new(&server_key, group, &device.public_key_bytes());
    forged.introduced_by = hex::encode(admin.public_key_bytes());
    // A genuine admin introduction, but for another group.
    let foreign = SignerIntroduction::new(&admin, Uuid::new_v4(), &device.public_key_bytes());

    assert!(!trust.absorb(&[untrusted, forged, foreign]));
    assert!(!trust.trusts(&device.public_key_bytes()));
    assert!(trust.introductions().is_empty());
}

#[test]
fn a_tampered_introduction_fails_authentication() {
    let group = Uuid::new_v4();
    let (admin, device, other) = (key(1), key(2), key(3));
    let mut introduction = SignerIntroduction::new(&admin, group, &device.public_key_bytes());
    assert!(introduction.is_authentic());

    introduction.identity_key = hex::encode(other.public_key_bytes());
    assert!(!introduction.is_authentic());
}

#[test]
fn introduce_vouches_only_from_a_trusted_key_and_survives_a_round_trip() {
    let group = Uuid::new_v4();
    let (me, device, stranger) = (key(1), key(2), key(9));
    let mut trust = GroupSignerTrust::seeded(group, [&me.public_key_bytes()[..]]);

    assert!(!trust.introduce(&stranger, &device.public_key_bytes()));
    assert!(trust.introduce(&me, &device.public_key_bytes()));
    assert!(
        !trust.introduce(&me, &device.public_key_bytes()),
        "already trusted"
    );

    // A peer that trusts `me` learns `device` from the forwarded introductions.
    let mut peer = GroupSignerTrust::seeded(group, [&me.public_key_bytes()[..]]);
    peer.absorb(trust.introductions());
    assert!(peer.trusts(&device.public_key_bytes()));

    let stored: GroupSignerTrust =
        serde_json::from_str(&serde_json::to_string(&trust).unwrap()).unwrap();
    assert_eq!(stored, trust);
}
