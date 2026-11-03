// Tests expired_invitation_keypair_blocks_auto_verify() in src/session/mod.rs: an invitation key pair older than 30 days blocks auto-verification only when the device key is not already pinned and verified.
use super::expired_invitation_keypair_blocks_auto_verify;
use chrono::Utc;
use hybridcipher_client::pinning::{PinnedKey, PinningMethod};

const KEY: [u8; 32] = [7; 32];

fn pin(identity_public_key: [u8; 32], verified: bool) -> PinnedKey {
    PinnedKey {
        user_id: "user".to_string(),
        device_id: "device".to_string(),
        identity_public_key,
        fingerprint: "fingerprint".to_string(),
        pinned_at: Utc::now(),
        verified,
        verified_at: verified.then(Utc::now),
        verification_method: PinningMethod::Manual,
        notes: None,
    }
}

#[test]
fn an_old_keypair_does_not_block_a_device_already_verified_with_the_same_key() {
    // The xps-win admin case: keys from more than 30 days ago, pin verified long since.
    assert!(!expired_invitation_keypair_blocks_auto_verify(false, Some(&pin(KEY, true)), &KEY));
}

#[test]
fn an_old_keypair_still_blocks_new_or_unverified_pins() {
    assert!(expired_invitation_keypair_blocks_auto_verify(false, None, &KEY));
    assert!(expired_invitation_keypair_blocks_auto_verify(false, Some(&pin(KEY, false)), &KEY));
}

#[test]
fn an_old_keypair_blocks_when_the_verified_pin_is_for_a_different_key() {
    assert!(expired_invitation_keypair_blocks_auto_verify(false, Some(&pin([9; 32], true)), &KEY));
}

#[test]
fn a_current_keypair_never_blocks() {
    assert!(!expired_invitation_keypair_blocks_auto_verify(true, None, &KEY));
    assert!(!expired_invitation_keypair_blocks_auto_verify(true, Some(&pin(KEY, false)), &KEY));
}
