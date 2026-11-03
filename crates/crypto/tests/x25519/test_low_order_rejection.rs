// Tests that X25519PrivateKey::diffie_hellman, ephemeral_diffie_hellman and hybridkem::decap in crates/crypto/src reject low-order X25519 points (HC-11).

use super::*;
use crate::x25519::ephemeral_diffie_hellman;
use rand_core::OsRng;

/// u = 0 (order 2) and u = 1 (order 4): both force the all-zero shared secret.
const LOW_ORDER_POINTS: [[u8; 32]; 2] = [[0u8; 32], {
    let mut point = [0u8; 32];
    point[0] = 1;
    point
}];

#[test]
fn static_dh_rejects_low_order_points() {
    let keypair = X25519KeyPair::generate(&mut OsRng);
    for point in LOW_ORDER_POINTS {
        let public = X25519PublicKey::from_bytes(&point).unwrap();
        assert!(matches!(
            keypair.private.diffie_hellman(&public),
            Err(CryptoError::InvalidKey(_))
        ));
    }
}

#[test]
fn ephemeral_dh_rejects_low_order_points() {
    for point in LOW_ORDER_POINTS {
        let public = X25519PublicKey::from_bytes(&point).unwrap();
        assert!(matches!(
            ephemeral_diffie_hellman(&mut OsRng, &public),
            Err(CryptoError::InvalidKey(_))
        ));
    }
}

#[test]
fn decap_rejects_ciphertext_with_low_order_ephemeral_key() {
    let recipient = HybridKeyPair::generate(&mut OsRng).unwrap();
    let (ciphertext, _) = encap(&recipient.public, Context::Welcome, &mut OsRng).unwrap();
    assert!(decap(&recipient.secret, &ciphertext, Context::Welcome).is_ok());

    for point in LOW_ORDER_POINTS {
        let tampered = HybridCiphertext {
            x25519_public: X25519PublicKey::from_bytes(&point).unwrap(),
            mlkem_ciphertext: ciphertext.mlkem_ciphertext.clone(),
        };
        assert!(matches!(
            decap(&recipient.secret, &tampered, Context::Welcome),
            Err(CryptoError::InvalidKey(_))
        ));
    }
}
