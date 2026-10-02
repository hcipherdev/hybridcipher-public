// Tests local_write_access authorization at expiry, revocation, role changes, and organization boundaries.
use super::*;
use crate::entitlement::{Claims, TrustedKey, AUDIENCE, OFFLINE_VALIDITY_SECONDS};
use hybridcipher_crypto::signatures::SigningKey;

#[test]
fn team_writes_stop_at_expiry_but_personal_writes_continue() {
    let key = SigningKey::generate(&mut rand::rngs::OsRng).unwrap();
    let keys = vec![TrustedKey {
        kid: "test".into(),
        key: key.verifying_key(),
    }];
    let claims = Claims {
        iss: "https://test.invalid".into(),
        aud: AUDIENCE.into(),
        sub: "user".into(),
        organization_id: "team".into(),
        plan: "team".into(),
        team: true,
        max_members: 2,
        entitlement_version: 1,
        iat: 1000,
        exp: 1000 + OFFLINE_VALIDITY_SECONDS,
    };
    let token = entitlement::sign(&claims, "test", &key).unwrap();
    let mut access = LocalWriteAccess {
        issuer: claims.iss.clone(),
        user_id: claims.sub.clone(),
        entitlement: Some(token),
        revoked: false,
    };
    assert!(access
        .check_group(Some("team"), Some("member"), &keys, claims.exp - 1)
        .is_ok());
    assert!(access
        .check_group(Some("team"), Some("member"), &keys, claims.exp)
        .is_err());
    assert!(access
        .check_group(None, Some("admin"), &keys, claims.exp)
        .is_ok());
    assert!(access
        .check_group(Some("other"), Some("member"), &keys, 1000)
        .is_err());
    assert!(access
        .check_group(Some("team"), Some("viewer"), &keys, 1000)
        .is_err());
    assert!(access
        .check_group(Some("team"), Some("removed"), &keys, 1000)
        .is_err());
    access.revoked = true;
    assert!(access
        .check_group(Some("team"), Some("admin"), &keys, 1000)
        .is_err());
    assert!(access.check_group(None, Some("admin"), &keys, 1000).is_ok());
}
