// Tests signed Team entitlement verification, account binding, and expiration in entitlement.rs.
use super::*;
use rand::rngs::OsRng;
include!("../../tests/licensing/test_entitlement_bounds.rs");

fn fixture() -> (SigningKey, TrustedKey, Claims) {
    let signer = SigningKey::generate(&mut OsRng).unwrap();
    let trusted = TrustedKey {
        kid: "team-key-1".into(),
        key: signer.verifying_key(),
    };
    let claims = Claims {
        iss: "https://api.example.test".into(),
        aud: AUDIENCE.into(),
        sub: "user-123".into(),
        organization_id: "org-123".into(),
        plan: "team".into(),
        team: true,
        max_members: 20,
        entitlement_version: 1,
        iat: 1_800_000_000,
        exp: 1_800_000_000 + OFFLINE_VALIDITY_SECONDS,
    };
    (signer, trusted, claims)
}

#[test]
fn accepts_only_current_entitlement_for_same_user_and_server() {
    let (signer, trusted, claims) = fixture();
    let token = sign(&claims, &trusted.kid, &signer).unwrap();
    assert_eq!(
        verify(
            &token,
            &[trusted.clone()],
            &claims.iss,
            &claims.sub,
            claims.iat
        )
        .unwrap(),
        claims
    );
    assert!(verify(&token, &[trusted.clone()], &claims.iss, "other", claims.iat).is_err());
    assert!(verify(
        &token,
        &[trusted.clone()],
        "https://other.example",
        &claims.sub,
        claims.iat
    )
    .is_err());
    assert!(verify(&token, &[trusted], &claims.iss, &claims.sub, claims.exp).is_err());
}

#[test]
fn rejects_tampering_and_untrusted_keys() {
    let (signer, trusted, claims) = fixture();
    let token = sign(&claims, &trusted.kid, &signer).unwrap();
    let mut parts: Vec<String> = token.split('.').map(str::to_string).collect();
    parts[1].push('A');
    assert!(verify(
        &parts.join("."),
        &[trusted],
        &claims.iss,
        &claims.sub,
        claims.iat
    )
    .is_err());
    assert!(verify(&token, &[], &claims.iss, &claims.sub, claims.iat).is_err());
}

#[test]
fn expired_entitlement_retains_existing_data_access_only() {
    let (signer, trusted, claims) = fixture();
    let token = sign(&claims, &trusted.kid, &signer).unwrap();
    assert!(verify(
        &token,
        &[trusted.clone()],
        &claims.iss,
        &claims.sub,
        claims.exp
    )
    .is_err());
    assert_eq!(
        verify_for_existing_data(&token, &[trusted], &claims.iss, &claims.sub, claims.exp).unwrap(),
        claims,
    );
}

#[test]
fn rotated_keys_verify_old_entitlements_until_retired() {
    let (old_signer, old_key, claims) = fixture();
    let new_signer = SigningKey::generate(&mut OsRng).unwrap();
    let new_key = TrustedKey {
        kid: "team-key-2".into(),
        key: new_signer.verifying_key(),
    };
    let token = sign(&claims, &old_key.kid, &old_signer).unwrap();
    assert!(verify(
        &token,
        &[new_key.clone()],
        &claims.iss,
        &claims.sub,
        claims.iat
    )
    .is_err());
    assert!(verify(
        &token,
        &[old_key, new_key],
        &claims.iss,
        &claims.sub,
        claims.iat
    )
    .is_ok());
}

#[test]
fn rejects_wrong_signed_purpose_and_future_issue_time() {
    let (signer, trusted, mut claims) = fixture();
    claims.aud = "another-client".into();
    assert!(sign(&claims, &trusted.kid, &signer).is_err());
    claims.aud = AUDIENCE.into();
    claims.team = false;
    assert!(sign(&claims, &trusted.kid, &signer).is_err());
    claims.team = true;
    claims.iat += 600;
    claims.exp += 600;
    let token = sign(&claims, &trusted.kid, &signer).unwrap();
    assert!(verify(
        &token,
        &[trusted],
        &claims.iss,
        &claims.sub,
        claims.iat - 600
    )
    .is_err());
}
