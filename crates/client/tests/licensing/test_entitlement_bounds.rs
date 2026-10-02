// Tests entitlement.rs rejection of overflowing timestamps and unsupported JOSE headers.
#[test]
fn rejects_overflowing_signed_lifetime_without_panicking() {
    let (signer, trusted, mut claims) = fixture();
    claims.iat = i64::MIN; claims.exp = i64::MAX;
    let token = sign(&claims, &trusted.kid, &signer).unwrap();
    assert!(verify(&token, &[trusted], &claims.iss, &claims.sub, 1_800_000_000).is_err());
}

#[test]
fn rejects_valid_signatures_with_wrong_token_type_or_critical_headers() {
    let (signer, trusted, claims) = fixture();
    for header in [
        serde_json::json!({"alg":"EdDSA","typ":"JWT","kid":trusted.kid}),
        serde_json::json!({"alg":"EdDSA","typ":TOKEN_TYPE,"kid":trusted.kid,"crit":["b64"],"b64":false}),
        serde_json::json!({"alg":"HS256","typ":TOKEN_TYPE,"kid":trusted.kid}),
    ] {
        let input = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()), URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()));
        let signature = signer.sign(input.as_bytes()).unwrap();
        let token = format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()));
        assert!(verify(&token, &[trusted.clone()], &claims.iss, &claims.sub, claims.iat).is_err());
    }
}
