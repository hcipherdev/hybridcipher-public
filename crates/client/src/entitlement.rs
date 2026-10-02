//! Signed, account-scoped Team licenses shared by the server, desktop, and CLI.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hybridcipher_crypto::signatures::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const AUDIENCE: &str = "hybridcipher-desktop-cli";
pub const TOKEN_TYPE: &str = "hc-entitlement+jwt";
pub const OFFLINE_VALIDITY_SECONDS: i64 = 30 * 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub organization_id: String,
    pub plan: String,
    pub team: bool,
    pub max_members: u32,
    pub entitlement_version: i64,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

#[derive(Debug, Clone)]
pub struct TrustedKey {
    pub kid: String,
    pub key: VerifyingKey,
}

pub fn sign(claims: &Claims, kid: &str, key: &SigningKey) -> Result<String, String> {
    if kid.is_empty() || claims.aud != AUDIENCE || claims.plan != "team" || !claims.team {
        return Err("Invalid Team entitlement claims".into());
    }
    let header = Header {
        alg: "EdDSA".into(),
        typ: TOKEN_TYPE.into(),
        kid: kid.into(),
    };
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|e| e.to_string())?);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|e| e.to_string())?);
    let signing_input = format!("{header}.{payload}");
    let signature = key
        .sign(signing_input.as_bytes())
        .map_err(|e| e.to_string())?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

pub fn verify(
    token: &str,
    keys: &[TrustedKey],
    expected_issuer: &str,
    expected_user: &str,
    now: i64,
) -> Result<Claims, String> {
    verify_with_expiry(token, keys, expected_issuer, expected_user, now, false)
}

/// A previously issued entitlement can identify existing local Team data after
/// expiry.  Callers must use this only for read, decrypt, and export paths.
pub fn verify_for_existing_data(
    token: &str,
    keys: &[TrustedKey],
    expected_issuer: &str,
    expected_user: &str,
    now: i64,
) -> Result<Claims, String> {
    verify_with_expiry(token, keys, expected_issuer, expected_user, now, true)
}

fn verify_with_expiry(
    token: &str,
    keys: &[TrustedKey],
    expected_issuer: &str,
    expected_user: &str,
    now: i64,
    allow_expired: bool,
) -> Result<Claims, String> {
    let mut parts = token.split('.');
    let (header, payload, signature) =
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(h), Some(p), Some(s), None) => (h, p, s),
            _ => return Err("Malformed entitlement".into()),
        };
    let decoded_header: Header = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(header)
            .map_err(|_| "Invalid entitlement header")?,
    )
    .map_err(|_| "Invalid entitlement header")?;
    if decoded_header.alg != "EdDSA" || decoded_header.typ != TOKEN_TYPE {
        return Err("Wrong entitlement signature type".into());
    }
    let key = keys
        .iter()
        .find(|key| key.kid == decoded_header.kid)
        .ok_or("Unknown entitlement signing key")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| "Invalid entitlement signature")?;
    let signature =
        Signature::from_bytes(&signature_bytes).map_err(|_| "Invalid entitlement signature")?;
    key.key
        .verify(format!("{header}.{payload}").as_bytes(), &signature)
        .map_err(|_| "Invalid entitlement signature")?;
    let claims: Claims = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| "Invalid entitlement payload")?,
    )
    .map_err(|_| "Invalid entitlement payload")?;
    if claims.iss.trim_end_matches('/') != expected_issuer.trim_end_matches('/')
        || claims.aud != AUDIENCE
        || claims.sub != expected_user
        || claims.plan != "team"
        || !claims.team
        || claims.organization_id.is_empty()
        || claims.max_members == 0
        || claims.entitlement_version < 1
        || claims.iat > now.saturating_add(300)
        || (!allow_expired && claims.exp <= now)
        || claims.exp <= claims.iat
        || claims
            .exp
            .checked_sub(claims.iat)
            .is_none_or(|duration| duration > OFFLINE_VALIDITY_SECONDS)
    {
        return Err("Entitlement is expired or is for another account or server".into());
    }
    Ok(claims)
}

/// Release builds inject the trusted public keys as `kid:base64url` pairs.
pub fn trusted_keys_from_build() -> Result<Vec<TrustedKey>, String> {
    let Some(value) = option_env!("HYBRIDCIPHER_ENTITLEMENT_PUBLIC_KEYS") else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (kid, encoded) = entry
                .split_once(':')
                .ok_or("Malformed entitlement public key")?;
            let bytes = URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| "Malformed entitlement public key")?;
            let key =
                VerifyingKey::from_bytes(&bytes).map_err(|_| "Malformed entitlement public key")?;
            Ok(TrustedKey {
                kid: kid.into(),
                key,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "../test/entitlement/test_entitlement.rs"]
mod tests;
