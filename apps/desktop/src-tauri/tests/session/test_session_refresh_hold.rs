// Tests SessionRefreshHold in src/state.rs, which stops the desktop app from re-sending a rejected or throttled refresh token.
use super::*;
use std::time::{Duration, Instant};

fn hold(token: &str, until: Option<Instant>) -> SessionRefreshHold {
    SessionRefreshHold {
        token_sha256: SessionRefreshHold::token_sha256(token),
        until,
        message: "Session refresh was rejected by the server. Please login again.".into(),
    }
}

#[test]
fn rejected_token_stays_held_until_a_new_login() {
    let rejected = hold("old-refresh-token", None);
    assert!(rejected.rejected());
    assert!(rejected.blocks("old-refresh-token"));
    // A new login brings a new refresh token, which the hold must not block.
    assert!(!rejected.blocks("new-refresh-token"));
}

#[test]
fn throttled_token_is_held_only_until_the_retry_time() {
    let waiting = hold("token", Some(Instant::now() + Duration::from_secs(60)));
    assert!(!waiting.rejected());
    assert!(waiting.blocks("token"));

    let expired = hold("token", Some(Instant::now() - Duration::from_secs(1)));
    assert!(!expired.blocks("token"));
}

#[test]
fn hold_does_not_keep_the_raw_token() {
    let held = hold("secret-refresh-token", None);
    assert!(!held.token_sha256.contains("secret-refresh-token"));
    assert_eq!(held.token_sha256.len(), 64);
}
