// Verify native Personal metadata, cache namespaces, and async session binding reject another account, server, or epoch identity.
use super::*;

fn group(id: Uuid) -> Value {
    json!({"id":id,"name":"Personal","organization_id":null,"role":"owner","current_epoch_id":Uuid::new_v4()})
}

#[test]
fn personal_metadata_requires_the_owned_default_and_valid_current_epoch() {
    let id = Uuid::new_v4();
    let mut value = json!({"personal_default_group_id":id,"state":"available","group":group(id),"candidates":[]});
    assert!(validate_snapshot(&value).is_ok());
    value["group"]["id"] = json!(Uuid::new_v4());
    assert!(validate_snapshot(&value).is_err());
    value["group"] = group(id);
    value["group"]["current_epoch_id"] = json!("invalid");
    assert!(validate_snapshot(&value).is_err());
    value["group"] = group(id);
    value["group"]["organization_id"] = json!(Uuid::new_v4());
    assert!(validate_snapshot(&value).is_err());
}

#[test]
fn missing_default_is_not_replaced_by_a_repair_candidate() {
    let id = Uuid::new_v4();
    let value = json!({"personal_default_group_id":null,"state":"unresolved","group":null,"candidates":[group(id)]});
    assert!(validate_snapshot(&value).is_ok());
    assert!(available_personal_group(&value, None).is_err());
    assert!(value["group"].is_null());
    let mut inherited = value;
    inherited["candidates"][0]["role"] = json!("member");
    assert!(validate_snapshot(&inherited).is_err());
}

#[test]
fn unavailable_metadata_requires_retry_without_inventing_repair_candidates() {
    let missing = cached_snapshot(None).unwrap_err();
    assert!(missing.contains("metadata is unavailable"));
    assert!(missing.contains("Check status"));
    assert!(cached_snapshot(Some("invalid json"))
        .unwrap_err()
        .contains("could not be read"));
    let invalid =
        json!({"state":"available","personal_default_group_id":null,"group":null,"candidates":[]});
    assert!(cached_snapshot(Some(&invalid.to_string()))
        .unwrap_err()
        .contains("metadata is invalid"));
}

#[test]
fn cached_identity_preserves_the_authoritative_default_and_real_repair_state_offline() {
    let id = Uuid::new_v4();
    let available = json!({"personal_default_group_id":id,"state":"available","group":group(id),"candidates":[]});
    assert_eq!(
        cached_snapshot(Some(&available.to_string())).unwrap(),
        available
    );
    let unresolved = json!({"personal_default_group_id":null,"state":"unresolved","group":null,"candidates":[group(id)]});
    assert_eq!(
        cached_snapshot(Some(&unresolved.to_string())).unwrap(),
        unresolved
    );
}

#[tokio::test]
async fn valid_online_metadata_remains_usable_when_its_offline_cache_cannot_be_written() {
    let id = Uuid::new_v4();
    let available = json!({"personal_default_group_id":id,"state":"available","group":group(id),"candidates":[]});
    let resolved = online_snapshot(available.clone(), |encoded| async move {
        assert_eq!(
            serde_json::from_str::<Value>(&encoded).unwrap()["personal_default_group_id"],
            json!(id)
        );
        Err::<(), _>("cache is unavailable")
    })
    .await
    .unwrap();
    assert_eq!(resolved, available);
    assert!(online_snapshot(json!({"state":"available"}), |_| async {
        panic!("Invalid metadata must never replace a saved cache");
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    })
    .await
    .is_err());
}

#[test]
fn folder_namespace_rejects_an_old_shared_selection_even_when_the_default_is_available() {
    let id = Uuid::new_v4();
    let value = json!({"personal_default_group_id":id,"state":"available","group":group(id),"candidates":[]});
    assert_eq!(
        available_personal_group(&value, None).unwrap()["id"],
        json!(id)
    );
    assert!(available_personal_group(&value, Some(Uuid::new_v4())).is_err());
    assert!(available_personal_group(&value, Some(id)).is_ok());
}

#[test]
fn enrollment_from_a_previous_picker_cannot_use_the_new_workspace() {
    let id = Uuid::new_v4();
    assert!(validate_expected_group(None, id).is_ok());
    assert!(validate_expected_group(Some(&id.to_string()), id).is_ok());
    assert!(validate_expected_group(Some(&Uuid::new_v4().to_string()), id).is_err());
    assert!(validate_expected_group(Some("invalid"), id).is_err());
}

#[test]
fn cache_namespace_is_bound_to_server_and_account_identity() {
    assert_eq!(
        cache_key("account-a", "https://a.test"),
        cache_key("account-a", "https://a.test/api/v1/")
    );
    assert_ne!(
        cache_key("account-a", "https://a.test"),
        cache_key("account-b", "https://a.test")
    );
    assert_ne!(
        cache_key("account-a", "https://a.test"),
        cache_key("account-a", "https://b.test")
    );
    assert_ne!(
        cache_key("account-a", "https://a.test"),
        "desktop_personal_workspace"
    );
}

#[test]
fn late_personal_response_rejects_relogin_device_and_server_changes() {
    let mut session = crate::state::UserSession {
        email: "owner@example.test".into(),
        device_id: "device-a".into(),
        user_id: "account-a".into(),
        server_url: Some("https://a.test".into()),
        token: "token".into(),
        refresh_token: String::new(),
        team_entitlement: None,
        team_revoked: false,
        pending_team_requests: vec![],
        expires_at: i64::MAX,
        opaque_export_key: None,
        persistent: false,
    };
    let scope = WorkspaceSessionScope {
        account_id: session.user_id.clone(),
        email: session.email.clone(),
        device_id: session.device_id.clone(),
        server: canonical_personal_server("https://a.test"),
        generation: 5,
    };
    assert!(scope.matches(&session, "https://a.test/api/v1/", 5));
    session.token = "refreshed-token".into();
    assert!(scope.matches(&session, "https://a.test", 5));
    assert!(!scope.matches(&session, "https://a.test", 6));
    assert!(!scope.matches(&session, "https://b.test", 5));
    session.device_id = "device-b".into();
    assert!(!scope.matches(&session, "https://a.test", 5));
    session.device_id = "device-a".into();
    session.user_id = "account-b".into();
    assert!(!scope.matches(&session, "https://a.test", 5));
}
