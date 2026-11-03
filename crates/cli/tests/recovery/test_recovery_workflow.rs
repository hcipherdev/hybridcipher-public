// Tests CLI saved-code recovery membership scoping, history merging, and code parsing.
use super::*;
use hybridcipher_crypto::epoch_id::EpochIdMapper;

fn membership(id: Uuid, role: &str) -> crate::session::GroupInfo {
    crate::session::GroupInfo {
        id: id.to_string(),
        organization_id: None,
        name: "Test group".into(),
        description: None,
        role: role.into(),
        current_epoch: Some(EpochIdMapper::u64_to_uuid(2, id.as_bytes()).to_string()),
        member_count: 1,
        created_at: Utc::now().to_rfc3339(),
    }
}

#[test]
fn test_recovery_scope_includes_all_current_memberships() {
    let personal = Uuid::new_v4();
    let team = Uuid::new_v4();
    let groups = vec![membership(personal, "admin"), membership(team, "member")];
    let scopes = recovery_scopes(&groups, Some(personal)).unwrap();
    assert_eq!(scopes.len(), 2);
    assert_eq!(scopes[1].user_role, GroupRole::Member);
    assert!(recovery_scopes(&groups, Some(team)).is_ok());
    assert!(recovery_scopes(&[], None).is_err());
}

#[test]
fn test_recovery_merges_full_history_only_with_matching_encryption_envelope() {
    let group = Uuid::new_v4();
    let mut remote = BackupArtifact::new("test-password", &[9; 32]).unwrap();
    let entry = |number, key| BackupEntryPlain {
        group_id: group,
        epoch_number: number,
        epoch_uuid: EpochIdMapper::u64_to_uuid(number, group.as_bytes()),
        created_at: Utc::now(),
        is_active: true,
        encryption_key_b64: general_purpose::STANDARD.encode([key; 32]),
    };
    remote
        .append_entries(&[entry(1, 3)], "test-password", &[9; 32])
        .unwrap();
    let mut local = remote.clone();
    local
        .append_entries(&[entry(2, 4)], "test-password", &[9; 32])
        .unwrap();
    let merged = merge_artifacts(remote.clone(), local.clone());
    assert_eq!(merged.entries.len(), 2);
    assert_eq!(
        merged
            .decrypt_entries("test-password", &[9; 32])
            .unwrap()
            .len(),
        2
    );
    local.k1_salt_b64 = general_purpose::STANDARD.encode([7; 16]);
    let different = merge_artifacts(remote, local);
    assert_eq!(different.entries.len(), 1);
    assert_eq!(
        different
            .decrypt_entries("test-password", &[9; 32])
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn test_recovery_code_requires_full_raw_secret() {
    let code = format_recovery_code(&[9; 32]);
    assert_eq!(
        parse_recovery_code(&format!("  {code}\n"))
            .unwrap()
            .as_slice(),
        &[9; 32]
    );
    assert!(parse_recovery_code("not-a-code").is_err());
    assert!(parse_recovery_code(&"0".repeat(62)).is_err());
}
