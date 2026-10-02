// Purpose: Keep Personal, Team, and legacy unknown group classifications distinct for offline write gating.
use super::*;

#[test]
fn group_cache_distinguishes_personal_team_and_legacy_unknown() {
    let mut cache: GroupMetadataCache =
        serde_json::from_str(r#"{"by_id":{"old":{"name":"Legacy","role":"owner"}}}"#).unwrap();
    assert_eq!(cache.organization_for_id("old"), None);

    cache.insert("personal", "Personal", Some("owner"), None);
    cache.insert("team", "Research", Some("owner"), Some("org-123"));
    assert_eq!(cache.organization_for_id("personal"), Some(None));
    assert_eq!(cache.organization_for_id("team"), Some(Some("org-123")));

    let restored: GroupMetadataCache =
        serde_json::from_str(&serde_json::to_string(&cache).unwrap()).unwrap();
    assert_eq!(restored.organization_for_id("personal"), Some(None));
    assert_eq!(restored.organization_for_id("team"), Some(Some("org-123")));
}
