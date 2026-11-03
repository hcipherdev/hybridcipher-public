// Tests own_device_target_groups(), own_device_access_summary() and pin_state_allows_auto_repair() in src/commands/welcome.rs: which groups an own device gets a Welcome for, the summary naming groups left for an admin, and which pins let repair-own-devices send keys without a new fingerprint check.
use super::*;

fn own_device(group_ids: Vec<Uuid>) -> PendingDeviceSummary {
    PendingDeviceSummary {
        user_id: Uuid::new_v4(),
        device_id: "device_phone".into(),
        device_name: None,
        pending_since: Utc::now(),
        invitation_public_key_hex: String::new(),
        identity_public_key_hex: String::new(),
        group_ids,
        missing_current_key: false,
    }
}

#[test]
fn an_own_device_gets_every_group_it_needs_unless_one_is_requested() {
    let (personal, team) = (Uuid::new_v4(), Uuid::new_v4());
    let device = own_device(vec![personal, team]);

    assert_eq!(own_device_target_groups(&device, None).unwrap(), vec![personal, team]);
    assert_eq!(own_device_target_groups(&device, Some(team)).unwrap(), vec![team]);
    assert!(own_device_target_groups(&device, Some(Uuid::new_v4())).is_err());
    assert!(own_device_target_groups(&own_device(Vec::new()), None).is_err());
}

#[test]
fn the_summary_names_the_groups_left_for_an_admin() {
    assert_eq!(own_device_access_summary(2, &[]), "Gave access in 2 of 2 groups.");
    assert_eq!(
        own_device_access_summary(1, &["Design".into()]),
        "Gave access in 1 of 2 groups; Design needs a group admin."
    );
    assert_eq!(
        own_device_access_summary(1, &["Design".into(), "Finance".into()]),
        "Gave access in 1 of 3 groups; Design, Finance need a group admin."
    );
}

#[test]
fn only_a_verification_this_account_made_lets_keys_go_out_unasked() {
    assert!(pin_state_allows_auto_repair(&JoinCardPinState::AlreadyPinned));
    assert!(pin_state_allows_auto_repair(&JoinCardPinState::RestoredFromOwnDevice {
        verifier_device_id: "device_laptop".into(),
    }));
    // A cached card may never have been compared, and the others were never verified.
    assert!(!pin_state_allows_auto_repair(&JoinCardPinState::RestoredFromCache));
    assert!(!pin_state_allows_auto_repair(&JoinCardPinState::Unverified { auto_pinned: true }));
    assert!(!pin_state_allows_auto_repair(&JoinCardPinState::Missing));
    assert!(!pin_state_allows_auto_repair(&JoinCardPinState::Expired(Utc::now())));
}
