// Tests Client::open_trusted_welcome(), authorize_welcome_signer() and encrypt_welcome_epoch() in crates/client/src/state/client/welcome_trust.rs: a Welcome is accepted only from a signer the device trusts for the group or that a trusted key introduced, and approvals forward the introductions (HC-02).
use super::*;
use crate::network::MockNetwork;
use crate::storage::MockStorage;
use crate::welcome_manager::ServerWelcomeSignable;

fn client() -> Client<MockStorage, MockNetwork> {
    Client::new(
        Ed25519KeyPair::generate(),
        Arc::new(MockStorage::new()),
        Arc::new(MockNetwork::new()),
    )
}

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_bytes(&[seed; 32]).unwrap()
}

/// A Welcome for `client`'s device, signed by `signer`, carrying `introductions`.
async fn welcome_from(
    client: &Client<MockStorage, MockNetwork>,
    signer: &Ed25519KeyPair,
    group: Uuid,
    epoch: u64,
    introductions: Vec<SignerIntroduction>,
) -> WelcomeMessagesResponse {
    let invitation = client.ensure_invitation_keypair().await.unwrap();
    let manager = WelcomeManager::new(client.storage.clone(), invitation.clone());
    let secrets = EpochSecrets {
        epoch_key: [epoch as u8; 32],
        epoch_id: epoch,
        group_members: Vec::new(),
        active_at: Utc::now(),
        signer_introductions: introductions,
    };
    let encrypted = manager
        .encrypt_epoch_secrets_for_device(&secrets, &invitation.invitation_public_key().unwrap())
        .unwrap();
    let epoch_uuid = EpochIdMapper::u64_to_uuid(epoch, group.as_bytes());
    let created_at = Utc::now();
    let signable = ServerWelcomeSignable::new(
        group,
        epoch_uuid,
        &invitation.device_id,
        &encrypted,
        created_at,
        None,
    );
    let signature = signer.sign(&signable.to_bytes().unwrap()).to_vec();
    WelcomeMessagesResponse {
        group_id: group,
        epoch_uuid,
        epoch_id: epoch,
        legacy_mapping: false,
        messages: vec![WelcomeMessagePayload {
            message_id: Uuid::new_v4(),
            epoch_id: epoch_uuid,
            group_id: group,
            recipient_user_id: Uuid::new_v4(),
            recipient_device_id: invitation.device_id,
            encrypted_epoch_key: encrypted,
            signature,
            signing_public_key: signer.public_key_bytes().to_vec(),
            created_at,
            expires_at: None,
        }],
        expires_at: created_at + chrono::Duration::minutes(30),
    }
}

#[tokio::test]
async fn a_welcome_from_an_untrusted_signer_is_rejected_and_not_installed() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let (group, admin, server_key) = (Uuid::new_v4(), key(1), key(66));
    // First contact (no server device list here) trusts the admin.
    client
        .authorize_welcome_signer(group, &admin.public_key_bytes(), &[])
        .await
        .unwrap();

    // The server pushes a group key it chose, validly signed by a key of its own.
    let response = welcome_from(&client, &server_key, group, 2, Vec::new()).await;
    let error = client
        .process_welcome_messages_inner(response, group)
        .await
        .unwrap_err();

    assert_eq!(error.error_code(), Some(ErrorCode::SecurityTampering));
    assert!(
        error.context().unwrap().message.contains("does not trust"),
        "{error:?}"
    );
    let state = client.state.read().await;
    assert!(Client::<MockStorage, MockNetwork>::get_epoch_state(&state, group, 2).is_none());
}

#[tokio::test]
async fn a_self_introduction_does_not_make_an_untrusted_signer_trusted() {
    let client = client();
    client.ensure_state_loaded().await.unwrap();
    let (group, admin, server_key) = (Uuid::new_v4(), key(1), key(66));
    client
        .authorize_welcome_signer(group, &admin.public_key_bytes(), &[])
        .await
        .unwrap();

    let self_introduced =
        SignerIntroduction::new(&server_key, group, &server_key.public_key_bytes());
    let response = welcome_from(&client, &server_key, group, 2, vec![self_introduced]).await;
    let error = client
        .process_welcome_messages_inner(response, group)
        .await
        .unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::SecurityTampering));
    assert!(
        error.context().unwrap().message.contains("does not trust"),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_signer_introduced_by_a_trusted_device_is_accepted_and_remembered() {
    let client = client();
    let (group, admin, device) = (Uuid::new_v4(), key(1), key(2));
    client
        .authorize_welcome_signer(group, &admin.public_key_bytes(), &[])
        .await
        .unwrap();

    let introduction = SignerIntroduction::new(&admin, group, &device.public_key_bytes());
    client
        .authorize_welcome_signer(group, &device.public_key_bytes(), &[introduction])
        .await
        .unwrap();
    // Later Welcomes from that device need no introduction.
    client
        .authorize_welcome_signer(group, &device.public_key_bytes(), &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn first_contact_trusts_only_the_first_signer_and_this_device() {
    let client = client();
    let (group, first, second) = (Uuid::new_v4(), key(1), key(2));
    client
        .authorize_welcome_signer(group, &first.public_key_bytes(), &[])
        .await
        .unwrap();

    assert!(client
        .authorize_welcome_signer(group, &second.public_key_bytes(), &[])
        .await
        .is_err());
    client
        .authorize_welcome_signer(group, &client.device_identity.public_key_bytes(), &[])
        .await
        .unwrap();
    // Trust is per group.
    client
        .authorize_welcome_signer(Uuid::new_v4(), &second.public_key_bytes(), &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn an_approval_introduces_the_recipient_and_forwards_known_introductions() {
    let approver = client();
    let recipient = client();
    let group = Uuid::new_v4();
    let earlier = key(5);
    // The approver already learned `earlier` from an introduction by itself.
    approver
        .authorize_welcome_signer(
            group,
            &earlier.public_key_bytes(),
            &[SignerIntroduction::new(
                &approver.device_identity,
                group,
                &earlier.public_key_bytes(),
            )],
        )
        .await
        .unwrap();

    let recipient_invitation = recipient.ensure_invitation_keypair().await.unwrap();
    let approver_manager = WelcomeManager::new(
        approver.storage.clone(),
        approver.ensure_invitation_keypair().await.unwrap(),
    );
    let epoch = EpochState {
        group_id: Some(group),
        epoch_id: 4,
        encryption_key: [4; 32],
        key_source: EpochKeySource::Welcome,
        members: Vec::new(),
        created_at: Utc::now(),
        is_active: true,
        file_count: 0,
        marked_for_removal: false,
        removal_eligible_at: None,
    };
    let encrypted = approver
        .encrypt_welcome_epoch(
            &approver_manager,
            group,
            &epoch,
            &recipient.device_identity.public_key_bytes(),
            &recipient_invitation.invitation_public_key().unwrap(),
        )
        .await
        .unwrap();

    let opened = WelcomeManager::new(recipient.storage.clone(), recipient_invitation)
        .decrypt_server_welcome_epoch_key(&encrypted, group)
        .unwrap();
    let secrets: EpochSecrets = serde_json::from_slice(&opened).unwrap();
    assert_eq!(secrets.epoch_key, [4; 32]);
    assert_eq!(secrets.epoch_id, 4);

    // A member who trusts only the approver learns both introduced keys.
    let mut peer = crate::welcome_signers::GroupSignerTrust::seeded(
        group,
        [&approver.device_identity.public_key_bytes()[..]],
    );
    peer.absorb(&secrets.signer_introductions);
    assert!(peer.trusts(&recipient.device_identity.public_key_bytes()));
    assert!(peer.trusts(&earlier.public_key_bytes()));
}
