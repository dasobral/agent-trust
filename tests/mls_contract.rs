use agent_trust::mls::MlsLab;

fn assert_rejected<T>(result: Result<T, String>) {
    assert!(result.is_err(), "operation should be rejected");
}

fn assert_member_set(lab: &MlsLab, expected: &[&str]) {
    let mut actual = lab.members();
    actual.sort();
    let mut expected = expected
        .iter()
        .map(|member| (*member).to_owned())
        .collect::<Vec<_>>();
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn new_lab_starts_with_alice_as_its_only_member() {
    // Catches a constructor that creates no usable founding member or adds extras.
    let lab = MlsLab::new().expect("new lab should create alice");

    assert_member_set(&lab, &["alice"]);
}

#[test]
fn other_current_members_decrypt_and_authenticated_data_round_trips() {
    // Catches encryption that omits another member, drops AAD, or returns a different payload.
    let mut lab = MlsLab::new().expect("new lab should create alice");
    lab.add_member("bob").expect("bob should join");
    lab.add_member("carol").expect("carol should join");

    let payload = b"group secret: inventory 7";
    let aad = b"content-type: application/test";
    let wire = lab
        .protect("alice", payload, aad)
        .expect("a current sender should protect a message");

    assert!(!wire.is_empty(), "protected wire should contain a message");
    // MLS sender ratchets do not retain decryption keys for their own private
    // messages. The sender already has the plaintext; exercise peer delivery.
    for recipient in ["bob", "carol"] {
        let (opened_payload, opened_aad) = lab
            .decrypt(recipient, &wire)
            .expect("each other current member should decrypt");
        assert_eq!(opened_payload, payload, "payload for {recipient}");
        assert_eq!(opened_aad, aad, "AAD for {recipient}");
    }
}

#[test]
fn modified_protected_wire_is_rejected() {
    // Catches unauthenticated ciphertext acceptance.
    let mut lab = MlsLab::new().expect("new lab should create alice");
    lab.add_member("bob").expect("bob should join");
    let mut wire = lab
        .protect("alice", b"tamper check", b"aad")
        .expect("alice should protect a message");
    assert!(
        !wire.is_empty(),
        "protected wire should contain a mutable byte"
    );
    let last = wire.len() - 1;
    wire[last] ^= 0x01;

    assert_rejected(lab.decrypt("bob", &wire));
}

#[test]
fn removal_rotates_group_and_blocks_a_pre_removal_snapshot_from_successor_traffic() {
    // Catches a removal that only changes a denial flag instead of evolving group state.
    let mut lab = MlsLab::new().expect("new lab should create alice");
    lab.add_member("bob").expect("bob should join");
    lab.add_member("carol").expect("carol should join");
    lab.snapshot_member("bob", "revoked-copy")
        .expect("a complete pre-removal bob endpoint should be snapshot");

    let old_payload = b"before removal";
    let old_aad = b"epoch: old";
    let old_wire = lab
        .protect("alice", old_payload, old_aad)
        .expect("alice should protect old-epoch traffic");

    // A snapshot represents the same cryptographic endpoint until membership changes.
    let (snapshot_payload, snapshot_aad) = lab
        .decrypt("revoked-copy", &old_wire)
        .expect("pre-removal snapshot should decrypt old-epoch traffic");
    assert_eq!(snapshot_payload, old_payload);
    assert_eq!(snapshot_aad, old_aad);

    let epoch_before_removal = lab.epoch();
    lab.remove_member("bob").expect("bob should be removed");
    assert!(
        lab.epoch() > epoch_before_removal,
        "removing a member must advance the epoch"
    );
    assert_member_set(&lab, &["alice", "carol"]);

    let successor_payload = b"after removal";
    let successor_aad = b"epoch: successor";
    let successor_wire = lab
        .protect("alice", successor_payload, successor_aad)
        .expect("remaining member should protect successor traffic");

    let (carol_payload, carol_aad) = lab
        .decrypt("carol", &successor_wire)
        .expect("remaining member should decrypt successor traffic");
    assert_eq!(carol_payload, successor_payload);
    assert_eq!(carol_aad, successor_aad);
    assert_rejected(lab.decrypt("revoked-copy", &successor_wire));
    assert_rejected(lab.decrypt("bob", &successor_wire));
    assert_rejected(lab.protect("bob", b"removed sender", b"aad"));
    assert_rejected(lab.protect("mallory", b"unknown sender", b"aad"));
}
