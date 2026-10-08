//! End-to-end LAP-MLS: the durable APF kernel coupled to real OpenMLS groups
//! through the trusted adapter (`agent_trust::lap::LapMls`).
//!
//! Every membership transition here is a real OpenMLS commit; the kernel only
//! ever sees evidence the adapter derived from those commits. Adversarial
//! commits (`MlsLab::adversarial_commit`) model a compromised member endpoint
//! that bypasses the adapter.

use agent_trust::authority::canonical_frontier_id;
use agent_trust::lap::{join_envelope, split_envelope, LapMls, LAP_GROUP};
use agent_trust::mls::EntropySource;
use serde_json::{json, Value};

fn lap() -> LapMls {
    LapMls::in_memory(EntropySource::Os).expect("LAP laboratory")
}

fn grant(lap: &mut LapMls, subject: &str, right: &str, generation: u64) {
    lap.authority(
        json!({"command": "grant", "actor": "alice", "subject": subject,
                         "right": right, "generation": generation, "fresh_keys": true,
                         "now": 10}),
    )
    .unwrap_or_else(|e| panic!("grant {right} to {subject}: {e}"));
}

fn member(lap: &mut LapMls, subject: &str) {
    for right in ["read", "write", "admit"] {
        grant(lap, subject, right, 0);
    }
    lap.admit("alice", subject, 20)
        .unwrap_or_else(|e| panic!("admit {subject}: {e}"));
}

fn revoke(lap: &mut LapMls, subject: &str, right: &str) -> Value {
    lap.authority(
        json!({"command": "revoke", "actor": "alice", "subject": subject,
                         "right": right, "now": 30}),
    )
    .expect("revoke")
}

fn checkpoint(lap: &mut LapMls) -> Value {
    lap.checkpoint().expect("checkpoint")
}

fn local_branch(lap: &mut LapMls, name: &str) -> String {
    let frontier = lap.lab().frontier(name).expect("member frontier");
    canonical_frontier_id(
        LAP_GROUP,
        frontier.epoch,
        &frontier.tree_hash,
        &frontier.confirmed_transcript_hash,
    )
}

fn has_code<T: std::fmt::Debug>(result: Result<T, String>, expected: &str) -> String {
    let error = result.expect_err("operation must be rejected");
    assert!(error.contains(expected), "expected {expected}, got {error}");
    error
}

#[test]
fn bound_group_carries_signed_acc_context_and_incarnations_matching_the_apf() {
    let mut lap = lap();
    member(&mut lap, "bob");
    member(&mut lap, "carol");

    let checkpoint = checkpoint(&mut lap);
    let branch = checkpoint["branch"].as_str().unwrap().to_owned();
    for name in ["alice", "bob", "carol"] {
        assert_eq!(
            local_branch(&mut lap, name),
            branch,
            "{name} at the APF frontier"
        );
        let (revision, roster) = lap.lab().acc_context(name).expect("acc_context");
        assert!(revision < checkpoint["revision"].as_u64().unwrap());
        assert_eq!(
            roster,
            vec![("alice".into(), 0), ("bob".into(), 0), ("carol".into(), 0)]
        );
        let mut incarnations = lap.lab().incarnations(name);
        incarnations.sort();
        assert_eq!(incarnations, roster, "{name}'s tree matches acc_context");
    }
    let commits = checkpoint["lap"]["commits"].as_array().unwrap();
    assert_eq!(commits.len(), 2);
    assert!(commits.iter().all(|c| c["kind"] == "admit"));
}

#[test]
fn release_certificate_is_bound_to_ciphertext_content_and_single_consumption() {
    let mut lap = lap();
    member(&mut lap, "bob");
    member(&mut lap, "carol");
    member(&mut lap, "dave");

    let first = lap.send("alice", "op-1", b"first", 40).expect("send first");
    let second = lap
        .send("alice", "op-2", b"second", 40)
        .expect("send second");

    assert_eq!(
        lap.receive("bob", &first, 41).expect("bob receives"),
        b"first"
    );
    // A duplicate delivery is rejected (MLS has deleted the message key; the
    // APF replay barrier is exercised against a rolled-back client below).
    assert!(lap.receive("bob", &first, 41).is_err());
    assert_eq!(
        lap.receive("carol", &first, 41).expect("carol receives"),
        b"first"
    );

    // A certificate moved onto another ciphertext fails the AAD binding
    // (dave has not opened the first ciphertext, so MLS decryption succeeds).
    let (cert_two, _) = split_envelope(&second).expect("split");
    let (_, wire_one) = split_envelope(&first).expect("split");
    let spliced = join_envelope(cert_two, wire_one);
    let (_, wire_two) = split_envelope(&second).expect("split");
    let wire_two = wire_two.to_vec();
    has_code(lap.receive("dave", &spliced, 42), "binding_mismatch");

    // A modified certificate fails its APF signature.
    let (cert, wire) = split_envelope(&second).expect("split");
    let mut forged = cert.to_vec();
    let position = forged.len() / 2;
    forged[position] ^= 0x01;
    has_code(
        lap.receive("bob", &join_envelope(&forged, wire), 42),
        "certificate",
    );

    // The untouched envelope still delivers exactly once.
    assert_eq!(
        lap.receive("bob", &join_envelope(cert_two, &wire_two), 42)
            .expect("bob receives second"),
        b"second"
    );
}

#[test]
fn read_revocation_fences_until_qualifying_repair_and_excludes_retained_state() {
    let mut lap = lap();
    member(&mut lap, "bob");
    member(&mut lap, "carol");
    member(&mut lap, "dave");
    lap.lab()
        .snapshot_member("bob", "bob-retained")
        .expect("retain bob's complete pre-revocation state");
    let pre_cut = lap
        .send("alice", "op-pre", b"pre-cut", 40)
        .expect("pre-cut send");

    let revoked = revoke(&mut lap, "bob", "read");
    assert_eq!(revoked["read_fenced"], true);
    has_code(
        lap.send("alice", "op-fenced", b"blocked", 41),
        "read_fenced",
    );
    has_code(lap.receive("carol", &pre_cut, 41), "read_fenced");

    // Baseline: API-only revocation. Traffic protected without the APF fence
    // (no MLS removal yet) is still readable by the revoked member's state.
    let bypass = lap
        .lab()
        .protect("alice", b"api-only", b"")
        .expect("raw MLS protect bypassing the adapter");
    assert_eq!(
        lap.lab()
            .decrypt("bob-retained", &bypass)
            .expect("retained reads")
            .0,
        b"api-only"
    );

    let report = lap.repair("alice", 50).expect("qualifying repair");
    assert_eq!(report.removed, vec!["bob".to_owned()]);
    assert_eq!(report.designated, "carol");
    assert!(report.confirmed);
    let checkpoint = checkpoint(&mut lap);
    assert_eq!(checkpoint["read_fenced"], false);
    assert_eq!(checkpoint["roster"], json!(["alice", "carol", "dave"]));
    let repair_entry = checkpoint["lap"]["commits"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    assert_eq!(repair_entry["kind"], "repair");
    let (revision, roster) = lap.lab().acc_context("carol").expect("acc_context");
    assert!(revision >= revoked["revision"].as_u64().unwrap());
    assert_eq!(
        roster,
        vec![("alice".into(), 0), ("carol".into(), 0), ("dave".into(), 0)]
    );

    let post = lap
        .send("alice", "op-post", b"successor", 51)
        .expect("post-repair send");
    assert_eq!(
        lap.receive("carol", &post, 52).expect("carol"),
        b"successor"
    );
    assert_eq!(lap.receive("dave", &post, 52).expect("dave"), b"successor");
    let (_, post_wire) = split_envelope(&post).expect("split");
    let post_wire = post_wire.to_vec();
    assert!(lap.lab().decrypt("bob-retained", &post_wire).is_err());
    assert!(lap.lab().decrypt("bob", &post_wire).is_err());
    assert!(lap.receive("bob", &post, 52).is_err());

    // The pre-cut release named the old epoch: delivery is rejected after repair.
    assert!(lap.receive("dave", &pre_cut, 52).is_err());
}

#[test]
fn rejected_canonicalization_rolls_the_committer_back() {
    let mut lap = lap();
    member(&mut lap, "bob");
    let before = local_branch(&mut lap, "alice");

    // Carol has no admit right: the APF rejects the real MLS Add commit.
    grant(&mut lap, "carol", "read", 0);
    has_code(lap.admit("alice", "carol", 20), "unauthorized");
    assert_eq!(
        local_branch(&mut lap, "alice"),
        before,
        "committer rolled back"
    );
    assert_eq!(
        lap.lab().members(),
        vec!["alice".to_owned(), "bob".to_owned()]
    );

    // Repair while not fenced is rejected the same way.
    has_code(lap.repair("alice", 30), "invalid_repair");
    assert_eq!(local_branch(&mut lap, "alice"), before);

    // Progress continues at the unchanged frontier.
    let envelope = lap.send("alice", "op-1", b"still fine", 40).expect("send");
    assert_eq!(
        lap.receive("bob", &envelope, 41).expect("bob"),
        b"still fine"
    );
}

#[test]
fn members_reject_commits_whose_acc_context_is_forged_stale_or_incoherent() {
    let mut lap = lap();
    member(&mut lap, "bob");
    member(&mut lap, "carol");
    let (revision, _) = lap.lab().acc_context("carol").expect("acc_context");
    let before = local_branch(&mut lap, "carol");

    let honest = lap
        .lab()
        .sign_acc_context(revision + 1, &[("alice", 0), ("bob", 0), ("carol", 0)]);
    let mut forged = honest.clone();
    let position = forged.len() - 3;
    forged[position] ^= 0x01;
    let stale = lap
        .lab()
        .sign_acc_context(0, &[("alice", 0), ("bob", 0), ("carol", 0)]);
    let incoherent = lap
        .lab()
        .sign_acc_context(revision + 1, &[("alice", 0), ("bob", 0), ("carol", 0)]);

    for (label, acc, removals) in [
        ("forged signature", forged, vec![]),
        ("revision rollback", stale, vec![]),
        ("roster without the removal", incoherent, vec!["alice"]),
    ] {
        let wire = lap
            .lab()
            .adversarial_commit("bob", acc, &removals)
            .unwrap_or_else(|e| panic!("{label}: rogue commit: {e}"));
        let error = lap
            .lab()
            .process_commit_as("carol", &wire)
            .expect_err(label);
        assert!(error.contains("coherence"), "{label}: {error}");
        assert_eq!(
            local_branch(&mut lap, "carol"),
            before,
            "{label}: rolled back"
        );
    }

    // Carol keeps working at the canonical frontier with honest members.
    let envelope = lap.send("alice", "op-1", b"after rogue", 40).expect("send");
    assert_eq!(
        lap.receive("carol", &envelope, 41).expect("carol"),
        b"after rogue"
    );
}

#[test]
fn write_revocation_closes_the_generation_without_removing_the_reader() {
    let mut lap = lap();
    member(&mut lap, "bob");
    let epoch = checkpoint(&mut lap)["epoch"].clone();

    let revoked = revoke(&mut lap, "bob", "write");
    assert_eq!(revoked["read_fenced"], false);
    has_code(lap.send("bob", "op-bob", b"denied", 40), "unauthorized");

    let envelope = lap
        .send("alice", "op-1", b"bob still reads", 40)
        .expect("send");
    assert_eq!(
        lap.receive("bob", &envelope, 41).expect("bob"),
        b"bob still reads"
    );
    assert_eq!(checkpoint(&mut lap)["epoch"], epoch);
    assert_eq!(
        lap.lab().members(),
        vec!["alice".to_owned(), "bob".to_owned()]
    );
}

#[test]
fn reauthorization_requires_a_fresh_generation_and_fresh_keys() {
    let mut lap = lap();
    member(&mut lap, "bob");
    member(&mut lap, "carol");
    let old_key = lap.lab().member_signature_key("bob").expect("bob key");
    lap.lab()
        .snapshot_member("bob", "bob-gen0")
        .expect("retain gen-0 state");

    revoke(&mut lap, "bob", "read");
    lap.repair("alice", 50).expect("repair");
    has_code(lap.admit("alice", "bob", 60), "unauthorized");
    has_code(
        lap.authority(
            json!({"command": "grant", "actor": "alice", "subject": "bob",
                             "right": "read", "generation": 0, "fresh_keys": true,
                             "now": 60}),
        ),
        "invalid_generation",
    );

    grant(&mut lap, "bob", "read", 1);
    lap.admit("alice", "bob", 61)
        .expect("re-admit bob at generation 1");
    let mut incarnations = lap.lab().incarnations("carol");
    incarnations.sort();
    assert_eq!(
        incarnations,
        vec![("alice".into(), 0), ("bob".into(), 1), ("carol".into(), 0)]
    );
    assert_ne!(lap.lab().member_signature_key("bob").expect("key"), old_key);

    let envelope = lap
        .send("alice", "op-1", b"generation one", 70)
        .expect("send");
    assert_eq!(
        lap.receive("bob", &envelope, 71).expect("bob"),
        b"generation one"
    );
    let (_, wire) = split_envelope(&envelope).expect("split");
    let wire = wire.to_vec();
    assert!(lap.lab().decrypt("bob-gen0", &wire).is_err());
}

#[test]
fn invocation_provenance_holds_through_the_adapter() {
    let mut lap = lap();
    member(&mut lap, "bob");
    // carol is a read-only member originating a request executed by alice.
    for right in ["read", "admit"] {
        grant(&mut lap, "carol", right, 0);
    }
    lap.admit("alice", "carol", 20).expect("admit carol");
    // A read-only origin cannot even issue a write invocation...
    has_code(
        lap.authority(
            json!({"command": "invoke", "actor": "carol", "executor": "alice",
                             "rights": ["write"], "resources": [LAP_GROUP], "now": 30}),
        ),
        "unauthorized",
    );
    // ...and alice cannot turn carol's read invocation into a write release.
    let invocation = lap
        .authority(
            json!({"command": "invoke", "actor": "carol", "executor": "alice",
                          "rights": ["read"], "resources": [LAP_GROUP], "now": 30}),
        )
        .expect("carol issues a read invocation")["invocation"]
        .as_str()
        .unwrap()
        .to_owned();

    has_code(
        lap.send_invoked("alice", "op-deputy", &invocation, b"laundered write", 40),
        "unauthorized",
    );
    let own = lap
        .send("alice", "op-own", b"alice's own write", 40)
        .expect("own write");
    assert_eq!(
        lap.receive("carol", &own, 41).expect("carol"),
        b"alice's own write"
    );
}

#[test]
fn adapter_only_commands_are_not_exposed_through_the_admin_interface() {
    let mut lap = lap();
    for command in [
        "admit",
        "repair",
        "confirm_repair",
        "release",
        "persist",
        "emit",
        "consume",
    ] {
        has_code(lap.authority(json!({"command": command})), "unauthorized");
    }
}

#[test]
fn offline_member_does_not_block_repair_and_stays_locally_fenced_until_restart() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lap = LapMls::durable(dir.path(), EntropySource::Os).expect("durable LAP");
    member(&mut lap, "bob");
    member(&mut lap, "carol");
    member(&mut lap, "dave");

    // Carol crashes while installing erin's admission and stays offline.
    lap.lab()
        .arm_crash_before_commit("carol")
        .expect("arm crash");
    member(&mut lap, "erin");
    assert!(lap.lab().frontier("carol").is_none(), "carol is offline");
    revoke(&mut lap, "bob", "read");
    let report = lap
        .repair("alice", 50)
        .expect("repair proceeds without carol");
    assert_eq!(
        report.designated, "dave",
        "an offline member is not designated"
    );
    assert!(report.confirmed);

    let envelope = lap
        .send("alice", "op-1", b"while carol is down", 51)
        .expect("send");
    assert_eq!(
        lap.receive("dave", &envelope, 52).expect("dave"),
        b"while carol is down"
    );
    assert!(
        lap.receive("carol", &envelope, 52).is_err(),
        "offline carol is fenced"
    );

    let restart = lap.lab().restart_member("carol").expect("carol restarts");
    assert!(restart.caught_up_epoch > restart.loaded_epoch);
    assert_eq!(
        lap.receive("carol", &envelope, 53)
            .expect("carol after catch-up"),
        b"while carol is down"
    );
}

#[test]
fn rolled_back_client_cannot_replay_a_consumed_release() {
    // Catches consumption tracked only by client state: a client restored to a
    // pre-delivery snapshot can decrypt again, so the APF must refuse the
    // second consumption.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lap = LapMls::durable(dir.path(), EntropySource::Os).expect("durable LAP");
    member(&mut lap, "bob");
    let envelope = lap.send("alice", "op-1", b"once only", 40).expect("send");
    lap.lab()
        .retain_storage_copy("bob", "bob-before")
        .expect("snapshot bob before delivery");

    assert_eq!(
        lap.receive("bob", &envelope, 41).expect("first delivery"),
        b"once only"
    );
    lap.lab()
        .restore_member_from("bob", "bob-before")
        .expect("roll bob's store back to before delivery");
    has_code(lap.receive("bob", &envelope, 42), "replay");
}
