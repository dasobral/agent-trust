//! Durable OpenMLS endpoint state: restart, retained-state adversary, and
//! crash atomicity at the durability boundary.
//!
//! Each durable endpoint stores its OpenMLS state in its own SQLite file
//! (rollback-journal mode). The adversary of the compatibility matrix is a
//! byte-for-byte copy of a member's file taken before its removal and opened in
//! a fresh connection, outside the trusted adapter's roster.

mod common;

use std::path::Path;

use agent_trust::mls::{EntropySource, MlsLab};
use common::FakeQrng;
use sha2::{Digest, Sha256};

fn durable(dir: &Path) -> MlsLab {
    MlsLab::open_durable(dir, EntropySource::Os).expect("durable lab")
}

fn file_digest(path: &Path) -> Vec<u8> {
    Sha256::digest(std::fs::read(path).expect("state file readable")).to_vec()
}

#[test]
fn restarted_member_reloads_secrets_and_signing_key_from_its_state_file() {
    // Catches state kept only in memory: after restart the member must still
    // decrypt traffic it never processed before and must still sign as itself.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lab = durable(dir.path());
    lab.add_member("bob").expect("bob joins");
    lab.add_member("carol").expect("carol joins");
    let bob_file = lab.state_file("bob").expect("bob has a state file");
    assert!(bob_file.starts_with(dir.path()));
    assert!(bob_file.is_file());

    let before_restart = lab
        .protect("alice", b"sent before restart", b"aad-1")
        .expect("alice protects");

    let report = lab.restart_member("bob").expect("bob restarts from disk");
    assert_eq!(
        report.loaded_epoch,
        lab.member_epoch("alice").expect("alice")
    );
    assert_eq!(report.caught_up_epoch, report.loaded_epoch);

    let (payload, aad) = lab
        .decrypt("bob", &before_restart)
        .expect("restarted bob decrypts traffic from before the restart");
    assert_eq!(payload, b"sent before restart");
    assert_eq!(aad, b"aad-1");

    let from_bob = lab
        .protect("bob", b"sent after restart", b"")
        .expect("restarted bob signs and protects");
    assert_eq!(
        lab.decrypt("alice", &from_bob).expect("alice decrypts").0,
        b"sent after restart"
    );
    assert_eq!(
        lab.decrypt("carol", &from_bob).expect("carol decrypts").0,
        b"sent after restart"
    );
}

#[test]
fn retained_byte_copy_of_removed_member_cannot_read_successor_traffic() {
    // Catches revocation that relies on the removed endpoint discarding state:
    // a complete pre-removal copy of its durable store must decrypt old-epoch
    // traffic (so the copy is real) and must fail on successor traffic.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lab = durable(dir.path());
    lab.add_member("bob").expect("bob joins");
    lab.add_member("carol").expect("carol joins");

    let old_wire = lab
        .protect("alice", b"old epoch", b"")
        .expect("alice protects old-epoch traffic");

    lab.retain_storage_copy("bob", "bob-retained")
        .expect("copy bob's store before removal");
    let bob_file = lab.state_file("bob").expect("bob file");
    let copy_file = lab.state_file("bob-retained").expect("copy file");
    assert_ne!(bob_file, copy_file);
    assert_eq!(
        file_digest(&bob_file),
        file_digest(&copy_file),
        "the retained copy must be byte-for-byte the member's quiescent store"
    );
    let journal_mode: String = rusqlite::Connection::open(&copy_file)
        .expect("open copy")
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("journal mode");
    assert_eq!(journal_mode, "delete", "a quiescent file copy is complete");
    for suffix in ["-wal", "-journal"] {
        let mut sidecar = bob_file.clone().into_os_string();
        sidecar.push(suffix);
        assert!(!Path::new(&sidecar).exists(), "no {suffix} at copy time");
    }

    assert_eq!(
        lab.decrypt("bob-retained", &old_wire)
            .expect("retained copy decrypts old-epoch traffic")
            .0,
        b"old epoch"
    );

    let epoch = lab.epoch();
    lab.remove_member("bob").expect("bob removed");
    assert!(lab.epoch() > epoch);

    let successor = lab
        .protect("alice", b"successor", b"")
        .expect("alice protects successor traffic");
    assert_eq!(
        lab.decrypt("carol", &successor).expect("carol decrypts").0,
        b"successor"
    );
    assert!(lab.decrypt("bob-retained", &successor).is_err());
    assert!(lab.decrypt("bob", &successor).is_err());

    lab.restart_member("carol")
        .expect("carol restarts after removal");
    let later = lab
        .protect("alice", b"after carol restart", b"")
        .expect("alice protects");
    assert_eq!(
        lab.decrypt("carol", &later)
            .expect("restarted carol decrypts")
            .0,
        b"after carol restart"
    );
    assert!(lab.decrypt("bob-retained", &later).is_err());
}

#[test]
fn crash_before_commit_rolls_back_to_the_previous_epoch_and_catches_up() {
    // Catches non-atomic epoch installation: a receiving member that dies after
    // OpenMLS wrote the successor state but before the durable commit must come
    // back at the previous epoch, complete, and then process the same commit.
    // The crashed member must not block the continuing members.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lab = durable(dir.path());
    lab.add_member("bob").expect("bob joins");
    lab.add_member("carol").expect("carol joins");
    let previous = lab.member_epoch("carol").expect("carol epoch");

    lab.arm_crash_before_commit("carol")
        .expect("arm carol's crash");
    lab.remove_member("bob")
        .expect("an offline member does not block removal");
    let successor_epoch = lab.member_epoch("alice").expect("alice epoch");
    assert!(successor_epoch > previous);

    let wire = lab
        .protect("alice", b"while carol is down", b"")
        .expect("alice protects");
    assert!(
        lab.decrypt("carol", &wire).is_err(),
        "a crashed member is offline until restarted"
    );

    let report = lab.restart_member("carol").expect("carol restarts");
    assert_eq!(
        report.loaded_epoch, previous,
        "the uncommitted successor epoch must roll back completely"
    );
    assert_eq!(report.caught_up_epoch, successor_epoch);
    assert_eq!(
        lab.decrypt("carol", &wire)
            .expect("carol decrypts after catch-up")
            .0,
        b"while carol is down"
    );
}

#[test]
fn durable_lab_refuses_reuse_and_memory_lab_has_no_durable_state() {
    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(dir.path().join("alice.sqlite"), b"pre-existing").expect("write");
    assert!(
        MlsLab::open_durable(dir.path(), EntropySource::Os).is_err(),
        "an existing state file must not be overwritten or silently reused"
    );

    let mut memory = MlsLab::new().expect("memory lab");
    memory.add_member("bob").expect("bob joins");
    assert!(memory.state_file("bob").is_none());
    assert!(memory.restart_member("bob").is_err());
    assert!(memory.retain_storage_copy("bob", "copy").is_err());
}

#[test]
fn failed_durable_admission_leaves_no_state_file_and_can_be_retried() {
    // Characterization test (written after implementation): an admission that
    // fails closed on QRNG unavailability must not leave a half-created state
    // file that would block the retry once entropy returns.
    let qrng = FakeQrng::start();
    let dir = tempfile::tempdir().expect("temp dir");
    let mut lab =
        MlsLab::open_durable(dir.path(), EntropySource::Qrng(qrng.client())).expect("lab");

    qrng.set_unavailable(true);
    assert!(lab.add_member("bob").is_err());
    assert!(!dir.path().join("bob.sqlite").exists());
    assert!(lab.state_file("bob").is_none());

    qrng.set_unavailable(false);
    lab.add_member("bob").expect("retry succeeds");
    assert!(dir.path().join("bob.sqlite").is_file());
    lab.restart_member("bob").expect("bob restarts");
    let wire = lab
        .protect("alice", b"durable qrng", b"")
        .expect("alice protects");
    assert_eq!(
        lab.decrypt("bob", &wire).expect("bob decrypts").0,
        b"durable qrng"
    );
}
