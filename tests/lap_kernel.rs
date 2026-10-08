//! Kernel contract for lap mode: the APF frontier is the real MLS epoch
//! identity, and membership transitions require MLS-derived evidence, a parent
//! compare-and-swap, a current `acc_context` binding, and (for repair) a
//! confirmation from the designated continuing member.
//!
//! Frontier hashes here are synthetic byte strings; the end-to-end tests in
//! `tests/lap_mls.rs` drive the same commands from real OpenMLS state.

use agent_trust::authority::Authority;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const GROUP: &str = "lab-group";

fn frontier(epoch: u64, tag: u8) -> Value {
    json!({
        "epoch": epoch,
        "tree_hash": hex::encode([tag; 32]),
        "confirmed_transcript_hash": hex::encode([tag ^ 0x5a; 32]),
    })
}

/// Independent recomputation of the documented frontier identity.
fn frontier_id(value: &Value) -> String {
    let mut input = b"AT-FRONTIER".to_vec();
    let sized = |input: &mut Vec<u8>, bytes: &[u8]| {
        input.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        input.extend_from_slice(bytes);
    };
    sized(&mut input, GROUP.as_bytes());
    input.extend_from_slice(&value["epoch"].as_u64().unwrap().to_be_bytes());
    sized(
        &mut input,
        &hex::decode(value["tree_hash"].as_str().unwrap()).unwrap(),
    );
    sized(
        &mut input,
        &hex::decode(value["confirmed_transcript_hash"].as_str().unwrap()).unwrap(),
    );
    hex::encode(Sha256::digest(&input))
}

fn code<T: std::fmt::Debug>(result: Result<T, String>, expected: &str) {
    let error = result.expect_err("request should be rejected");
    assert!(
        error == expected || error.starts_with(&format!("{expected}:")),
        "expected {expected}, got {error}"
    );
}

fn roster(members: &[(&str, u64)]) -> Value {
    Value::Array(
        members
            .iter()
            .map(|(subject, generation)| json!({"subject": subject, "generation": generation}))
            .collect(),
    )
}

struct Lap {
    _dir: tempfile::TempDir,
    apf: Authority,
}

impl Lap {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut apf = Authority::open(dir.path().join("apf.sqlite")).expect("open");
        let response = apf
            .execute(json!({"command": "init", "group": GROUP, "root": "alice",
                            "frontier": frontier(0, 1)}))
            .expect("lap init");
        assert_eq!(response["branch"], frontier_id(&frontier(0, 1)));
        Self { _dir: dir, apf }
    }

    fn run(&mut self, request: Value) -> Result<Value, String> {
        self.apf.execute(request)
    }

    fn ok(&mut self, request: Value) -> Value {
        self.run(request).expect("request should succeed")
    }

    fn checkpoint(&mut self) -> Value {
        self.ok(json!({"command": "checkpoint"}))
    }

    fn grant_member(&mut self, subject: &str) {
        for right in ["read", "write", "admit"] {
            self.ok(
                json!({"command": "grant", "actor": "alice", "subject": subject,
                           "right": right, "generation": 0, "fresh_keys": true, "now": 10}),
            );
        }
    }

    fn admit(&mut self, subject: &str, parent: &Value, successor: &Value, acc: &[(&str, u64)]) {
        let revision = self.checkpoint()["revision"].clone();
        let acc_roster = roster(acc);
        let response = self.ok(json!({
            "command": "admit", "actor": "alice", "subject": subject, "now": 20,
            "parent": frontier_id(parent), "successor": successor,
            "acc_revision": revision, "acc_roster": acc_roster,
            "generation": 0, "commit": "00ff",
        }));
        assert_eq!(response["branch"], frontier_id(successor));
    }
}

#[test]
fn lap_init_binds_the_frontier_and_refuses_fixture_transitions() {
    let mut lap = Lap::new();
    let checkpoint = lap.checkpoint();
    assert_eq!(checkpoint["epoch"], 0);
    assert_eq!(checkpoint["branch"], frontier_id(&frontier(0, 1)));
    assert_eq!(checkpoint["lap"]["frontier"], frontier(0, 1));

    // The fixture repair takes caller booleans; lap mode must refuse it.
    lap.ok(
        json!({"command": "revoke", "actor": "alice", "subject": "alice",
                  "right": "write", "now": 10}),
    );
    code(
        lap.run(
            json!({"command": "repair", "parent_branch": frontier_id(&frontier(0, 1)),
                       "new_branch": "x", "epoch": 1, "revision": 1, "removed": ["bob"],
                       "update_path": true, "confirmed": true, "durable": true}),
        ),
        "malformed",
    );
    // The fixture admit names no MLS successor; lap mode must refuse it.
    lap.grant_member("bob");
    code(
        lap.run(json!({"command": "admit", "actor": "alice", "subject": "bob", "now": 20})),
        "malformed",
    );
}

#[test]
fn lap_admit_requires_cas_current_binding_and_incarnation_generation() {
    let mut lap = Lap::new();
    lap.grant_member("bob");
    let genesis = frontier(0, 1);
    let next = frontier(1, 2);
    let revision = lap.checkpoint()["revision"].as_u64().unwrap();
    let good_roster = roster(&[("alice", 0), ("bob", 0)]);
    let base = json!({
        "command": "admit", "actor": "alice", "subject": "bob", "now": 20,
        "parent": frontier_id(&genesis), "successor": next,
        "acc_revision": revision, "acc_roster": good_roster,
        "generation": 0, "commit": "00ff",
    });
    let with = |key: &str, value: Value| {
        let mut request = base.clone();
        request[key] = value;
        request
    };

    code(
        lap.run(with("parent", json!(frontier_id(&frontier(0, 9))))),
        "stale_frontier",
    );
    code(
        lap.run(with("successor", frontier(2, 2))),
        "invalid_transition",
    );
    code(
        lap.run(with("acc_revision", json!(revision - 1))),
        "binding_mismatch",
    );
    code(
        lap.run(with("acc_roster", roster(&[("alice", 0)]))),
        "binding_mismatch",
    );
    code(
        lap.run(with("acc_roster", roster(&[("alice", 0), ("bob", 1)]))),
        "binding_mismatch",
    );
    code(lap.run(with("generation", json!(1))), "invalid_generation");
    assert_eq!(
        lap.checkpoint()["epoch"],
        0,
        "rejections leave state unchanged"
    );

    let response = lap.ok(base.clone());
    assert_eq!(response["epoch"], 1);
    assert_eq!(response["branch"], frontier_id(&next));

    // A sibling successor from the same parent loses the compare-and-swap.
    lap.grant_member("carol");
    let revision = lap.checkpoint()["revision"].clone();
    code(
        lap.run(json!({
            "command": "admit", "actor": "alice", "subject": "carol", "now": 20,
            "parent": frontier_id(&genesis), "successor": frontier(1, 3),
            "acc_revision": revision,
            "acc_roster": roster(&[("alice", 0), ("bob", 0), ("carol", 0)]),
            "generation": 0, "commit": "00ff",
        })),
        "stale_frontier",
    );

    let log = lap.checkpoint()["lap"]["commits"].clone();
    assert_eq!(log.as_array().unwrap().len(), 1);
    assert_eq!(log[0]["kind"], "admit");
    assert_eq!(log[0]["parent"], frontier_id(&genesis));
    assert_eq!(log[0]["branch"], frontier_id(&next));
    assert_eq!(log[0]["commit"], "00ff");
}

#[test]
fn lap_repair_requires_exact_evidence_and_designated_confirmation() {
    let mut lap = Lap::new();
    lap.grant_member("bob");
    lap.grant_member("carol");
    let f0 = frontier(0, 1);
    let f1 = frontier(1, 2);
    let f2 = frontier(2, 3);
    lap.admit("bob", &f0, &f1, &[("alice", 0), ("bob", 0)]);
    lap.admit("carol", &f1, &f2, &[("alice", 0), ("bob", 0), ("carol", 0)]);

    let revoked = lap.ok(
        json!({"command": "revoke", "actor": "alice", "subject": "bob",
                                "right": "read", "now": 30}),
    );
    assert_eq!(revoked["read_fenced"], true);
    let denial_revision = revoked["revision"].as_u64().unwrap();
    assert_eq!(lap.checkpoint()["lap"]["denial_revision"], denial_revision);

    let f3 = frontier(3, 4);
    let continuing = roster(&[("alice", 0), ("carol", 0)]);
    let base = json!({
        "command": "repair", "parent": frontier_id(&f2), "successor": f3,
        "removed": ["bob"], "update_path": true, "acc_revision": denial_revision,
        "acc_roster": continuing, "designated": "carol", "commit": "0aff",
    });
    let with = |key: &str, value: Value| {
        let mut request = base.clone();
        request[key] = value;
        request
    };

    code(
        lap.run(with("parent", json!(frontier_id(&f1)))),
        "stale_frontier",
    );
    code(lap.run(with("removed", json!(["carol"]))), "invalid_repair");
    code(
        lap.run(with("removed", json!(["bob", "carol"]))),
        "invalid_repair",
    );
    code(lap.run(with("update_path", json!(false))), "invalid_repair");
    code(
        lap.run(with("acc_revision", json!(denial_revision - 1))),
        "invalid_repair",
    );
    code(
        lap.run(with(
            "acc_roster",
            roster(&[("alice", 0), ("bob", 0), ("carol", 0)]),
        )),
        "invalid_repair",
    );
    code(lap.run(with("designated", json!("bob"))), "invalid_repair");
    assert_eq!(
        lap.checkpoint()["epoch"],
        2,
        "rejections leave state unchanged"
    );

    let repaired = lap.ok(base.clone());
    assert_eq!(repaired["branch"], frontier_id(&f3));
    let checkpoint = lap.checkpoint();
    assert_eq!(checkpoint["roster"], json!(["alice", "carol"]));
    assert_eq!(
        checkpoint["read_fenced"], true,
        "the fence stays closed until the designated member confirms"
    );

    lap.ok(json!({"command": "allocate", "actor": "alice", "op": "op-1"}));
    let revision = lap.checkpoint()["revision"].clone();
    let release = json!({
        "command": "release", "actor": "alice", "op": "op-1", "right": "write",
        "revision": revision, "epoch": 3, "branch": frontier_id(&f3),
        "digest": "d1", "now": 40,
        "cover": [[{"subject": "alice", "right": "write", "generation": 0}],
                  [{"subject": "alice", "right": "read", "generation": 0}],
                  [{"subject": "carol", "right": "read", "generation": 0}]],
    });
    code(lap.run(release.clone()), "read_fenced");

    code(
        lap.run(json!({"command": "confirm_repair", "member": "alice", "installed": f3})),
        "invalid_repair",
    );
    code(
        lap.run(json!({"command": "confirm_repair", "member": "carol",
                       "installed": frontier(3, 9)})),
        "invalid_repair",
    );
    lap.ok(json!({"command": "confirm_repair", "member": "carol", "installed": f3}));
    assert_eq!(lap.checkpoint()["read_fenced"], false);
    code(
        lap.run(json!({"command": "confirm_repair", "member": "carol", "installed": f3})),
        "invalid_repair",
    );

    let mut release = release;
    release["revision"] = lap.checkpoint()["revision"].clone();
    lap.ok(release);
}

#[test]
fn lap_repair_is_refused_while_the_group_is_not_fenced() {
    let mut lap = Lap::new();
    let revision = lap.checkpoint()["revision"].clone();
    code(
        lap.run(json!({
            "command": "repair", "parent": frontier_id(&frontier(0, 1)),
            "successor": frontier(1, 2), "removed": ["alice"], "update_path": true,
            "acc_revision": revision, "acc_roster": [], "designated": "alice",
            "commit": "00",
        })),
        "invalid_repair",
    );
}

#[test]
fn persist_and_emit_accept_real_size_mls_envelopes() {
    // Catches the envelope being parsed as a 256-byte identifier: a certificate
    // plus a real MLS ciphertext is several kilobytes of hex.
    let dir = tempfile::tempdir().expect("temp dir");
    let mut apf = Authority::open(dir.path().join("apf.sqlite")).expect("open");
    apf.execute(json!({"command": "init", "group": GROUP, "root": "alice"}))
        .expect("init");
    apf.execute(json!({"command": "allocate", "actor": "alice", "op": "op-1"}))
        .expect("allocate");
    let checkpoint = apf
        .execute(json!({"command": "checkpoint"}))
        .expect("checkpoint");
    apf.execute(json!({
        "command": "release", "actor": "alice", "op": "op-1", "right": "write",
        "revision": checkpoint["revision"], "epoch": 0, "branch": "genesis",
        "digest": "d".repeat(64), "now": 1,
        "cover": [[{"subject": "alice", "right": "write", "generation": 0}],
                  [{"subject": "alice", "right": "read", "generation": 0}]],
    }))
    .expect("release");
    let envelope = "ab".repeat(6000);
    apf.execute(
        json!({"command": "persist", "op": "op-1", "digest": "d".repeat(64),
                       "envelope": envelope}),
    )
    .expect("persist a 6000-byte envelope");
    apf.execute(json!({"command": "emit", "op": "op-1", "envelope": envelope}))
        .expect("emit the persisted envelope");
    code(
        apf.execute(
            json!({"command": "persist", "op": "op-1", "digest": "d".repeat(64),
                           "envelope": "ab".repeat(1 << 20)}),
        ),
        "malformed",
    );
}
