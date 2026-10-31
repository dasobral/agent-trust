//! R-13d.5 (D-17): `Authority::replay(after)` re-executes the recorded requests after an
//! anchor and requires byte-identical events. A writer who holds the whole store, and so
//! can recompute every hash, still cannot make the kernel accept a step its rules refuse,
//! change what a step did, or move `now` back.
use agent_trust::authority::Authority;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn fresh() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    (dir, path)
}

fn ok(kernel: &mut Authority, request: Value) -> Value {
    kernel
        .execute(request.clone())
        .unwrap_or_else(|err| panic!("{request} should succeed: {err}"))
}

/// Grants, a delegation that expires, admissions, an invocation, one message persisted
/// and consumed, an R-12 expiry recorded by a step that then fails, and later steps.
fn history(path: &Path) {
    let mut k = Authority::open(path).unwrap();
    ok(
        &mut k,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
    ok(
        &mut k,
        json!({"command":"delegate", "actor":"root", "subject":"bob", "rights":["read","write","admit"],
               "resources":["group-a"], "expires_at":50, "not_before":0, "depth":4, "now":10}),
    );
    for right in ["read", "admit", "write"] {
        ok(
            &mut k,
            json!({"command":"grant", "actor":"root", "subject":"alice", "right":right,
                   "generation":0, "fresh_keys":true, "now":10}),
        );
    }
    for subject in ["alice", "bob"] {
        ok(
            &mut k,
            json!({"command":"admit", "actor":"root", "subject":subject, "now":10}),
        );
    }
    ok(
        &mut k,
        json!({"command":"invoke", "actor":"root", "executor":"alice", "rights":["write"],
               "resources":["group-a"], "now":10}),
    );
    ok(
        &mut k,
        json!({"command":"allocate", "actor":"root", "op":"op-1"}),
    );
    let head = ok(&mut k, json!({"command":"checkpoint", "history":"none"}));
    ok(
        &mut k,
        json!({"command":"release", "actor":"root", "op":"op-1", "right":"write",
               "policy_revision":head["policy_revision"], "epoch":head["epoch"],
               "branch":head["branch"], "digest":"cafebabe",
               "cover":[[{"subject":"root","right":"write","generation":0}],
                        [{"subject":"root","right":"read","generation":0}],
                        [{"subject":"alice","right":"read","generation":0}],
                        [{"subject":"bob","right":"read","generation":0}]],
               "now":10}),
    );
    ok(
        &mut k,
        json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":"0a0b0c"}),
    );
    ok(
        &mut k,
        json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":20}),
    );
    // At 100 bob's delegation has expired: the expiry is recorded, then the step fails
    // (consume while the fence is closed).
    assert!(k
        .execute(
            json!({"command":"consume", "op":"op-1", "recipient":"bob", "actor":"bob", "now":100})
        )
        .is_err());
    ok(
        &mut k,
        json!({"command":"grant", "actor":"root", "subject":"carol", "right":"read",
               "generation":0, "fresh_keys":true, "now":100}),
    );
    ok(
        &mut k,
        json!({"command":"allocate", "actor":"root", "op":"op-2"}),
    );
}

fn events(path: &Path) -> Vec<(i64, String, String, String)> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT sequence, previous, hash, event FROM authority_events ORDER BY sequence")
        .unwrap();
    let rows = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap();
    rows.map(Result::unwrap).collect()
}

fn v2_hash(sequence: u64, previous: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-trust/kernel-event/v2\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous.as_bytes());
    hasher.update([0u8]);
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

/// Rewrites the first event whose stored bytes contain `find`, replacing it once, and
/// recomputes that hash and every later one, then drops the Merkle tree so that `open`
/// rebuilds it: a consistent store that only the replay can refuse. Returns the
/// rewritten sequence.
fn forge(path: &Path, find: &str, replace: &str) -> i64 {
    let events = events(path);
    let target = events
        .iter()
        .position(|(_, _, _, raw)| raw.contains(find))
        .unwrap_or_else(|| panic!("no event contains {find}"));
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut previous = events[target].1.clone();
    for (sequence, _, _, raw) in &events[target..] {
        let raw = if *sequence == events[target].0 {
            raw.replacen(find, replace, 1)
        } else {
            raw.clone()
        };
        let hash = v2_hash(*sequence as u64, &previous, &raw);
        connection
            .execute(
                "UPDATE authority_events SET previous = ?1, hash = ?2, event = ?3 WHERE sequence = ?4",
                rusqlite::params![previous, hash, raw, sequence],
            )
            .unwrap();
        previous = hash;
    }
    connection.execute("DROP TABLE authority_mmr", []).unwrap();
    events[target].0
}

fn corrupt(result: Result<(), String>) {
    let err = result.expect_err("replay must refuse the forged history");
    assert!(err.starts_with("corrupt_history"), "{err}");
}

#[test]
fn an_honest_history_replays_from_genesis_and_from_any_anchor() {
    let (_dir, path) = fresh();
    history(&path);
    let tip = events(&path).len() as u64 - 1;
    let mut kernel = Authority::open(&path).unwrap();
    kernel.replay(None).expect("replay from genesis");
    for after in [0, 3, 8, 11, tip - 1, tip] {
        kernel
            .replay(Some(after))
            .unwrap_or_else(|err| panic!("replay after {after}: {err}"));
    }
    // Replay changes nothing.
    let before = ok(&mut kernel, json!({"command":"checkpoint"}));
    kernel.replay(None).unwrap();
    assert_eq!(ok(&mut kernel, json!({"command":"checkpoint"})), before);
}

#[test]
fn a_rechained_step_the_rules_refuse_is_caught() {
    // carol's grant, recorded as made by alice, who holds no `admin`.
    let (_dir, path) = fresh();
    history(&path);
    let sequence = forge(
        &path,
        "\"actor\":\"root\",\"command\":\"grant\",\"fresh_keys\":true,\"generation\":0,\"now\":100",
        "\"actor\":\"alice\",\"command\":\"grant\",\"fresh_keys\":true,\"generation\":0,\"now\":100",
    );
    let mut kernel = Authority::open(&path).expect("the forged store is consistent");
    corrupt(kernel.replay(None));
    corrupt(kernel.replay(Some(sequence as u64 - 1)));
    // An anchor after the forgery covers it: replay checks only what follows.
    kernel.replay(Some(sequence as u64)).unwrap();
}

#[test]
fn a_rechained_change_to_what_a_step_did_is_caught() {
    // The release records alice's read generation as 7.
    let (_dir, path) = fresh();
    history(&path);
    forge(
        &path,
        "{\"subject\":\"alice\",\"generation\":0}",
        "{\"subject\":\"alice\",\"generation\":7}",
    );
    let mut kernel = Authority::open(&path).expect("the forged store is consistent");
    corrupt(kernel.replay(None));
}

#[test]
fn a_rechained_now_that_goes_back_is_caught() {
    // alice's consume at 20 recorded at 5, after steps at 10.
    let (_dir, path) = fresh();
    history(&path);
    forge(
        &path,
        "\"command\":\"consume\",\"now\":20",
        "\"command\":\"consume\",\"now\":5",
    );
    let mut kernel = Authority::open(&path).expect("the forged store is consistent");
    corrupt(kernel.replay(None));
}
