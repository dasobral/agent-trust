//! R-13d.2 (D-17): every operation and invocation row that a request reads is checked
//! against the event that wrote it, and that event against an append-only Merkle tree
//! over the event hashes whose root the handle derived from the chain it validated. An
//! edited row, an edited event, or an edited tree fails the next request that reads it.
use agent_trust::authority::Authority;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

fn fresh() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    (dir, path)
}

fn code<T: std::fmt::Debug>(result: Result<T, String>, expected: &str) {
    match result {
        Err(err) => assert!(
            err == expected || err.starts_with(&format!("{expected}:")),
            "expected {expected}, got {err}"
        ),
        Ok(value) => panic!("expected {expected}, got {value:?}"),
    }
}

fn ok(kernel: &mut Authority, request: Value) -> Value {
    kernel
        .execute(request.clone())
        .unwrap_or_else(|err| panic!("{request} should succeed: {err}"))
}

/// Root, alice and bob admitted; op-1 released, persisted and consumed by alice; an
/// invocation root -> bob for `write`.
fn store(path: &Path) -> Authority {
    let mut kernel = Authority::open(path).unwrap();
    ok(
        &mut kernel,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
    for reader in ["alice", "bob"] {
        for right in ["read", "admit"] {
            ok(
                &mut kernel,
                json!({"command":"grant", "actor":"root", "subject":reader, "right":right,
                       "generation":0, "fresh_keys":true, "now":10}),
            );
        }
        ok(
            &mut kernel,
            json!({"command":"admit", "actor":"root", "subject":reader, "now":10}),
        );
    }
    ok(
        &mut kernel,
        json!({"command":"grant", "actor":"root", "subject":"bob", "right":"write",
               "generation":0, "fresh_keys":true, "now":10}),
    );
    ok(
        &mut kernel,
        json!({"command":"invoke", "actor":"root", "executor":"bob", "rights":["write"],
               "resources":["group-a"], "now":10}),
    );
    ok(
        &mut kernel,
        json!({"command":"allocate", "actor":"root", "op":"op-1"}),
    );
    let head = ok(
        &mut kernel,
        json!({"command":"checkpoint", "history":"none"}),
    );
    ok(
        &mut kernel,
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
        &mut kernel,
        json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":"0a0b"}),
    );
    ok(
        &mut kernel,
        json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":10}),
    );
    kernel
}

fn sql(path: &Path, statement: &str) {
    rusqlite::Connection::open(path)
        .unwrap()
        .execute(statement, [])
        .unwrap();
}

fn invocation_id(kernel: &mut Authority) -> String {
    ok(kernel, json!({"command":"checkpoint"}))["invocations"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn an_edited_operation_row_fails_the_next_request_on_it() {
    // Clearing alice's consumption would let her consume op-1 twice.
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    sql(
        &path,
        "UPDATE authority_ops SET row = REPLACE(row, '\"consumed_by\":[\"alice\"]', '\"consumed_by\":[]') WHERE op = 'op-1'",
    );
    code(
        kernel.execute(json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":10})),
        "corrupt_history",
    );
    // A request that does not read op-1 is unaffected.
    ok(
        &mut kernel,
        json!({"command":"checkpoint", "history":"none"}),
    );
}

#[test]
fn an_edited_invocation_row_fails_the_next_request_that_names_it() {
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    let id = invocation_id(&mut kernel);
    sql(
        &path,
        "UPDATE authority_invocations SET record = REPLACE(record, '\"executor\":\"bob\"', '\"executor\":\"alice\"')",
    );
    code(
        kernel
            .execute(json!({"command":"allocate", "actor":"alice", "op":"op-2", "invocation":id})),
        "corrupt_history",
    );
}

/// The v2 event hash (`docs/authority-contract.md`, `checkpoint`).
fn v2_hash(sequence: u64, previous: &str, raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"agent-trust/kernel-event/v2\0");
    hasher.update(sequence.to_be_bytes());
    hasher.update(previous.as_bytes());
    hasher.update([0u8]);
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

#[test]
fn an_event_rewritten_with_a_valid_hash_fails_the_next_request_that_reads_its_row() {
    // The writer rewrites the consume event and the row together and recomputes that
    // event's hash; the tree over the event hashes still holds the old one.
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    // A later event, and a request after it, so the handle's anchored tip is above the
    // forged event.
    ok(
        &mut kernel,
        json!({"command":"allocate", "actor":"root", "op":"op-9"}),
    );
    ok(
        &mut kernel,
        json!({"command":"checkpoint", "history":"none"}),
    );
    let connection = rusqlite::Connection::open(&path).unwrap();
    let (sequence, previous, raw): (i64, String, String) = connection
        .query_row(
            "SELECT e.sequence, e.previous, e.event FROM authority_events e
             JOIN authority_ops o ON o.written = e.sequence WHERE o.op = 'op-1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let forged = raw.replace(
        "\"consumed_by\":[\"alice\"]}},\"invocations\"",
        "\"consumed_by\":[]}},\"invocations\"",
    );
    let forged = if forged == raw {
        // No invocations key after the ops: the row is the last field of `after`.
        raw.replacen("\"consumed_by\":[\"alice\"]", "\"consumed_by\":[]", 2)
    } else {
        forged
    };
    assert_ne!(forged, raw, "the forgery changes the event");
    let hash = v2_hash(sequence as u64, &previous, &forged);
    connection
        .execute(
            "UPDATE authority_events SET event = ?1, hash = ?2 WHERE sequence = ?3",
            rusqlite::params![forged, hash, sequence],
        )
        .unwrap();
    connection
        .execute(
            "UPDATE authority_ops SET row = REPLACE(row, '\"consumed_by\":[\"alice\"]', '\"consumed_by\":[]') WHERE op = 'op-1'",
            [],
        )
        .unwrap();
    code(
        kernel.execute(json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":10})),
        "corrupt_history",
    );
}

/// `store` writes 13 events. The tree over 13 leaves has peaks (3,0), (2,2) and (0,12);
/// the invocation was written by event 8, whose proof uses (0,9), (1,5) and (2,2).
#[test]
fn an_edited_peak_fails_every_request() {
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    sql(
        &path,
        "UPDATE authority_mmr SET hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE height = 3 AND idx = 0",
    );
    code(
        kernel.execute(json!({"command":"checkpoint", "history":"none"})),
        "corrupt_history",
    );
}

#[test]
fn an_edited_inner_node_fails_the_next_request_whose_proof_uses_it() {
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    let id = invocation_id(&mut kernel);
    sql(
        &path,
        "UPDATE authority_mmr SET hash = '0000000000000000000000000000000000000000000000000000000000000000' WHERE height = 0 AND idx = 9",
    );
    // Not a peak: a request that reads no row written under it is unaffected.
    ok(&mut kernel, json!({"command":"checkpoint", "history":"none"}));
    code(
        kernel.execute(json!({"command":"allocate", "actor":"bob", "op":"op-2", "invocation":id})),
        "corrupt_history",
    );
}

#[test]
fn a_store_without_the_tree_builds_it_at_open() {
    let (_dir, path) = fresh();
    let mut kernel = store(&path);
    let before = ok(&mut kernel, json!({"command":"checkpoint"}));
    drop(kernel);
    sql(&path, "DROP TABLE authority_mmr");
    let mut reopened = Authority::open(&path).unwrap();
    assert_eq!(ok(&mut reopened, json!({"command":"checkpoint"})), before);
    code(
        reopened.execute(json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":10})),
        "replay",
    );
    ok(
        &mut reopened,
        json!({"command":"consume", "op":"op-1", "recipient":"bob", "actor":"bob", "now":10}),
    );
}
