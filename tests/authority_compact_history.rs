//! R-13d.1 (D-17): compact v2 history events and a bounded live state.
//! - Every event after R-13d records its request and the before and after values of what
//!   it changed, not a snapshot of the whole state, so history bytes grow linearly.
//! - `checkpoint` with `history` absent or `"all"` still returns v1-shaped snapshots,
//!   rebuilt from the events; `{"since": s}` returns the stored events as they are.
//! - v1 stores (`tests/fixtures/kernel`) open, keep their checkpoint, and continue.
use agent_trust::authority::Authority;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

fn fresh() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    (dir, path)
}

fn fixture(name: &str) -> (tempfile::TempDir, PathBuf, Value) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/kernel")
        .join(name);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("authority.sqlite");
    fs::copy(source.join("authority.sqlite"), &path).unwrap();
    let checkpoint: Value =
        serde_json::from_str(&fs::read_to_string(source.join("checkpoint.json")).unwrap()).unwrap();
    (dir, path, checkpoint)
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

fn full(kernel: &mut Authority) -> Value {
    ok(kernel, json!({"command":"checkpoint"}))
}

fn without(mut value: Value, keys: &[&str]) -> Value {
    for key in keys {
        value.as_object_mut().unwrap().remove(*key);
    }
    value
}

fn raw_events(path: &Path) -> Vec<String> {
    let connection = rusqlite::Connection::open(path).unwrap();
    let mut statement = connection
        .prepare("SELECT event FROM authority_events ORDER BY sequence")
        .unwrap();
    let rows = statement.query_map([], |row| row.get(0)).unwrap();
    rows.map(Result::unwrap).collect()
}

fn history_bytes(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(event)),0) FROM authority_events",
            [],
            |row| row.get(0),
        )
        .unwrap()
}

/// Root and `readers`, admitted; returns the kernel.
fn group(path: &Path, readers: &[&str]) -> Authority {
    let mut kernel = Authority::open(path).unwrap();
    ok(
        &mut kernel,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
    for reader in readers {
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
    kernel
}

/// One E5-style message from root: allocate, release, persist and one consume per reader.
fn message(kernel: &mut Authority, op: &str, readers: &[&str], envelope: &str) {
    ok(
        kernel,
        json!({"command":"allocate", "actor":"root", "op":op}),
    );
    let head = ok(kernel, json!({"command":"checkpoint", "history":"none"}));
    let mut cover = vec![
        json!([{"subject":"root","right":"write","generation":0}]),
        json!([{"subject":"root","right":"read","generation":0}]),
    ];
    for reader in readers {
        cover.push(json!([{"subject":reader,"right":"read","generation":0}]));
    }
    ok(
        kernel,
        json!({"command":"release", "actor":"root", "op":op, "right":"write",
               "policy_revision":head["policy_revision"], "epoch":head["epoch"],
               "branch":head["branch"], "digest":"cafebabe", "cover":cover, "now":10}),
    );
    ok(
        kernel,
        json!({"command":"persist", "op":op, "digest":"cafebabe", "envelope":envelope}),
    );
    for reader in readers {
        ok(
            kernel,
            json!({"command":"consume", "op":op, "recipient":reader, "actor":reader, "now":10}),
        );
    }
}

#[test]
fn events_after_init_are_compact_v2_records_without_snapshots_or_envelopes() {
    let (_dir, path) = fresh();
    let readers = ["alice", "bob"];
    let mut kernel = group(&path, &readers);
    let envelope = "ab".repeat(3000);
    message(&mut kernel, "op-1", &readers, &envelope);
    drop(kernel);
    let events = raw_events(&path);
    assert!(events.len() >= 10);
    for raw in &events {
        let event: Value = serde_json::from_str(raw).unwrap();
        assert_eq!(event["v"], 2, "every event is v2: {raw}");
        assert!(event.get("snapshot").is_none(), "no stored snapshot: {raw}");
        assert!(
            event["request"].is_object(),
            "the request is recorded: {raw}"
        );
        assert!(event["head_hash"].as_str().is_some_and(|h| h.len() == 64));
        assert!(
            !raw.contains(&envelope),
            "the envelope is never stored in the history"
        );
    }
}

#[test]
fn history_bytes_grow_linearly_with_events() {
    let (_dir, path) = fresh();
    let readers = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"];
    let mut kernel = group(&path, &readers);
    let envelope = "ab".repeat(2725);
    let base = history_bytes(&path);
    for i in 0..20 {
        message(&mut kernel, &format!("op-{i}"), &readers, &envelope);
    }
    let first = history_bytes(&path) - base;
    for i in 20..40 {
        message(&mut kernel, &format!("op-{i}"), &readers, &envelope);
    }
    let second = history_bytes(&path) - base - first;
    // Quadratic growth would make the second 20 messages cost about three times the first.
    assert!(
        (second as f64) < 1.15 * first as f64,
        "history bytes: first 20 messages {first}, next 20 {second}"
    );
}

#[test]
fn request_time_does_not_grow_with_history() {
    let (_dir, path) = fresh();
    let readers = ["alice", "bob", "carol"];
    let mut kernel = group(&path, &readers);
    let envelope = "ab".repeat(700);
    let window = |kernel: &mut Authority, from: usize, to: usize| {
        let start = Instant::now();
        for i in from..to {
            message(kernel, &format!("op-{i}"), &readers, &envelope);
        }
        start.elapsed().as_secs_f64() / (to - from) as f64
    };
    window(&mut kernel, 0, 20); // warm-up
    let early = window(&mut kernel, 20, 60);
    window(&mut kernel, 60, 260);
    let late = window(&mut kernel, 260, 300);
    // Quadratic growth would make the late window more than ten times the early one.
    assert!(
        late < 3.0 * early,
        "per message: early {early:.5} s, late {late:.5} s"
    );
}

#[test]
fn head_checkpoint_omits_history_and_invocations() {
    let (_dir, path) = fresh();
    let mut kernel = group(&path, &["alice"]);
    let all = full(&mut kernel);
    let head = ok(
        &mut kernel,
        json!({"command":"checkpoint", "history":"none"}),
    );
    assert_eq!(head, without(all, &["history", "invocations"]));
}

#[test]
fn full_history_rebuilds_snapshots_and_since_returns_stored_events() {
    let (_dir, path) = fresh();
    let readers = ["alice"];
    let mut kernel = group(&path, &readers);
    message(&mut kernel, "op-1", &readers, "0a0b");
    let all = full(&mut kernel);
    let since = ok(
        &mut kernel,
        json!({"command":"checkpoint", "history":{"since":0}}),
    );
    let all_events = all["history"].as_array().unwrap();
    let since_events = since["history"].as_array().unwrap();
    assert_eq!(since_events.len(), all_events.len() - 1);
    for (rebuilt, stored) in all_events[1..].iter().zip(since_events) {
        let mut stripped = rebuilt.clone();
        stripped["event"]
            .as_object_mut()
            .unwrap()
            .remove("snapshot");
        assert_eq!(&stripped, stored);
        assert!(stored["event"].get("snapshot").is_none());
    }
    // The last rebuilt snapshot is the v1 view of the state.
    let last = &all_events.last().unwrap()["event"]["snapshot"];
    assert_eq!(last["revision"], all["revision"]);
    assert_eq!(last["consumed"], json!([{"op":"op-1","recipient":"alice"}]));
    assert_eq!(last["operations"][0]["status"], "persisted");
    assert_eq!(last["roster"], all["roster"]);
}

#[test]
fn v1_stores_open_with_the_same_checkpoint() {
    for name in ["v1-e774ba2", "v1-efc0892"] {
        let (_dir, path, expected) = fixture(name);
        let mut kernel = Authority::open(&path).unwrap();
        let actual = full(&mut kernel);
        // R-13d changes the policy digest format (an incremental invocations commitment).
        assert_eq!(
            without(actual.clone(), &["policy_digest"]),
            without(expected, &["policy_digest"]),
            "{name}"
        );
        drop(kernel);
        let mut reopened = Authority::open(&path).unwrap();
        assert_eq!(full(&mut reopened), actual, "{name} after reopening");
    }
}

#[test]
fn v1_stores_continue_with_v2_events() {
    for name in ["v1-e774ba2", "v1-efc0892"] {
        let (_dir, path, _) = fixture(name);
        let mut kernel = Authority::open(&path).unwrap();
        // The persisted envelope of op-1 stays bound: hex in e774ba2, a digest in efc0892.
        ok(
            &mut kernel,
            json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":"0a0b0c0d"}),
        );
        code(
            kernel.execute(json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":"0a0b0c0e"})),
            "binding_mismatch",
        );
        ok(
            &mut kernel,
            json!({"command":"emit", "op":"op-1", "envelope":"0A0B0C0D"}),
        );
        code(
            kernel.execute(json!({"command":"allocate", "actor":"root", "op":"op-1"})),
            "duplicate_operation",
        );
        ok(
            &mut kernel,
            json!({"command":"allocate", "actor":"root", "op":"op-2"}),
        );
        // A child of the fixture's invocation (root -> carol, write).
        let parent = full(&mut kernel)["invocations"][0]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let child = ok(
            &mut kernel,
            json!({"command":"invoke", "actor":"carol", "executor":"carol", "rights":["write"],
                   "resources":["group-a"], "parent_invocation":parent, "now":10}),
        );
        assert!(child["invocation"].is_string());
        let after = full(&mut kernel);
        let history = after["history"].as_array().unwrap();
        // allocate and invoke; the identical persist records nothing.
        assert_eq!(history.len(), 13 + 2, "{name}: two new events");
        let last = &history.last().unwrap()["event"];
        assert_eq!(last["v"], 2);
        let snapshot = &last["snapshot"];
        assert_eq!(snapshot["invocations"].as_array().unwrap().len(), 2);
        assert_eq!(snapshot["consumed"].as_array().unwrap().len(), 2);
        let ops: Vec<&str> = snapshot["operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["op"].as_str().unwrap())
            .collect();
        assert_eq!(ops, ["op-1", "op-2"], "{name}");
        assert_eq!(after["invocations"], snapshot["invocations"]);
        drop(kernel);
        let mut reopened = Authority::open(&path).unwrap();
        assert_eq!(full(&mut reopened), after, "{name} after reopening");
    }
}

#[test]
fn a_truncated_or_edited_tip_fails_the_next_request() {
    let (_dir, path) = fresh();
    let readers = ["alice"];
    let mut kernel = group(&path, &readers);
    message(&mut kernel, "op-1", &readers, "0a0b");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute(
            "DELETE FROM authority_events WHERE sequence = (SELECT MAX(sequence) FROM authority_events)",
            [],
        )
        .unwrap();
    code(
        kernel.execute(json!({"command":"checkpoint", "history":"none"})),
        "corrupt_history",
    );

    let (_dir2, path2) = fresh();
    let mut kernel = group(&path2, &readers);
    message(&mut kernel, "op-1", &readers, "0a0b");
    let connection = rusqlite::Connection::open(&path2).unwrap();
    connection
        .execute(
            "UPDATE authority_events SET event = REPLACE(event, '\"alice\"', '\"mallory\"')
             WHERE sequence = (SELECT MAX(sequence) FROM authority_events)",
            [],
        )
        .unwrap();
    code(
        kernel.execute(json!({"command":"checkpoint", "history":"none"})),
        "corrupt_history",
    );
}
