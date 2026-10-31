//! R-13c (D-17): the kernel binds a persisted envelope by `SHA-256(envelope bytes)` and
//! keeps neither the bytes nor their hex in its state or history. The adapter store keeps
//! the exact bytes.
use agent_trust::authority::Authority;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

struct Store {
    dir: PathBuf,
    db: PathBuf,
}

impl Store {
    fn new() -> Self {
        let serial = NEXT_STORE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "agent-trust-envelope-digest-{}-{nanos}-{serial}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self {
            db: dir.join("authority.sqlite"),
            dir,
        }
    }

    fn path(&self) -> &Path {
        &self.db
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, String>, expected: &str) {
    let err = match result {
        Err(err) => err,
        Ok(value) => panic!("request should be rejected with {expected}, got {value:?}"),
    };
    assert!(
        err == expected || err.starts_with(&format!("{expected}:")),
        "expected {expected}, got {err}"
    );
}

fn request(authority: &mut Authority, value: Value) -> Value {
    authority
        .execute(value.clone())
        .unwrap_or_else(|err| panic!("{value} should succeed: {err}"))
}

/// A kernel with `op-1` released by root to itself and alice, not yet persisted.
fn released(store: &Store) -> Authority {
    let mut authority = Authority::open(store.path()).unwrap();
    request(
        &mut authority,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
    for right in ["read", "admit"] {
        request(
            &mut authority,
            json!({"command":"grant", "actor":"root", "subject":"alice", "right":right,
                   "generation":0, "fresh_keys":true, "now":10}),
        );
    }
    request(
        &mut authority,
        json!({"command":"admit", "actor":"root", "subject":"alice", "now":10}),
    );
    request(
        &mut authority,
        json!({"command":"allocate", "actor":"root", "op":"op-1"}),
    );
    let head = checkpoint(&mut authority);
    request(
        &mut authority,
        json!({"command":"release", "actor":"root", "op":"op-1", "right":"write",
               "policy_revision":head["policy_revision"], "epoch":head["epoch"],
               "branch":head["branch"], "digest":"cafebabe",
               "cover":[[{"subject":"root","right":"write","generation":0}],
                        [{"subject":"root","right":"read","generation":0}],
                        [{"subject":"alice","right":"read","generation":0}]],
               "now":10}),
    );
    authority
}

fn checkpoint(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}))
}

fn persist(authority: &mut Authority, envelope: &str) -> Result<Value, String> {
    authority.execute(
        json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":envelope}),
    )
}

fn operation(checkpoint: &Value) -> Value {
    let last = checkpoint["history"]
        .as_array()
        .unwrap()
        .last()
        .unwrap()
        .clone();
    last["event"]["snapshot"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["op"] == "op-1")
        .cloned()
        .expect("op-1 in the last snapshot")
}

fn digest_hex(envelope_hex: &str) -> String {
    hex::encode(Sha256::digest(hex::decode(envelope_hex).unwrap()))
}

#[test]
fn persisted_operation_carries_the_envelope_digest_not_the_envelope() {
    let store = Store::new();
    let mut authority = released(&store);
    let envelope = "0a0b0c0d";
    persist(&mut authority, envelope).unwrap();
    let operation = operation(&checkpoint(&mut authority));
    assert_eq!(operation["status"], "persisted");
    assert_eq!(operation["envelope_digest"], json!(digest_hex(envelope)));
    assert!(
        operation.get("envelope").is_none() || operation["envelope"].is_null(),
        "the kernel must not keep the envelope: {operation}"
    );
}

#[test]
fn history_size_does_not_depend_on_the_envelope_size() {
    let store = Store::new();
    let mut authority = released(&store);
    let envelope = "ab".repeat(64 * 1024);
    persist(&mut authority, &envelope).unwrap();
    let connection = rusqlite::Connection::open(store.path()).unwrap();
    let (largest, state): (i64, i64) = connection
        .query_row(
            "SELECT (SELECT MAX(LENGTH(event)) FROM authority_events),
                    (SELECT LENGTH(v) FROM authority_meta WHERE k='state')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert!(largest < 8 * 1024, "largest event is {largest} bytes");
    assert!(state < 8 * 1024, "state row is {state} bytes");
}

#[test]
fn persist_and_emit_bind_the_same_bytes_only() {
    let store = Store::new();
    let mut authority = released(&store);
    persist(&mut authority, "0a0b").unwrap();
    // An identical persist changes nothing; other bytes are a binding mismatch.
    let before = checkpoint(&mut authority);
    persist(&mut authority, "0a0b").unwrap();
    assert_eq!(checkpoint(&mut authority), before);
    code(persist(&mut authority, "0a0c"), "binding_mismatch");
    let emitted = request(
        &mut authority,
        json!({"command":"emit", "op":"op-1", "envelope":"0a0b"}),
    );
    assert_eq!(emitted, json!({"op":"op-1", "envelope":"0a0b"}));
    code(
        authority.execute(json!({"command":"emit", "op":"op-1", "envelope":"0a0c"})),
        "binding_mismatch",
    );
}

#[test]
fn the_digest_covers_bytes_not_hex_spelling() {
    // Upper- and lower-case hex of the same bytes are the same envelope.
    let store = Store::new();
    let mut authority = released(&store);
    persist(&mut authority, "0a0b").unwrap();
    persist(&mut authority, "0A0B").unwrap();
    let emitted = request(
        &mut authority,
        json!({"command":"emit", "op":"op-1", "envelope":"0A0B"}),
    );
    assert_eq!(emitted["op"], "op-1");
}
