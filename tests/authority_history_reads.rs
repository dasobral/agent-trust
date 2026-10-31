//! R-13a (D-17): `checkpoint` reads that do not materialize the whole history.
//! `history` absent or `"all"` keeps today's response; `"none"` returns the head only;
//! `{"since": s}` returns the events after sequence `s`. R-13d: the head also omits the
//! invocations, and `since` returns the stored events without rebuilt snapshots.
use agent_trust::authority::Authority;
use serde_json::{json, Value};
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
            "agent-trust-history-reads-{}-{nanos}-{serial}",
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

/// A kernel with every kind of history event the message flow produces: grants, an
/// admission, then one message allocated, released, persisted and consumed.
fn populated(store: &Store) -> Authority {
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
    let head = full(&mut authority);
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
    request(
        &mut authority,
        json!({"command":"persist", "op":"op-1", "digest":"cafebabe", "envelope":"0a0b"}),
    );
    request(
        &mut authority,
        json!({"command":"consume", "op":"op-1", "recipient":"alice", "actor":"alice", "now":10}),
    );
    authority
}

fn full(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}))
}

fn without_history(mut checkpoint: Value) -> Value {
    checkpoint
        .as_object_mut()
        .expect("checkpoint object")
        .remove("history");
    checkpoint
}

#[test]
fn head_checkpoint_is_the_full_checkpoint_without_history() {
    let store = Store::new();
    let mut authority = populated(&store);
    let full = full(&mut authority);
    assert!(full["history"].as_array().unwrap().len() >= 8);

    let head = request(
        &mut authority,
        json!({"command":"checkpoint", "history":"none"}),
    );
    assert!(
        head.get("history").is_none(),
        "a head checkpoint must not carry the history: {head}"
    );
    assert_eq!(head["history_root"], full["history_root"]);
    // R-13d: the head omits the invocations too; they grow with the history.
    let mut expected = without_history(full);
    expected.as_object_mut().unwrap().remove("invocations");
    assert_eq!(head, expected);
}

#[test]
fn explicit_all_is_the_default_checkpoint() {
    let store = Store::new();
    let mut authority = populated(&store);
    let default = full(&mut authority);
    let all = request(
        &mut authority,
        json!({"command":"checkpoint", "history":"all"}),
    );
    assert_eq!(all, default);
}

#[test]
fn since_returns_exactly_the_events_after_the_sequence() {
    let store = Store::new();
    let mut authority = populated(&store);
    let full = full(&mut authority);
    let history = full["history"].as_array().unwrap().clone();
    let last = history.len() as u64 - 1;

    for since in [0, 3, last - 1, last] {
        let read = request(
            &mut authority,
            json!({"command":"checkpoint", "history":{"since":since}}),
        );
        // R-13d: `since` returns the stored events; only `"all"` rebuilds snapshots.
        let expected: Vec<Value> = history
            .iter()
            .filter(|event| event["sequence"].as_u64().unwrap() > since)
            .cloned()
            .map(|mut event| {
                event["event"].as_object_mut().unwrap().remove("snapshot");
                event
            })
            .collect();
        assert_eq!(read["history"], json!(expected), "since {since}");
        assert_eq!(
            without_history(read),
            without_history(full.clone()),
            "since {since}"
        );
    }
}

#[test]
fn since_past_the_tip_is_refused() {
    // A reader that knows a later sequence than the kernel holds has seen a history
    // that this store no longer has: the read fails instead of answering "nothing new".
    let store = Store::new();
    let mut authority = populated(&store);
    let last = full(&mut authority)["history"].as_array().unwrap().len() as u64 - 1;
    code(
        authority.execute(json!({"command":"checkpoint", "history":{"since":last + 1}})),
        "stale_frontier",
    );
}

#[test]
fn malformed_history_selectors_are_refused() {
    let store = Store::new();
    let mut authority = populated(&store);
    for selector in [
        json!("some"),
        json!(5),
        json!(null),
        json!({"since":-1}),
        json!({"since":"3"}),
        json!({"since":1.5}),
        json!({"since":1, "until":2}),
        json!({}),
    ] {
        code(
            authority.execute(json!({"command":"checkpoint", "history":selector})),
            "malformed",
        );
    }
}

#[test]
fn head_checkpoint_still_detects_a_tampered_state_row() {
    let store = Store::new();
    let mut authority = populated(&store);
    let tamper = rusqlite_like_update(store.path());
    tamper();
    code(
        authority.execute(json!({"command":"checkpoint", "history":"none"})),
        "corrupt_history",
    );
}

/// Rewrites the current state row through a second SQLite connection, as an outside
/// writer would, without touching the hash chain.
fn rusqlite_like_update(path: &Path) -> impl Fn() + '_ {
    move || {
        let connection = rusqlite::Connection::open(path).unwrap();
        let raw: String = connection
            .query_row("SELECT v FROM authority_meta WHERE k='state'", [], |row| {
                row.get(0)
            })
            .unwrap();
        let mut state: Value = serde_json::from_str(&raw).unwrap();
        state["epoch"] = json!(state["epoch"].as_u64().unwrap() + 7);
        connection
            .execute(
                "UPDATE authority_meta SET v=?1 WHERE k='state'",
                [state.to_string()],
            )
            .unwrap();
    }
}
