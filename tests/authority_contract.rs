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
            "agent-trust-authority-contract-{}-{nanos}-{serial}",
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

fn code<T>(result: Result<T, String>, expected: &str) {
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("request should be rejected"),
    };
    assert!(
        err == expected || err.starts_with(&format!("{expected}:")),
        "expected {expected}, got {err}"
    );
}

fn request(authority: &mut Authority, value: Value) -> Value {
    authority
        .execute(value)
        .expect("contract request should succeed")
}

fn init(authority: &mut Authority) {
    let response = request(
        authority,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
    assert_eq!(
        response,
        json!({"revision":0, "epoch":0, "branch":"genesis"})
    );
}

fn checkpoint(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}))
}

fn grant(
    authority: &mut Authority,
    subject: &str,
    right: &str,
    generation: u64,
    fresh_keys: bool,
    now: u64,
) {
    request(
        authority,
        json!({
            "command":"grant", "actor":"root", "subject":subject, "right":right,
            "generation":generation, "fresh_keys":fresh_keys, "now":now
        }),
    );
}

fn admit(authority: &mut Authority, subject: &str, now: u64) {
    request(
        authority,
        json!({"command":"admit", "actor":"root", "subject":subject, "now":now}),
    );
}

fn support(subject: &str, right: &str, generation: u64) -> Value {
    json!({"subject":subject, "right":right, "generation":generation})
}

fn singleton_support(subject: &str, right: &str, generation: u64) -> Value {
    json!([support(subject, right, generation)])
}

fn release(
    authority: &mut Authority,
    actor: &str,
    op: &str,
    digest: &str,
    cover: Vec<Value>,
    now: u64,
) -> Result<Value, String> {
    let current = checkpoint(authority);
    authority.execute(json!({
        "command":"release", "actor":actor, "op":op, "right":"write",
        "revision":current["revision"], "epoch":current["epoch"], "branch":current["branch"],
        "digest":digest, "cover":cover, "now":now
    }))
}

fn allocate(authority: &mut Authority, op: &str) {
    request(
        authority,
        json!({"command":"allocate", "actor":"root", "op":op}),
    );
}

fn active(snapshot: &Value, subject: &str, right: &str) -> bool {
    snapshot["grants"]
        .as_array()
        .unwrap()
        .iter()
        .any(|g| g["subject"] == subject && g["right"] == right && g["active"] == true)
}

fn root_cover() -> Vec<Value> {
    vec![
        singleton_support("root", "write", 0),
        singleton_support("root", "read", 0),
    ]
}

fn admit_alice(authority: &mut Authority) {
    grant(authority, "alice", "read", 0, true, 10);
    grant(authority, "alice", "admit", 0, true, 10);
    admit(authority, "alice", 10);
}

#[test]
fn initialization_has_the_documented_genesis_state_and_survives_restart() {
    let store = Store::new();
    let mut first = Authority::open(store.path()).unwrap();
    init(&mut first);
    let before = checkpoint(&mut first);
    drop(first);

    let mut reopened = Authority::open(store.path()).unwrap();
    let after = checkpoint(&mut reopened);
    assert_eq!(after["group"], "group-a");
    assert_eq!(after["revision"], 0);
    assert_eq!(after["epoch"], 0);
    assert_eq!(after["branch"], "genesis");
    assert_eq!(after["roster"], json!(["root"]));
    assert_eq!(after["read_fenced"], false);
    assert!(active(&after, "root", "read"));
    assert!(active(&after, "root", "write"));
    assert!(active(&after, "root", "admin"));
    assert!(active(&after, "root", "admit"));
    assert_eq!(after, before);
    code(
        reopened.execute(json!({"command":"init", "group":"group-a", "root":"root"})),
        "already_initialized",
    );
}

#[test]
fn independently_opened_handles_reload_committed_state_before_each_mutation() {
    let store = Store::new();
    let mut first = Authority::open(store.path()).unwrap();
    init(&mut first);
    let mut stale = Authority::open(store.path()).unwrap();

    grant(&mut first, "alice", "read", 0, true, 10);
    grant(&mut stale, "bob", "read", 0, true, 10);

    let mut verifier = Authority::open(store.path()).unwrap();
    let state = checkpoint(&mut verifier);
    assert_eq!(state["revision"], 2);
    assert!(active(&state, "alice", "read"));
    assert!(active(&state, "bob", "read"));
}

#[test]
fn denied_release_is_rejected_before_fence_state_and_fence_blocks_authorized_release() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_alice(&mut authority);
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":11}),
    );

    code(
        release(
            &mut authority,
            "mallory",
            "bad-release",
            "aa",
            root_cover(),
            11,
        ),
        "unauthorized",
    );
    code(
        release(
            &mut authority,
            "root",
            "fenced-release",
            "aa",
            root_cover(),
            11,
        ),
        "read_fenced",
    );
}

#[test]
fn revoking_non_roster_read_does_not_fence_the_group() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    grant(&mut authority, "alice", "read", 0, true, 10);

    let response = request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":11}),
    );
    assert_eq!(response["read_fenced"], false);

    allocate(&mut authority, "non-roster-revocation-op");
    release(
        &mut authority,
        "root",
        "non-roster-revocation-op",
        "aa",
        root_cover(),
        11,
    )
    .expect("revoking a non-roster grant must not fence current readers");
}

#[test]
fn release_rejects_administrative_rights() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "wrong-right-op");

    let current = checkpoint(&mut authority);
    code(
        authority.execute(json!({
            "command":"release", "actor":"root", "op":"wrong-right-op", "right":"admin",
            "revision":current["revision"], "epoch":current["epoch"], "branch":current["branch"],
            "digest":"aa", "cover":root_cover(), "now":10
        })),
        "malformed",
    );

    release(
        &mut authority,
        "root",
        "wrong-right-op",
        "aa",
        root_cover(),
        10,
    )
    .expect("a rejected non-write release must leave the reservation available");
}

#[test]
fn content_release_requires_an_exact_sound_cover_for_every_roster_reader() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_alice(&mut authority);
    allocate(&mut authority, "cover-op");

    code(
        release(&mut authority, "root", "cover-op", "a1", root_cover(), 11),
        "unsound_cover",
    );
    code(
        release(
            &mut authority,
            "root",
            "cover-op",
            "a1",
            vec![
                json!([support("root", "write", 0), support("root", "read", 0)]),
                singleton_support("alice", "read", 0),
            ],
            11,
        ),
        "unsound_cover",
    );
    let accepted = release(
        &mut authority,
        "root",
        "cover-op",
        "a1",
        vec![
            singleton_support("root", "write", 0),
            singleton_support("root", "read", 0),
            singleton_support("alice", "read", 0),
        ],
        11,
    )
    .unwrap();
    assert_eq!(accepted["op"], "cover-op");
    assert_eq!(accepted["digest"], "a1");
}

#[test]
fn revoking_one_non_read_right_leaves_other_rights_and_the_read_fence_unchanged() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    grant(&mut authority, "alice", "read", 0, true, 10);
    grant(&mut authority, "alice", "write", 0, true, 10);
    let response = request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"write", "now":11}),
    );
    assert_eq!(response["read_fenced"], false);
    let state = checkpoint(&mut authority);
    assert!(active(&state, "alice", "read"));
    assert!(!active(&state, "alice", "write"));
}

#[test]
fn attenuated_delegations_expire_and_revoke_cascades_only_the_affected_right() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    request(
        &mut authority,
        json!({
            "command":"delegate", "actor":"root", "subject":"alice",
            "rights":["admin", "read", "admit"], "resources":["group-a"],
            "expires_at":20, "not_before":0, "depth":7, "now":10
        }),
    );
    request(
        &mut authority,
        json!({
            "command":"delegate", "actor":"alice", "subject":"bob",
            "rights":["read", "admit"], "resources":["group-a"],
            "expires_at":15, "not_before":0, "depth":6, "now":10
        }),
    );
    admit(&mut authority, "bob", 10);

    allocate(&mut authority, "expired-op");
    code(
        release(
            &mut authority,
            "root",
            "expired-op",
            "a2",
            vec![
                singleton_support("root", "write", 0),
                singleton_support("root", "read", 0),
                singleton_support("bob", "read", 0),
            ],
            16,
        ),
        "unauthorized",
    );
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":16}),
    );
    let state = checkpoint(&mut authority);
    assert!(!active(&state, "alice", "read"));
    assert!(!active(&state, "bob", "read"));
    assert!(active(&state, "alice", "admin"));
}

#[test]
fn reallow_after_denial_requires_fresh_keys_and_strictly_increments_generation() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    grant(&mut authority, "alice", "write", 0, true, 10);
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"write", "now":11}),
    );
    code(
        authority.execute(json!({
            "command":"grant", "actor":"root", "subject":"alice", "right":"write",
            "generation":1, "fresh_keys":false, "now":12
        })),
        "invalid_generation",
    );
    grant(&mut authority, "alice", "write", 1, true, 12);
    let state = checkpoint(&mut authority);
    let grant = state["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["subject"] == "alice" && g["right"] == "write")
        .unwrap();
    assert_eq!(grant["generation"], 1);
    assert_eq!(grant["active"], true);
}

#[test]
fn persisted_envelopes_bind_digest_and_emit_requires_the_exact_bytes() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "envelope-op");
    release(
        &mut authority,
        "root",
        "envelope-op",
        "cafebabe",
        root_cover(),
        10,
    )
    .unwrap();
    request(
        &mut authority,
        json!({"command":"persist", "op":"envelope-op", "digest":"cafebabe", "envelope":"0a0b"}),
    );
    request(
        &mut authority,
        json!({"command":"persist", "op":"envelope-op", "digest":"cafebabe", "envelope":"0a0b"}),
    );
    code(authority.execute(json!({"command":"persist", "op":"envelope-op", "digest":"cafebabe", "envelope":"0a0c"})), "binding_mismatch");
    let emitted = request(
        &mut authority,
        json!({"command":"emit", "op":"envelope-op", "envelope":"0a0b"}),
    );
    assert_eq!(emitted["envelope"], "0a0b");
    code(
        authority.execute(json!({"command":"emit", "op":"envelope-op", "envelope":"0a0c"})),
        "binding_mismatch",
    );
}

#[test]
fn abandoned_released_operations_are_idempotently_closed_and_never_reusable() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "abandoned-op");
    release(
        &mut authority,
        "root",
        "abandoned-op",
        "deadbeef",
        root_cover(),
        10,
    )
    .unwrap();
    request(
        &mut authority,
        json!({"command":"abandon", "op":"abandoned-op"}),
    );
    request(
        &mut authority,
        json!({"command":"abandon", "op":"abandoned-op"}),
    );
    code(
        authority.execute(json!({"command":"allocate", "actor":"root", "op":"abandoned-op"})),
        "duplicate_operation",
    );
    code(
        authority.execute(
            json!({"command":"persist", "op":"abandoned-op", "digest":"deadbeef", "envelope":"00"}),
        ),
        "invalid_transition",
    );
}

#[test]
fn repair_requires_the_exact_fenced_parent_frontier_and_full_removed_reader_set() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_alice(&mut authority);
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":11}),
    );
    let fenced = checkpoint(&mut authority);
    assert_eq!(fenced["read_fenced"], true);

    code(
        authority.execute(json!({
            "command":"repair", "parent_branch":fenced["branch"], "new_branch":"repair-1",
            "epoch":fenced["epoch"].as_u64().unwrap() + 1, "revision":fenced["revision"],
            "removed":[], "update_path":true, "confirmed":true, "durable":true
        })),
        "invalid_repair",
    );
    let repaired = request(
        &mut authority,
        json!({
            "command":"repair", "parent_branch":fenced["branch"], "new_branch":"repair-1",
            "epoch":fenced["epoch"].as_u64().unwrap() + 1, "revision":fenced["revision"],
            "removed":["alice"], "update_path":true, "confirmed":true, "durable":true
        }),
    );
    assert_eq!(repaired["branch"], "repair-1");
    let state = checkpoint(&mut authority);
    assert_eq!(state["read_fenced"], false);
    assert_eq!(state["roster"], json!(["root"]));
}

#[test]
fn malformed_uninitialized_and_wrongly_typed_requests_are_rejected_without_mutation() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    code(
        authority.execute(json!({"command":"checkpoint"})),
        "uninitialized",
    );
    code(
        authority.execute(json!({"command":"init", "group":17, "root":"root"})),
        "malformed",
    );
    init(&mut authority);
    let before = checkpoint(&mut authority);
    code(authority.execute(json!({"command":"grant", "actor":"root", "subject":"alice", "right":"read", "generation":-1, "fresh_keys":true, "now":0})), "malformed");
    code(authority.execute(json!({"command":"grant", "actor":"root", "subject":"alice", "right":"read", "generation":0.5, "fresh_keys":true, "now":0})), "malformed");
    code(authority.execute(json!({"command":"grant", "actor":"root", "subject":"alice", "right":"read", "generation":true, "fresh_keys":true, "now":0})), "malformed");
    code(authority.execute(json!({"command":"unknown"})), "malformed");
    assert_eq!(checkpoint(&mut authority), before);
}

#[test]
fn checkpoint_history_is_ordered_hash_chained_and_disk_tampering_is_detected() {
    let store = Store::new();
    {
        let mut authority = Authority::open(store.path()).unwrap();
        init(&mut authority);
        grant(&mut authority, "alice", "read", 0, true, 10);
        let history = checkpoint(&mut authority)["history"]
            .as_array()
            .unwrap()
            .clone();
        assert!(history.len() >= 2);
        for (index, record) in history.iter().enumerate() {
            assert_eq!(record["sequence"], index as u64);
            assert_eq!(record["hash"].as_str().unwrap().len(), 64);
            if index > 0 {
                assert_eq!(record["previous"], history[index - 1]["hash"]);
            }
        }
    }
    let mut bytes = fs::read(store.path()).expect("authority state must be durable on disk");
    let location = bytes
        .windows(4)
        .position(|window| window == b"init")
        .expect("event records must retain their event kind");
    bytes[location] = b'x';
    fs::write(store.path(), bytes).unwrap();
    code(Authority::open(store.path()), "corrupt_history");
}
