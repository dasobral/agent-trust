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
            "agent-trust-authority-adversarial-{}-{nanos}-{serial}",
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
    request(
        authority,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
}

fn checkpoint(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}))
}

fn allocate(authority: &mut Authority, op: &str) {
    request(
        authority,
        json!({"command":"allocate", "actor":"root", "op":op}),
    );
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

fn singleton(subject: &str, right: &str, generation: u64) -> Value {
    json!([{"subject":subject, "right":right, "generation":generation}])
}

fn root_cover() -> Vec<Value> {
    vec![singleton("root", "write", 0), singleton("root", "read", 0)]
}

fn release(
    authority: &mut Authority,
    op: &str,
    digest: &str,
    cover: Vec<Value>,
    now: u64,
) -> Result<Value, String> {
    let frontier = checkpoint(authority);
    authority.execute(json!({
        "command":"release", "actor":"root", "op":op, "right":"write",
        "revision":frontier["revision"], "epoch":frontier["epoch"], "branch":frontier["branch"],
        "digest":digest, "cover":cover, "now":now
    }))
}

fn delegate(
    authority: &mut Authority,
    actor: &str,
    subject: &str,
    rights: Value,
    resources: Value,
    expires_at: u64,
    depth: u64,
) -> Result<Value, String> {
    authority.execute(json!({
        "command":"delegate", "actor":actor, "subject":subject, "rights":rights,
        "resources":resources, "expires_at":expires_at, "not_before":0,
        "depth":depth, "now":10
    }))
}

fn admit_alice(authority: &mut Authority) {
    grant(authority, "alice", "read", 0, true, 10);
    grant(authority, "alice", "admit", 0, true, 10);
    request(
        authority,
        json!({"command":"admit", "actor":"root", "subject":"alice", "now":10}),
    );
}

#[test]
fn persisted_operation_consumes_once_across_restarts_and_the_first_consume_progresses() {
    let store = Store::new();
    {
        let mut authority = Authority::open(store.path()).unwrap();
        init(&mut authority);
        allocate(&mut authority, "consume-op");
        release(&mut authority, "consume-op", "c0ffee", root_cover(), 10).unwrap();
        request(
            &mut authority,
            json!({"command":"persist", "op":"consume-op", "digest":"c0ffee", "envelope":"0a0b"}),
        );
    }

    {
        let mut reopened = Authority::open(store.path()).unwrap();
        assert_eq!(
            request(
                &mut reopened,
                json!({"command":"consume", "op":"consume-op", "recipient":"root", "now":10})
            ),
            json!({"op":"consume-op", "recipient":"root"})
        );
    }

    let mut reopened_again = Authority::open(store.path()).unwrap();
    code(
        reopened_again
            .execute(json!({"command":"consume", "op":"consume-op", "recipient":"root", "now":10})),
        "replay",
    );
}

#[test]
fn denied_release_from_an_independent_handle_cannot_poison_a_reserved_operation() {
    let store = Store::new();
    let mut owner = Authority::open(store.path()).unwrap();
    init(&mut owner);
    allocate(&mut owner, "shared-op");
    let before_denial = checkpoint(&mut owner);

    let mut contender = Authority::open(store.path()).unwrap();
    code(
        contender.execute(json!({
            "command":"release", "actor":"mallory", "op":"shared-op", "right":"write",
            "revision":before_denial["revision"], "epoch":before_denial["epoch"],
            "branch":before_denial["branch"], "digest":"bad", "cover":root_cover(), "now":10
        })),
        "unauthorized",
    );
    assert_eq!(checkpoint(&mut contender), before_denial);

    let released = release(&mut owner, "shared-op", "good", root_cover(), 10).unwrap();
    assert_eq!(released["op"], "shared-op");
    assert_eq!(released["digest"], "good");
}

#[test]
fn release_requires_a_preexisting_reservation_and_leaves_no_operation_state_on_failure() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    let before = checkpoint(&mut authority);
    code(
        release(&mut authority, "never-allocated", "aa", root_cover(), 10),
        "invalid_transition",
    );
    assert_eq!(checkpoint(&mut authority), before);
}

#[test]
fn malformed_cover_is_rejected_without_consuming_the_reservation() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "malformed-cover-op");
    let frontier = checkpoint(&mut authority);
    code(
        authority.execute(json!({
            "command":"release", "actor":"root", "op":"malformed-cover-op", "right":"write",
            "revision":frontier["revision"], "epoch":frontier["epoch"], "branch":frontier["branch"],
            "digest":"aa", "cover":"not-a-support-list", "now":10
        })),
        "malformed",
    );
    release(&mut authority, "malformed-cover-op", "aa", root_cover(), 10).unwrap();
}

#[test]
fn delegation_rejects_child_validity_that_outlives_its_parent() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    delegate(
        &mut authority,
        "root",
        "alice",
        json!(["read"]),
        json!(["group-a"]),
        20,
        7,
    )
    .unwrap();
    code(
        delegate(
            &mut authority,
            "alice",
            "bob",
            json!(["read"]),
            json!(["group-a"]),
            21,
            6,
        ),
        "invalid_delegation",
    );
}

#[test]
fn delegation_rejects_a_child_depth_that_is_not_strictly_lower() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    delegate(
        &mut authority,
        "root",
        "alice",
        json!(["read"]),
        json!(["group-a"]),
        u64::MAX,
        7,
    )
    .unwrap();
    code(
        delegate(
            &mut authority,
            "alice",
            "bob",
            json!(["read"]),
            json!(["group-a"]),
            u64::MAX,
            7,
        ),
        "invalid_delegation",
    );
}

#[test]
fn delegation_rejects_resources_outside_the_parent_grant() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    delegate(
        &mut authority,
        "root",
        "alice",
        json!(["read"]),
        json!(["group-a"]),
        u64::MAX,
        7,
    )
    .unwrap();
    code(
        delegate(
            &mut authority,
            "alice",
            "bob",
            json!(["read"]),
            json!(["other-resource"]),
            u64::MAX,
            6,
        ),
        "invalid_delegation",
    );
}

#[test]
fn delegation_rejects_rights_the_parent_does_not_hold() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    delegate(
        &mut authority,
        "root",
        "alice",
        json!(["read"]),
        json!(["group-a"]),
        u64::MAX,
        7,
    )
    .unwrap();
    code(
        delegate(
            &mut authority,
            "alice",
            "bob",
            json!(["write"]),
            json!(["group-a"]),
            u64::MAX,
            6,
        ),
        "invalid_delegation",
    );
}

#[test]
fn stale_reader_generation_cannot_satisfy_a_release_cover_after_reallow() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_alice(&mut authority);
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":11}),
    );
    let fenced = checkpoint(&mut authority);
    request(
        &mut authority,
        json!({
            "command":"repair", "parent_branch":fenced["branch"], "new_branch":"repair-1",
            "epoch":fenced["epoch"].as_u64().unwrap() + 1, "revision":fenced["revision"],
            "removed":["alice"], "update_path":true, "confirmed":true, "durable":true
        }),
    );
    grant(&mut authority, "alice", "read", 1, true, 12);
    request(
        &mut authority,
        json!({"command":"admit", "actor":"root", "subject":"alice", "now":12}),
    );
    allocate(&mut authority, "stale-generation-op");

    code(
        release(
            &mut authority,
            "stale-generation-op",
            "a1",
            vec![
                singleton("root", "write", 0),
                singleton("root", "read", 0),
                singleton("alice", "read", 0),
            ],
            12,
        ),
        "unsound_cover",
    );
}

#[test]
fn repair_cannot_be_replayed_against_its_former_parent_branch() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_alice(&mut authority);
    request(
        &mut authority,
        json!({"command":"revoke", "actor":"root", "subject":"alice", "right":"read", "now":11}),
    );
    let fenced = checkpoint(&mut authority);
    request(
        &mut authority,
        json!({
            "command":"repair", "parent_branch":fenced["branch"], "new_branch":"repair-1",
            "epoch":fenced["epoch"].as_u64().unwrap() + 1, "revision":fenced["revision"],
            "removed":["alice"], "update_path":true, "confirmed":true, "durable":true
        }),
    );
    let after_first_repair = checkpoint(&mut authority);

    code(
        authority.execute(json!({
            "command":"repair", "parent_branch":fenced["branch"], "new_branch":"repair-2",
            "epoch":fenced["epoch"].as_u64().unwrap() + 1, "revision":fenced["revision"],
            "removed":["alice"], "update_path":true, "confirmed":true, "durable":true
        })),
        "invalid_repair",
    );
    assert_eq!(checkpoint(&mut authority), after_first_repair);
}
