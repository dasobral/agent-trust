//! Requirement corrections for the adapter (approved 2026-10-23).
//!
//! Normative source: `docs/authority-contract.md`, final section
//! "Requirement corrections for the adapter" (R-1, R-2, R-3, R-6, D-3, R-7).
//! Requests without the new fields keep the baseline behavior.

use agent_trust::authority::Authority;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

const MAX_ENVELOPE_BYTES: usize = 1_048_576;

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
            "agent-trust-authority-corrections-{}-{nanos}-{serial}",
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
        Ok(_) => panic!("request should be rejected with {expected}"),
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

fn grant(authority: &mut Authority, subject: &str, right: &str, generation: u64, now: u64) {
    request(
        authority,
        json!({
            "command":"grant", "actor":"root", "subject":subject, "right":right,
            "generation":generation, "fresh_keys":true, "now":now
        }),
    );
}

fn admit(authority: &mut Authority, subject: &str, now: u64) -> Value {
    request(
        authority,
        json!({"command":"admit", "actor":"root", "subject":subject, "now":now}),
    )
}

fn admit_reader(authority: &mut Authority, subject: &str, now: u64) {
    grant(authority, subject, "read", 0, now);
    grant(authority, subject, "admit", 0, now);
    admit(authority, subject, now);
}

fn revoke(authority: &mut Authority, subject: &str, right: &str, now: u64) -> Value {
    request(
        authority,
        json!({"command":"revoke", "actor":"root", "subject":subject, "right":right, "now":now}),
    )
}

fn allocate(authority: &mut Authority, actor: &str, op: &str) {
    request(
        authority,
        json!({"command":"allocate", "actor":actor, "op":op}),
    );
}

fn singleton(subject: &str, right: &str, generation: u64) -> Value {
    json!([{"subject":subject, "right":right, "generation":generation}])
}

fn root_cover() -> Vec<Value> {
    vec![singleton("root", "write", 0), singleton("root", "read", 0)]
}

fn cover_with(readers: &[&str]) -> Vec<Value> {
    let mut cover = root_cover();
    for reader in readers {
        cover.push(singleton(reader, "read", 0));
    }
    cover
}

/// Release request at the current epoch/branch with neither `revision`
/// nor `policy_revision`; callers add the frontier form under test.
fn bare_release(frontier: &Value, op: &str, digest: &str, cover: Vec<Value>, now: u64) -> Value {
    json!({
        "command":"release", "actor":"root", "op":op, "right":"write",
        "epoch":frontier["epoch"], "branch":frontier["branch"],
        "digest":digest, "cover":cover, "now":now
    })
}

/// Baseline form: compares the state `revision` taken from `frontier`.
fn legacy_release(
    authority: &mut Authority,
    frontier: &Value,
    op: &str,
    digest: &str,
    cover: Vec<Value>,
    now: u64,
) -> Result<Value, String> {
    let mut body = bare_release(frontier, op, digest, cover, now);
    body["revision"] = frontier["revision"].clone();
    authority.execute(body)
}

/// R-3 form: supplies `policy_revision` in place of `revision`.
fn policy_release(
    authority: &mut Authority,
    frontier: &Value,
    policy_revision: u64,
    op: &str,
    digest: &str,
    cover: Vec<Value>,
    now: u64,
) -> Result<Value, String> {
    let mut body = bare_release(frontier, op, digest, cover, now);
    body["policy_revision"] = json!(policy_revision);
    authority.execute(body)
}

fn current_release(
    authority: &mut Authority,
    op: &str,
    digest: &str,
    cover: Vec<Value>,
    now: u64,
) -> Result<Value, String> {
    let frontier = checkpoint(authority);
    legacy_release(authority, &frontier, op, digest, cover, now)
}

fn policy_revision(snapshot: &Value) -> u64 {
    snapshot["policy_revision"]
        .as_u64()
        .expect("checkpoint must expose policy_revision as u64")
}

fn policy_digest(snapshot: &Value) -> String {
    let digest = snapshot["policy_digest"]
        .as_str()
        .expect("checkpoint must expose policy_digest as a string")
        .to_owned();
    assert_eq!(digest.len(), 64, "policy_digest must be 64 hex characters");
    assert!(
        digest
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
        "policy_digest must be lowercase hex, got {digest}"
    );
    digest
}

fn last_history_hash(snapshot: &Value) -> Value {
    snapshot["history"]
        .as_array()
        .expect("checkpoint history array")
        .last()
        .expect("history must not be empty")["hash"]
        .clone()
}

fn hex_envelope(bytes: usize, seed: u8) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes * 2);
    for index in 0..bytes {
        let byte = (index as u8).wrapping_mul(31).wrapping_add(seed);
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Drives one request of every kind named by R-3 and reports, after each
/// step, whether the contract says the policy state changes at that step.
fn policy_scenario(authority: &mut Authority, observe: &mut dyn FnMut(&mut Authority, &str, bool)) {
    grant(authority, "alice", "read", 0, 10);
    observe(authority, "grant alice read", true);
    grant(authority, "alice", "admit", 0, 10);
    observe(authority, "grant alice admit", true);
    admit(authority, "alice", 10);
    observe(authority, "admit alice", false);

    request(
        authority,
        json!({
            "command":"delegate", "actor":"root", "subject":"bob",
            "rights":["read"], "resources":["group-a"],
            "expires_at":1000, "not_before":0, "depth":7, "now":10
        }),
    );
    observe(authority, "delegate bob", true);

    let invocation = request(
        authority,
        json!({
            "command":"invoke", "actor":"root", "executor":"alice",
            "rights":["read"], "resources":["group-a"], "now":10
        }),
    );
    assert!(invocation["invocation"].is_string());
    observe(authority, "invoke", true);

    allocate(authority, "root", "policy-op");
    observe(authority, "allocate", false);
    current_release(authority, "policy-op", "aa", cover_with(&["alice"]), 11)
        .expect("authorized release");
    observe(authority, "release", false);
    request(
        authority,
        json!({"command":"persist", "op":"policy-op", "digest":"aa", "envelope":"0a0b"}),
    );
    observe(authority, "persist", false);
    request(
        authority,
        json!({"command":"emit", "op":"policy-op", "envelope":"0a0b"}),
    );
    observe(authority, "emit", false);
    request(
        authority,
        json!({"command":"consume", "op":"policy-op", "recipient":"alice", "now":11}),
    );
    observe(authority, "consume", false);

    allocate(authority, "root", "abandoned-op");
    current_release(authority, "abandoned-op", "bb", cover_with(&["alice"]), 11)
        .expect("authorized release");
    observe(authority, "release before abandon", false);
    request(authority, json!({"command":"abandon", "op":"abandoned-op"}));
    observe(authority, "abandon", false);

    let effective = revoke(authority, "bob", "read", 12);
    assert_eq!(effective["read_fenced"], false);
    observe(authority, "effective revoke", true);
    revoke(authority, "bob", "read", 12);
    observe(authority, "no-op revoke", false);

    code(
        authority.execute(json!({
            "command":"grant", "actor":"mallory", "subject":"carol", "right":"read",
            "generation":0, "fresh_keys":true, "now":12
        })),
        "unauthorized",
    );
    observe(authority, "failed grant", false);
    code(
        authority.execute(json!({
            "command":"grant", "actor":"root", "subject":"alice", "right":"read",
            "generation":0, "fresh_keys":true, "now":12
        })),
        "invalid_generation",
    );
    observe(authority, "failed regrant", false);
}

#[test]
fn init_accepts_genesis_frontier_and_defaults_to_genesis() {
    let custom = Store::new();
    let mut authority = Authority::open(custom.path()).unwrap();
    let response = request(
        &mut authority,
        json!({"command":"init", "group":"group-a", "root":"root", "branch":"mls-genesis-0a1b"}),
    );
    assert_eq!(
        response,
        json!({"revision":0, "epoch":0, "branch":"mls-genesis-0a1b"})
    );
    let state = checkpoint(&mut authority);
    assert_eq!(state["branch"], "mls-genesis-0a1b");
    assert_eq!(state["epoch"], 0);
    assert_eq!(state["revision"], 0);

    let default = Store::new();
    let mut fixture = Authority::open(default.path()).unwrap();
    init(&mut fixture);
    assert_eq!(checkpoint(&mut fixture)["branch"], "genesis");
}

#[test]
fn admit_with_adapter_frontier_requires_exact_parent_and_next_epoch() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    grant(&mut authority, "alice", "read", 0, 10);
    grant(&mut authority, "alice", "admit", 0, 10);

    let admitted = request(
        &mut authority,
        json!({
            "command":"admit", "actor":"root", "subject":"alice", "now":10,
            "parent_branch":"genesis", "new_branch":"mls-epoch-1", "epoch":1
        }),
    );
    assert_eq!(admitted, json!({"epoch":1, "branch":"mls-epoch-1"}));
    let state = checkpoint(&mut authority);
    assert_eq!(state["epoch"], 1);
    assert_eq!(state["branch"], "mls-epoch-1");
    assert_eq!(state["roster"], json!(["root", "alice"]));

    grant(&mut authority, "bob", "read", 0, 10);
    grant(&mut authority, "bob", "admit", 0, 10);
    let before = checkpoint(&mut authority);
    let admit_bob = |fields: Value| {
        let mut body = json!({"command":"admit", "actor":"root", "subject":"bob", "now":10});
        for (key, value) in fields.as_object().unwrap() {
            body[key] = value.clone();
        }
        body
    };

    let rejected = [
        (
            json!({"parent_branch":"genesis", "new_branch":"mls-epoch-2", "epoch":2}),
            "stale_frontier",
        ),
        (
            json!({"parent_branch":"mls-epoch-1", "new_branch":"mls-epoch-2", "epoch":3}),
            "stale_frontier",
        ),
        (
            json!({"parent_branch":"mls-epoch-1", "new_branch":"mls-epoch-2", "epoch":1}),
            "stale_frontier",
        ),
        (
            json!({"parent_branch":"mls-epoch-1", "new_branch":"mls-epoch-1", "epoch":2}),
            "invalid_transition",
        ),
        (json!({"parent_branch":"mls-epoch-1"}), "malformed"),
        (
            json!({"parent_branch":"mls-epoch-1", "new_branch":"mls-epoch-2"}),
            "malformed",
        ),
        (json!({"new_branch":"mls-epoch-2", "epoch":2}), "malformed"),
        (json!({"epoch":2}), "malformed"),
    ];
    for (fields, expected) in rejected {
        code(authority.execute(admit_bob(fields.clone())), expected);
        assert_eq!(
            checkpoint(&mut authority),
            before,
            "rejected admit {fields} must leave state unchanged"
        );
    }

    let admitted = request(
        &mut authority,
        admit_bob(json!({"parent_branch":"mls-epoch-1", "new_branch":"mls-epoch-2", "epoch":2})),
    );
    assert_eq!(admitted, json!({"epoch":2, "branch":"mls-epoch-2"}));
    let state = checkpoint(&mut authority);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["branch"], "mls-epoch-2");
}

#[test]
fn admit_without_adapter_frontier_keeps_fixture_branch() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    grant(&mut authority, "alice", "read", 0, 10);
    grant(&mut authority, "alice", "admit", 0, 10);
    assert_eq!(
        admit(&mut authority, "alice", 10),
        json!({"epoch":1, "branch":"admit:1:alice"})
    );
    grant(&mut authority, "bob", "read", 0, 10);
    grant(&mut authority, "bob", "admit", 0, 10);
    assert_eq!(
        admit(&mut authority, "bob", 10),
        json!({"epoch":2, "branch":"admit:2:bob"})
    );
    let state = checkpoint(&mut authority);
    assert_eq!(state["epoch"], 2);
    assert_eq!(state["branch"], "admit:2:bob");
}

#[test]
fn policy_revision_ignores_allocate_persist_and_consume() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    let genesis = checkpoint(&mut authority);
    assert_eq!(policy_revision(&genesis), 0);
    assert_eq!(genesis.get("fence_revision"), Some(&Value::Null));
    assert_eq!(genesis.get("repair_pending"), Some(&Value::Null));

    let mut previous = 0;
    policy_scenario(&mut authority, &mut |authority, step, changes| {
        let now = policy_revision(&checkpoint(authority));
        let expected = if changes { previous + 1 } else { previous };
        assert_eq!(now, expected, "policy_revision after {step}");
        previous = now;
    });
    assert_eq!(previous, 5);
}

#[test]
fn release_with_policy_revision_survives_unrelated_allocate() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "root", "root-op");
    let frontier = checkpoint(&mut authority);
    let policy = policy_revision(&frontier);

    allocate(&mut authority, "worker", "unrelated-op");
    let current = checkpoint(&mut authority);
    assert_ne!(current["revision"], frontier["revision"]);
    assert_eq!(policy_revision(&current), policy);

    code(
        legacy_release(&mut authority, &frontier, "root-op", "aa", root_cover(), 10),
        "stale_frontier",
    );
    assert_eq!(checkpoint(&mut authority), current);

    let released = policy_release(
        &mut authority,
        &frontier,
        policy,
        "root-op",
        "aa",
        root_cover(),
        10,
    )
    .expect("policy_revision release must not depend on unrelated state revisions");
    assert_eq!(released["op"], "root-op");
    assert_eq!(released["epoch"], current["epoch"]);
    assert_eq!(released["branch"], current["branch"]);
    assert_eq!(released["digest"], "aa");
    assert_eq!(released["policy_revision"], policy);
    assert_eq!(released["revision"], current["revision"]);
}

#[test]
fn release_with_stale_policy_revision_is_stale_frontier() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    allocate(&mut authority, "root", "control-op");
    let control = checkpoint(&mut authority);
    let old_policy = policy_revision(&control);
    policy_release(
        &mut authority,
        &control,
        old_policy,
        "control-op",
        "aa",
        root_cover(),
        10,
    )
    .expect("release with the current policy_revision");

    grant(&mut authority, "alice", "read", 0, 10);
    allocate(&mut authority, "root", "stale-op");
    let current = checkpoint(&mut authority);
    let new_policy = policy_revision(&current);
    assert_eq!(new_policy, old_policy + 1);

    code(
        policy_release(
            &mut authority,
            &current,
            old_policy,
            "stale-op",
            "bb",
            root_cover(),
            11,
        ),
        "stale_frontier",
    );
    assert_eq!(checkpoint(&mut authority), current);

    let mut both = bare_release(&current, "stale-op", "bb", root_cover(), 11);
    both["revision"] = current["revision"].clone();
    both["policy_revision"] = json!(new_policy);
    code(authority.execute(both), "malformed");
    assert_eq!(checkpoint(&mut authority), current);

    let neither = bare_release(&current, "stale-op", "bb", root_cover(), 11);
    code(authority.execute(neither), "malformed");
    assert_eq!(checkpoint(&mut authority), current);

    policy_release(
        &mut authority,
        &current,
        new_policy,
        "stale-op",
        "bb",
        root_cover(),
        11,
    )
    .expect("rejected releases must leave the reservation available");
}

#[test]
fn policy_digest_changes_exactly_when_policy_changes() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    let mut previous = policy_digest(&checkpoint(&mut authority));
    policy_scenario(&mut authority, &mut |authority, step, changes| {
        let now = policy_digest(&checkpoint(authority));
        if changes {
            assert_ne!(now, previous, "policy_digest must change after {step}");
        } else {
            assert_eq!(now, previous, "policy_digest must not change after {step}");
        }
        previous = now;
    });
}

#[test]
fn release_response_exposes_its_history_event_hash() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);

    allocate(&mut authority, "root", "legacy-op");
    let released = current_release(&mut authority, "legacy-op", "aa", root_cover(), 10)
        .expect("legacy release");
    let after = checkpoint(&mut authority);
    assert_eq!(released["policy_revision"], policy_revision(&after));
    assert!(released["event_hash"].is_string());
    assert_eq!(released["event_hash"], last_history_hash(&after));

    allocate(&mut authority, "root", "policy-op");
    let frontier = checkpoint(&mut authority);
    let released = policy_release(
        &mut authority,
        &frontier,
        policy_revision(&frontier),
        "policy-op",
        "bb",
        root_cover(),
        10,
    )
    .expect("policy_revision release");
    let after = checkpoint(&mut authority);
    assert_eq!(released["policy_revision"], policy_revision(&after));
    assert!(released["event_hash"].is_string());
    assert_eq!(released["event_hash"], last_history_hash(&after));
}

#[test]
fn persist_accepts_envelopes_up_to_max_envelope_and_rejects_larger() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    for (op, digest) in [("medium-op", "a1"), ("max-op", "a2"), ("oversize-op", "a3")] {
        allocate(&mut authority, "root", op);
        current_release(&mut authority, op, digest, root_cover(), 10).expect("release");
    }

    let medium = hex_envelope(3000, 1);
    assert_eq!(medium.len(), 6000);
    request(
        &mut authority,
        json!({"command":"persist", "op":"medium-op", "digest":"a1", "envelope":medium}),
    );
    let emitted = request(
        &mut authority,
        json!({"command":"emit", "op":"medium-op", "envelope":medium}),
    );
    assert!(emitted["envelope"].as_str() == Some(medium.as_str()));

    let max = hex_envelope(MAX_ENVELOPE_BYTES, 2);
    assert_eq!(max.len(), 2_097_152);
    request(
        &mut authority,
        json!({"command":"persist", "op":"max-op", "digest":"a2", "envelope":max}),
    );
    let emitted = request(
        &mut authority,
        json!({"command":"emit", "op":"max-op", "envelope":max}),
    );
    assert!(emitted["envelope"].as_str() == Some(max.as_str()));

    let before = checkpoint(&mut authority);
    let oversize = hex_envelope(MAX_ENVELOPE_BYTES + 1, 3);
    code(
        authority.execute(
            json!({"command":"persist", "op":"oversize-op", "digest":"a3", "envelope":oversize}),
        ),
        "malformed",
    );
    code(
        authority.execute(json!({"command":"emit", "op":"max-op", "envelope":oversize})),
        "malformed",
    );
    assert!(
        checkpoint(&mut authority) == before,
        "oversize envelope must leave state unchanged"
    );

    request(
        &mut authority,
        json!({"command":"persist", "op":"oversize-op", "digest":"a3", "envelope":"0a0b"}),
    );
}

#[test]
fn repair_stage_keeps_fence_closed_until_repair_open() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    admit_reader(&mut authority, "alice", 10);
    allocate(&mut authority, "root", "during-repair-op");

    // Cycle 1: positive path.
    let revoked = revoke(&mut authority, "alice", "read", 11);
    assert_eq!(revoked["read_fenced"], true);
    let fenced = checkpoint(&mut authority);
    assert_eq!(fenced["read_fenced"], true);
    let fence = fenced["fence_revision"]
        .as_u64()
        .expect("fence_revision is set when a revoke closes the fence");
    assert_eq!(fence, policy_revision(&fenced));
    assert_eq!(fenced["repair_pending"], Value::Null);
    let next_epoch = fenced["epoch"].as_u64().unwrap() + 1;

    let staged = request(
        &mut authority,
        json!({
            "command":"repair_stage", "parent_branch":fenced["branch"],
            "new_branch":"repair-1", "epoch":next_epoch,
            "policy_revision":policy_revision(&fenced), "removed":["alice"],
            "update_path":true, "durable":true
        }),
    );
    assert_eq!(
        staged,
        json!({"epoch":next_epoch, "branch":"repair-1", "policy_revision":policy_revision(&fenced)})
    );
    let pending = checkpoint(&mut authority);
    assert_eq!(pending["epoch"], next_epoch);
    assert_eq!(pending["branch"], "repair-1");
    assert_eq!(pending["roster"], json!(["root"]));
    assert_eq!(pending["read_fenced"], true);
    assert_eq!(pending["repair_pending"], "repair-1");
    assert_eq!(pending["fence_revision"], fence);
    assert_eq!(policy_revision(&pending), policy_revision(&fenced));

    code(
        current_release(&mut authority, "during-repair-op", "aa", root_cover(), 11),
        "read_fenced",
    );
    assert_eq!(checkpoint(&mut authority), pending);

    let opened = request(
        &mut authority,
        json!({"command":"repair_open", "branch":"repair-1", "confirmed":true}),
    );
    assert_eq!(opened, json!({"epoch":next_epoch, "branch":"repair-1"}));
    let open = checkpoint(&mut authority);
    assert_eq!(open["read_fenced"], false);
    assert_eq!(open["repair_pending"], Value::Null);
    assert_eq!(open["fence_revision"], Value::Null);
    current_release(&mut authority, "during-repair-op", "aa", root_cover(), 11)
        .expect("release after repair_open");

    // Cycle 2: negatives on a fenced state where the positive path succeeds.
    admit_reader(&mut authority, "bob", 12);
    allocate(&mut authority, "root", "second-repair-op");
    revoke(&mut authority, "bob", "read", 13);
    let fenced = checkpoint(&mut authority);
    let fence = fenced["fence_revision"]
        .as_u64()
        .expect("fence_revision is set when a revoke closes the fence");
    assert_eq!(fence, policy_revision(&fenced));
    let parent = fenced["branch"].clone();
    let next_epoch = fenced["epoch"].as_u64().unwrap() + 1;
    let stage = |policy: u64| {
        json!({
            "command":"repair_stage", "parent_branch":parent,
            "new_branch":"repair-2", "epoch":next_epoch,
            "policy_revision":policy, "removed":["bob"],
            "update_path":true, "durable":true
        })
    };

    code(
        authority.execute(json!({"command":"repair_open", "branch":parent, "confirmed":true})),
        "invalid_repair",
    );
    assert_eq!(checkpoint(&mut authority), fenced);
    code(authority.execute(stage(fence - 1)), "invalid_repair");
    assert_eq!(checkpoint(&mut authority), fenced);
    code(authority.execute(stage(fence + 1)), "invalid_repair");
    assert_eq!(checkpoint(&mut authority), fenced);

    grant(&mut authority, "carol", "read", 0, 13);
    let fenced = checkpoint(&mut authority);
    let current_policy = policy_revision(&fenced);
    assert_eq!(current_policy, fence + 1);
    code(authority.execute(stage(fence)), "invalid_repair");
    assert_eq!(checkpoint(&mut authority), fenced);

    let staged = request(&mut authority, stage(current_policy));
    assert_eq!(
        staged,
        json!({"epoch":next_epoch, "branch":"repair-2", "policy_revision":current_policy})
    );
    let pending = checkpoint(&mut authority);
    assert_eq!(pending["repair_pending"], "repair-2");

    code(
        authority.execute(json!({"command":"repair_open", "branch":parent, "confirmed":true})),
        "invalid_repair",
    );
    assert_eq!(checkpoint(&mut authority), pending);
    code(
        authority.execute(json!({"command":"repair_open", "branch":"repair-2", "confirmed":false})),
        "invalid_repair",
    );
    assert_eq!(checkpoint(&mut authority), pending);

    request(
        &mut authority,
        json!({"command":"repair_open", "branch":"repair-2", "confirmed":true}),
    );
    let open = checkpoint(&mut authority);
    assert_eq!(open["read_fenced"], false);
    assert_eq!(open["repair_pending"], Value::Null);
    assert_eq!(open["fence_revision"], Value::Null);
    current_release(&mut authority, "second-repair-op", "bb", root_cover(), 13)
        .expect("release after second repair_open");
}
