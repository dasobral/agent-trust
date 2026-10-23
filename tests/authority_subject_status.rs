//! Phase 4.2 kernel contract tests for C-7 `subject_status` (`docs/adapter-contract.md`
//! §4.10): an adapter-only, read-only command with fields `subject` and `now` that
//! returns `{subject, known, rights, expires_at}`.
//!
//! The kernel is driven directly. The last check routes the command through a
//! policy-only adapter to show that a worker request for it is `unauthorized`.

mod common;

use agent_trust::adapter::Adapter;
use agent_trust::authority::Authority;
use common::{adapter_dir, code, scripted_provider, sign, DalekSigner, FixedClock};
use serde_json::{json, Value};

const GROUP: &str = "g";
const ROOT: &str = "root";
/// Deterministic test-only seed for the root's request key. Not a real key.
const ROOT_SEED: [u8; 32] = [0x37; 32];

fn kernel() -> (tempfile::TempDir, Authority) {
    let dir = adapter_dir();
    let mut kernel = Authority::open(dir.path().join("authority.sqlite")).expect("open kernel");
    kernel
        .execute(json!({"command":"init", "group":GROUP, "root":ROOT}))
        .expect("init");
    (dir, kernel)
}

fn ok(kernel: &mut Authority, request: Value) -> Value {
    kernel
        .execute(request.clone())
        .unwrap_or_else(|err| panic!("{request} should succeed, got {err}"))
}

fn status(kernel: &mut Authority, subject: &str, now: u64) -> Value {
    ok(
        kernel,
        json!({"command":"subject_status", "subject":subject, "now":now}),
    )
}

fn entry(right: &str, generation: u64, active: bool, effective: bool) -> Value {
    json!({"right":right, "generation":generation, "active":active, "effective":effective})
}

/// Delegates from `actor`; a root child gets depth 4, a grandchild depth 2.
fn delegate(kernel: &mut Authority, actor: &str, subject: &str, rights: &[&str], expires_at: u64) {
    let depth = if actor == ROOT { 4 } else { 2 };
    ok(
        kernel,
        json!({
            "command":"delegate", "actor":actor, "subject":subject, "rights":rights,
            "resources":[GROUP], "expires_at":expires_at, "not_before":0, "depth":depth, "now":10
        }),
    );
}

fn grant(kernel: &mut Authority, subject: &str, right: &str, generation: u64) {
    ok(
        kernel,
        json!({
            "command":"grant", "actor":ROOT, "subject":subject, "right":right,
            "generation":generation, "fresh_keys":true, "now":10
        }),
    );
}

fn revoke(kernel: &mut Authority, subject: &str, right: &str) {
    ok(
        kernel,
        json!({"command":"revoke", "actor":ROOT, "subject":subject, "right":right, "now":10}),
    );
}

fn checkpoint(kernel: &mut Authority) -> Value {
    ok(kernel, json!({"command":"checkpoint"}))
}

#[test]
fn subject_status_reports_rights_generations_and_expiry() {
    let (_dir, mut k) = kernel();

    // The root: all four rights at generation 0, effective, and its self-anchored
    // delegation record expires at u64::MAX.
    assert_eq!(
        status(&mut k, ROOT, 10),
        json!({
            "subject":ROOT, "known":true,
            "rights":[
                entry("read", 0, true, true),
                entry("write", 0, true, true),
                entry("admin", 0, true, true),
                entry("admit", 0, true, true),
            ],
            "expires_at":u64::MAX,
        })
    );

    // A delegated child with an expiry; rights in the order read, write, admin, admit
    // regardless of the order in the delegate request.
    delegate(&mut k, ROOT, "alice", &["admit", "write", "read"], 100);
    let alice = |read: Value, write: Value, admit: Value| json!({"subject":"alice", "known":true, "rights":[read, write, admit], "expires_at":100});
    assert_eq!(
        status(&mut k, "alice", 10),
        alice(
            entry("read", 0, true, true),
            entry("write", 0, true, true),
            entry("admit", 0, true, true)
        )
    );
    // The expiry instant itself is still valid (the kernel rejects `now > expires_at`).
    assert_eq!(
        status(&mut k, "alice", 100),
        alice(
            entry("read", 0, true, true),
            entry("write", 0, true, true),
            entry("admit", 0, true, true)
        )
    );

    // A revoked right is inactive and not effective; the others are untouched.
    revoke(&mut k, "alice", "write");
    assert_eq!(
        status(&mut k, "alice", 10),
        alice(
            entry("read", 0, true, true),
            entry("write", 0, false, false),
            entry("admit", 0, true, true)
        )
    );
    // Reauthorization shows the new generation.
    grant(&mut k, "alice", "write", 1);
    assert_eq!(
        status(&mut k, "alice", 10),
        alice(
            entry("read", 0, true, true),
            entry("write", 1, true, true),
            entry("admit", 0, true, true)
        )
    );

    // An expired chain: still active, no longer effective at a later `now`.
    assert_eq!(
        status(&mut k, "alice", 101),
        alice(
            entry("read", 0, true, false),
            entry("write", 1, true, false),
            entry("admit", 0, true, false)
        )
    );
    // A grandchild whose own record is still valid is not effective once its
    // ancestor's grant is revoked (descendant grants close with it).
    delegate(&mut k, "alice", "amy", &["read"], 90);
    assert_eq!(
        status(&mut k, "amy", 10),
        json!({"subject":"amy", "known":true, "rights":[entry("read", 0, true, true)],
               "expires_at":90})
    );
    assert_eq!(
        status(&mut k, "amy", 95),
        json!({"subject":"amy", "known":true, "rights":[entry("read", 0, true, false)],
               "expires_at":90})
    );
    revoke(&mut k, "alice", "read");
    assert_eq!(
        status(&mut k, "amy", 10),
        json!({"subject":"amy", "known":true, "rights":[entry("read", 0, false, false)],
               "expires_at":90})
    );

    // A direct root-anchored grant has no delegation record: expires_at is null.
    grant(&mut k, "dan", "admit", 0);
    grant(&mut k, "dan", "read", 0);
    assert_eq!(
        status(&mut k, "dan", 10),
        json!({
            "subject":"dan", "known":true,
            "rights":[entry("read", 0, true, true), entry("admit", 0, true, true)],
            "expires_at":null,
        })
    );
    assert_eq!(
        status(&mut k, "dan", u64::MAX),
        json!({
            "subject":"dan", "known":true,
            "rights":[entry("read", 0, true, true), entry("admit", 0, true, true)],
            "expires_at":null,
        })
    );

    // Unknown subject.
    assert_eq!(
        status(&mut k, "zed", 10),
        json!({"subject":"zed", "known":false, "rights":[], "expires_at":null})
    );

    // Missing or mistyped fields are malformed.
    for request in [
        json!({"command":"subject_status", "subject":"alice"}),
        json!({"command":"subject_status", "now":10}),
        json!({"command":"subject_status", "subject":"alice", "now":-1}),
        json!({"command":"subject_status", "subject":"alice", "now":"10"}),
        json!({"command":"subject_status", "subject":"", "now":10}),
        json!({"command":"subject_status", "subject":7, "now":10}),
    ] {
        code(k.execute(request), "malformed");
    }

    // Before init the kernel has no state to report.
    let empty = adapter_dir();
    let mut fresh = Authority::open(empty.path().join("authority.sqlite")).expect("open kernel");
    code(
        fresh.execute(json!({"command":"subject_status", "subject":ROOT, "now":10})),
        "uninitialized",
    );
}

#[test]
fn subject_status_is_read_only() {
    let (_dir, mut k) = kernel();
    delegate(&mut k, ROOT, "alice", &["read", "admit"], 100);
    grant(&mut k, "dan", "read", 0);
    revoke(&mut k, "dan", "read");

    let before = checkpoint(&mut k);
    let revision = before["revision"].clone();
    let policy_revision = before["policy_revision"].clone();
    let policy_digest = before["policy_digest"].clone();
    let history_len = before["history"].as_array().expect("history").len();
    assert!(revision.is_u64() && policy_revision.is_u64() && policy_digest.is_string());

    // Positive path: the command answers for known, revoked, expired and unknown subjects.
    assert_eq!(status(&mut k, "alice", 10)["known"], json!(true));
    assert_eq!(
        status(&mut k, "dan", 10)["rights"],
        json!([entry("read", 0, false, false)])
    );
    assert_eq!(
        status(&mut k, "alice", 500)["rights"],
        json!([
            entry("read", 0, true, false),
            entry("admit", 0, true, false)
        ])
    );
    assert_eq!(status(&mut k, "zed", 10)["known"], json!(false));
    for _ in 0..3 {
        status(&mut k, ROOT, 10);
    }
    let _ = k.execute(json!({"command":"subject_status", "subject":"alice"}));

    let after = checkpoint(&mut k);
    assert_eq!(after["revision"], revision, "revision unchanged");
    assert_eq!(
        after["policy_revision"], policy_revision,
        "policy_revision unchanged"
    );
    assert_eq!(
        after["policy_digest"], policy_digest,
        "policy_digest unchanged"
    );
    assert_eq!(
        after["history"].as_array().expect("history").len(),
        history_len,
        "no history event appended"
    );
    assert_eq!(after, before, "the whole checkpoint is unchanged");

    // A mutating command afterwards still works and appends exactly one event.
    grant(&mut k, "dan", "read", 1);
    let later = checkpoint(&mut k);
    assert_eq!(
        later["history"].as_array().expect("history").len(),
        history_len + 1
    );
    assert_eq!(
        status(&mut k, "dan", 10)["rights"],
        json!([entry("read", 1, true, true)])
    );

    // C-7: a worker request for it is `unauthorized`, even for the root, and the
    // kernel stays unchanged.
    let adapter_dir = adapter_dir();
    let (provider, _) = scripted_provider(b"subject-status-worker");
    let root = DalekSigner::from_seed(ROOT_SEED);
    let mut adapter = Adapter::create(
        adapter_dir.path(),
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        FixedClock::new(10),
    )
    .expect("policy-only adapter");
    // Positive path through the same adapter: a routed command is accepted.
    adapter
        .handle(&sign(
            &root,
            GROUP,
            ROOT,
            1,
            &json!({"command":"allocate", "op":"op-1"}),
        ))
        .expect("allocate is routed");
    let kernel_before = adapter.checkpoint().expect("checkpoint");
    let trace_len = adapter.trace().len();
    code(
        adapter.handle(&sign(
            &root,
            GROUP,
            ROOT,
            2,
            &json!({"command":"subject_status", "subject":ROOT}),
        )),
        "unauthorized",
    );
    assert_eq!(adapter.checkpoint().expect("checkpoint"), kernel_before);
    let trace = adapter.trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!("unauthorized"));
    assert_eq!(trace[trace_len]["command"], json!("subject_status"));
}
