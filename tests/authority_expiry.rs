//! R-12 (D-16) kernel contract tests: delegation expiry is a ledger event
//! (`docs/adapter-contract.md` §10 R-12 and C-45, `docs/authority-contract.md` R-12).
//!
//! At the first mutating kernel step that carries a `now` past a delegation's
//! `expires_at`, the kernel records one `expire` event for that delegation before the
//! step. It deactivates the delegation's rights for the subject and its descendants with
//! the cascade and fence rule of `revoke`, and advances `revision` and `policy_revision`.
//! The event commits even when the step itself fails. Read-only commands record nothing.
//!
//! The kernel is driven directly.

mod common;

use agent_trust::authority::Authority;
use common::{adapter_dir, code};
use serde_json::{json, Value};

const GROUP: &str = "g";
const ROOT: &str = "root";
/// Time of every setup step.
const SETUP: u64 = 10;
/// `expires_at` of the short delegations.
const EXPIRES: u64 = 100;
/// `expires_at` of the long delegations.
const LONG: u64 = 1_000_000;

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

fn checkpoint(kernel: &mut Authority) -> Value {
    ok(kernel, json!({"command":"checkpoint"}))
}

fn delegate(kernel: &mut Authority, actor: &str, subject: &str, rights: &[&str], expires_at: u64) {
    let depth = if actor == ROOT { 4 } else { 2 };
    ok(
        kernel,
        json!({
            "command":"delegate", "actor":actor, "subject":subject, "rights":rights,
            "resources":[GROUP], "expires_at":expires_at, "not_before":0, "depth":depth,
            "now":SETUP
        }),
    );
}

/// Admits `subject` into the roster with the next epoch.
fn admit(kernel: &mut Authority, subject: &str) {
    ok(
        kernel,
        json!({"command":"admit", "actor":ROOT, "subject":subject, "now":SETUP}),
    );
}

/// A root grant of `read` at generation 0 to a new subject, at `now`: a step that
/// succeeds whether or not the fence is closed.
fn grant_new(kernel: &mut Authority, subject: &str, now: u64) -> Result<Value, String> {
    kernel.execute(json!({
        "command":"grant", "actor":ROOT, "subject":subject, "right":"read",
        "generation":0, "fresh_keys":true, "now":now
    }))
}

/// The `kind` of every history event, in order.
fn kinds(checkpoint: &Value) -> Vec<String> {
    checkpoint["history"]
        .as_array()
        .expect("history")
        .iter()
        .map(|entry| {
            entry["event"]["kind"]
                .as_str()
                .expect("event kind")
                .to_owned()
        })
        .collect()
}

fn count(checkpoint: &Value, kind: &str) -> usize {
    kinds(checkpoint).iter().filter(|k| *k == kind).count()
}

/// The snapshot of the history event at `index` from the end (0 = last).
fn snapshot_from_end(checkpoint: &Value, index: usize) -> Value {
    let history = checkpoint["history"].as_array().expect("history");
    history[history.len() - 1 - index]["event"]["snapshot"].clone()
}

fn grant_active(checkpoint: &Value, subject: &str, right: &str) -> bool {
    checkpoint["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .find(|g| g["subject"] == json!(subject) && g["right"] == json!(right))
        .unwrap_or_else(|| panic!("{subject} has a {right} grant"))["active"]
        .as_bool()
        .expect("active")
}

fn u64_of(value: &Value, key: &str) -> u64 {
    value[key]
        .as_u64()
        .unwrap_or_else(|| panic!("{key} is a u64"))
}

/// Root, bob (`read`, `write`, `admit`, expires at `EXPIRES`) and carol (the same rights,
/// long-lived), both admitted.
fn roster_with_expiring_reader() -> (tempfile::TempDir, Authority) {
    let (dir, mut kernel) = kernel();
    delegate(
        &mut kernel,
        ROOT,
        "bob",
        &["read", "write", "admit"],
        EXPIRES,
    );
    delegate(
        &mut kernel,
        ROOT,
        "carol",
        &["read", "write", "admit"],
        LONG,
    );
    admit(&mut kernel, "bob");
    admit(&mut kernel, "carol");
    (dir, kernel)
}

#[test]
fn expiry_is_recorded_at_the_first_step_after_expires_at_and_closes_the_fence() {
    let (_dir, mut kernel) = roster_with_expiring_reader();

    // At `expires_at` the delegation is still valid: no event.
    let before = checkpoint(&mut kernel);
    grant_new(&mut kernel, "dave", EXPIRES).expect("grant at expires_at");
    let at = checkpoint(&mut kernel);
    assert_eq!(count(&at, "expire"), 0, "no expiry at expires_at");
    assert!(grant_active(&at, "bob", "read"));
    assert_eq!(at["read_fenced"], json!(false));
    assert_eq!(
        u64_of(&at, "policy_revision"),
        u64_of(&before, "policy_revision") + 1
    );

    // The first step after it records the expiry, then the step itself.
    grant_new(&mut kernel, "erin", EXPIRES + 1).expect("grant after expires_at");
    let after = checkpoint(&mut kernel);
    let kinds_after = kinds(&after);
    assert_eq!(
        kinds_after[kinds_after.len() - 2..],
        ["expire".to_owned(), "grant".to_owned()],
        "one expire event, before the step's own event"
    );
    for right in ["read", "write", "admit"] {
        assert!(!grant_active(&after, "bob", right), "bob {right} closed");
        assert!(
            grant_active(&after, "carol", right),
            "carol {right} untouched"
        );
    }
    assert!(grant_active(&after, "erin", "read"));
    assert_eq!(after["read_fenced"], json!(true), "a roster reader expired");
    assert_eq!(
        u64_of(&after, "revision"),
        u64_of(&at, "revision") + 2,
        "expire and grant each advance revision"
    );
    assert_eq!(
        u64_of(&after, "policy_revision"),
        u64_of(&at, "policy_revision") + 2,
        "expire and grant each advance policy_revision"
    );

    // The expire event itself carries the fence at its own policy revision.
    let expired = snapshot_from_end(&after, 1);
    assert_eq!(expired["read_fenced"], json!(true));
    assert_eq!(
        u64_of(&expired, "fence_revision"),
        u64_of(&expired, "policy_revision")
    );
    assert_eq!(
        u64_of(&after, "fence_revision"),
        u64_of(&expired, "policy_revision")
    );

    // The removal set now includes bob, so a repair can be staged and opened.
    let branch = after["branch"].as_str().expect("branch").to_owned();
    let epoch = u64_of(&after, "epoch");
    ok(
        &mut kernel,
        json!({
            "command":"repair_stage", "parent_branch":branch, "new_branch":"repaired",
            "epoch":epoch + 1, "policy_revision":u64_of(&after, "policy_revision"),
            "removed":["bob"], "update_path":true, "durable":true
        }),
    );
    ok(
        &mut kernel,
        json!({"command":"repair_open", "branch":"repaired", "confirmed":true}),
    );
    let open = checkpoint(&mut kernel);
    assert_eq!(open["read_fenced"], json!(false));
    assert_eq!(open["roster"], json!([ROOT, "carol"]));
}

#[test]
fn expiry_commits_even_when_the_triggering_step_fails() {
    let (_dir, mut kernel) = roster_with_expiring_reader();
    let before = checkpoint(&mut kernel);

    // A release of an operation that was never allocated fails, but only after the
    // expiry has closed the fence: the error is the fence.
    let err = code(
        kernel.execute(json!({
            "command":"release", "actor":ROOT, "op":"never-allocated", "right":"write",
            "policy_revision":u64_of(&before, "policy_revision"),
            "epoch":u64_of(&before, "epoch"), "branch":before["branch"],
            "digest":"00", "cover":[], "now":EXPIRES + 1
        })),
        "read_fenced",
    );
    let after = checkpoint(&mut kernel);
    assert_eq!(
        kinds(&after).last().map(String::as_str),
        Some("expire"),
        "the expiry is recorded although the release failed ({err})"
    );
    assert_eq!(count(&after, "expire"), 1);
    assert_eq!(after["read_fenced"], json!(true));
    assert_eq!(
        u64_of(&after, "fence_revision"),
        u64_of(&after, "policy_revision")
    );
    assert_eq!(
        u64_of(&after, "revision"),
        u64_of(&before, "revision") + 1,
        "only the expire event advanced revision"
    );
    assert!(!grant_active(&after, "bob", "read"));
}

#[test]
fn read_only_commands_never_record_expiry() {
    let (_dir, mut kernel) = roster_with_expiring_reader();
    let before = checkpoint(&mut kernel);
    let late = EXPIRES + 1_000;

    let status = ok(
        &mut kernel,
        json!({"command":"subject_status", "subject":"bob", "now":late}),
    );
    let read = status["rights"]
        .as_array()
        .expect("rights")
        .iter()
        .find(|r| r["right"] == json!("read"))
        .expect("bob read")
        .clone();
    assert_eq!(read["active"], json!(true), "not yet recorded");
    assert_eq!(read["effective"], json!(false), "but not effective");

    let after = checkpoint(&mut kernel);
    assert_eq!(kinds(&after), kinds(&before), "no history event");
    assert_eq!(after["revision"], before["revision"]);
    assert_eq!(after["policy_revision"], before["policy_revision"]);
    assert_eq!(after["read_fenced"], json!(false));
}

#[test]
fn expiry_cascades_to_descendants_and_is_idempotent() {
    let (_dir, mut kernel) = kernel();
    delegate(
        &mut kernel,
        ROOT,
        "bob",
        &["read", "write", "admit"],
        EXPIRES,
    );
    delegate(&mut kernel, "bob", "frank", &["read", "admit"], EXPIRES);
    delegate(&mut kernel, ROOT, "carol", &["read", "admit"], LONG);
    admit(&mut kernel, "carol");
    admit(&mut kernel, "frank");

    grant_new(&mut kernel, "dave", EXPIRES + 1).expect("step after expiry");
    let after = checkpoint(&mut kernel);
    // Bob's expiry cascades to frank, so frank's own delegation changes nothing more.
    assert_eq!(count(&after, "expire"), 1, "one event for bob's delegation");
    assert!(!grant_active(&after, "bob", "read"));
    assert!(!grant_active(&after, "frank", "read"), "cascade to frank");
    assert!(grant_active(&after, "carol", "read"));
    assert!(
        grant_active(&after, ROOT, "admin"),
        "the root never expires"
    );
    assert_eq!(
        after["read_fenced"],
        json!(true),
        "frank is a roster reader"
    );

    // A later step records nothing more.
    grant_new(&mut kernel, "erin", EXPIRES + 50).expect("later step");
    let later = checkpoint(&mut kernel);
    assert_eq!(count(&later, "expire"), 1, "idempotent");
    assert_eq!(kinds(&later).last().map(String::as_str), Some("grant"));
    assert_eq!(
        u64_of(&later, "policy_revision"),
        u64_of(&after, "policy_revision") + 1
    );

    // A re-grant to an expired subject is reactivated by `grant` and closed again by the
    // next step's expiry: the sweep is authoritative (C-45).
    ok(
        &mut kernel,
        json!({
            "command":"grant", "actor":ROOT, "subject":"bob", "right":"write",
            "generation":1, "fresh_keys":true, "now":EXPIRES + 60
        }),
    );
    assert!(grant_active(&checkpoint(&mut kernel), "bob", "write"));
    grant_new(&mut kernel, "gina", EXPIRES + 70).expect("next step");
    let swept = checkpoint(&mut kernel);
    assert!(!grant_active(&swept, "bob", "write"));
    assert_eq!(count(&swept, "expire"), 2);
}

#[test]
fn expiry_of_a_non_roster_subject_does_not_fence() {
    let (_dir, mut kernel) = kernel();
    delegate(&mut kernel, ROOT, "dave", &["write"], EXPIRES);
    let before = checkpoint(&mut kernel);

    grant_new(&mut kernel, "erin", EXPIRES + 1).expect("step after expiry");
    let after = checkpoint(&mut kernel);
    assert_eq!(count(&after, "expire"), 1);
    assert!(!grant_active(&after, "dave", "write"));
    assert_eq!(after["read_fenced"], json!(false));
    assert_eq!(after["fence_revision"], Value::Null);
    assert_eq!(
        u64_of(&after, "policy_revision"),
        u64_of(&before, "policy_revision") + 2
    );
}
