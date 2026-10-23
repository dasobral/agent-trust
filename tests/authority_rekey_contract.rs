//! Phase 4.4b kernel contract tests for R-10 `rekey` (approved 2026-10-23, D-9).
//!
//! Normative source: `docs/authority-contract.md`, final section, "R-10 rekey", plus the
//! baseline `grant` rules, R-1 frontier binding, R-3 policy revision and D-3
//! `repair_stage`/`repair_open`. These tests call the kernel directly, as the trusted
//! adapter does; `rekey` is never exposed to workers (that is checked in
//! `tests/adapter_rekey.rs`).
//!
//! Every rejected request is checked to leave the complete checkpoint unchanged.

use agent_trust::authority::Authority;
use serde_json::{json, Value};

const GROUP: &str = "g";
const NOW: u64 = 100;

fn code<T>(result: Result<T, String>, expected: &str) -> String {
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("request should be rejected with {expected}"),
    };
    assert!(
        err == expected || err.starts_with(&format!("{expected}:")),
        "expected {expected}, got {err}"
    );
    err
}

struct Kernel {
    /// Keeps the store directory alive.
    _dir: tempfile::TempDir,
    authority: Authority,
}

impl Kernel {
    /// `init` with the genesis branch `b0`.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary kernel directory");
        let mut authority =
            Authority::open(dir.path().join("authority.sqlite")).expect("open kernel");
        let response = authority
            .execute(json!({"command":"init", "group":GROUP, "root":"root", "branch":"b0"}))
            .expect("init");
        assert_eq!(response, json!({"revision":0, "epoch":0, "branch":"b0"}));
        Self {
            _dir: dir,
            authority,
        }
    }

    fn ok(&mut self, request: Value) -> Value {
        self.authority
            .execute(request.clone())
            .unwrap_or_else(|err| panic!("{request} should succeed, got {err}"))
    }

    fn checkpoint(&mut self) -> Value {
        self.ok(json!({"command":"checkpoint"}))
    }

    /// Asserts the code and a completely unchanged checkpoint.
    fn rejected(&mut self, request: Value, expected: &str) -> String {
        let before = self.checkpoint();
        let err = code(self.authority.execute(request.clone()), expected);
        assert_eq!(
            self.checkpoint(),
            before,
            "rejected {request} ({err}) must leave the kernel unchanged"
        );
        err
    }

    fn frontier(&mut self) -> (u64, String) {
        let checkpoint = self.checkpoint();
        (
            checkpoint["epoch"].as_u64().expect("epoch"),
            checkpoint["branch"].as_str().expect("branch").to_owned(),
        )
    }

    fn policy_revision(&mut self) -> u64 {
        self.checkpoint()["policy_revision"]
            .as_u64()
            .expect("policy_revision")
    }

    fn grant(&mut self, actor: &str, subject: &str, right: &str, generation: u64) {
        self.ok(json!({
            "command":"grant", "actor":actor, "subject":subject, "right":right,
            "generation":generation, "fresh_keys":true, "now":NOW
        }));
    }

    fn revoke(&mut self, subject: &str, right: &str) -> Value {
        self.ok(json!({
            "command":"revoke", "actor":"root", "subject":subject, "right":right, "now":NOW
        }))
    }

    /// Direct root grants of read, write and admit at generation 0, then an R-1 admit
    /// onto `new_branch`.
    fn admit_member(&mut self, subject: &str, new_branch: &str) {
        for right in ["read", "write", "admit"] {
            self.grant("root", subject, right, 0);
        }
        let (epoch, branch) = self.frontier();
        let response = self.ok(json!({
            "command":"admit", "actor":"root", "subject":subject, "now":NOW,
            "parent_branch":branch, "new_branch":new_branch, "epoch":epoch + 1
        }));
        assert_eq!(response, json!({"epoch":epoch + 1, "branch":new_branch}));
    }

    /// The grant record of `subject` for `right`.
    fn record(&mut self, subject: &str, right: &str) -> Option<Value> {
        let checkpoint = self.checkpoint();
        checkpoint["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .find(|g| g["subject"] == json!(subject) && g["right"] == json!(right))
            .cloned()
    }

    /// C-7 `subject_status` entry of `subject` for `right`.
    fn status(&mut self, subject: &str, right: &str) -> Value {
        let response = self.ok(json!({"command":"subject_status", "subject":subject, "now":NOW}));
        response["rights"]
            .as_array()
            .expect("rights")
            .iter()
            .find(|entry| entry["right"] == json!(right))
            .cloned()
            .unwrap_or_else(|| panic!("{subject} has a {right} record"))
    }
}

#[allow(clippy::too_many_arguments)]
fn rekey(
    actor: &str,
    subject: &str,
    right: &str,
    generation: u64,
    parent_branch: &str,
    new_branch: &str,
    epoch: u64,
) -> Value {
    json!({
        "command":"rekey", "actor":actor, "subject":subject, "right":right,
        "generation":generation, "parent_branch":parent_branch, "new_branch":new_branch,
        "epoch":epoch, "now":NOW
    })
}

#[test]
fn rekey_applies_grant_and_advances_frontier_atomically() {
    let mut k = Kernel::new();
    k.admit_member("bob", "b1");
    let response = k.revoke("bob", "write");
    assert_eq!(response["read_fenced"], json!(false));
    assert_eq!(
        k.record("bob", "write").expect("record")["active"],
        json!(false)
    );

    let before = k.checkpoint();
    let policy_revision = before["policy_revision"].as_u64().expect("policy_revision");
    assert_eq!(k.frontier(), (1, "b1".to_owned()));

    let response = k.ok(rekey("root", "bob", "write", 1, "b1", "b2", 2));
    assert_eq!(
        response,
        json!({"epoch":2, "branch":"b2", "policy_revision":policy_revision + 1})
    );
    let after = k.checkpoint();
    assert_eq!(
        k.record("bob", "write"),
        Some(json!({"subject":"bob", "right":"write", "generation":1, "active":true}))
    );
    assert_eq!(after["epoch"], json!(2));
    assert_eq!(after["branch"], json!("b2"));
    assert_eq!(after["policy_revision"], json!(policy_revision + 1));
    assert_ne!(after["policy_digest"], before["policy_digest"]);
    assert_eq!(after["roster"], before["roster"], "rekey changes no roster");
    assert_eq!(after["read_fenced"], json!(false));
    assert_eq!(after["fence_revision"], Value::Null);
    assert_eq!(after["repair_pending"], Value::Null);
    let status = k.status("bob", "write");
    assert_eq!(status["generation"], json!(1));
    assert_eq!(status["effective"], json!(true));
    // Other grants are untouched.
    assert_eq!(k.status("bob", "read")["generation"], json!(0));
    assert_eq!(k.status("bob", "read")["active"], json!(true));

    // A new right for a current member starts at generation 0.
    assert!(k.record("bob", "admin").is_none());
    let response = k.ok(rekey("root", "bob", "admin", 0, "b2", "b3", 3));
    assert_eq!(
        response,
        json!({"epoch":3, "branch":"b3", "policy_revision":policy_revision + 2})
    );
    assert_eq!(
        k.record("bob", "admin"),
        Some(json!({"subject":"bob", "right":"admin", "generation":0, "active":true}))
    );
    assert_eq!(k.status("bob", "admin")["effective"], json!(true));
    // The new admin right works: bob now grants on his own authority.
    k.grant("bob", "carol", "read", 0);
    assert_eq!(
        k.record("carol", "read").expect("record")["active"],
        json!(true)
    );
}

#[test]
fn rekey_rejects_invalid_requests_without_mutation() {
    let mut k = Kernel::new();
    k.admit_member("bob", "b1");
    k.admit_member("carol", "b2");
    // dave holds grants but is not in the roster.
    k.grant("root", "dave", "read", 0);
    k.grant("root", "dave", "admit", 0);
    assert_eq!(k.checkpoint()["roster"], json!(["root", "bob", "carol"]));

    // Positive first: re-authorize bob's revoked write.
    k.revoke("bob", "write");
    k.ok(rekey("root", "bob", "write", 1, "b2", "b3", 3));
    assert_eq!(k.frontier(), (3, "b3".to_owned()));

    // The base request below is valid: a new admin right for bob at the frontier.
    let base = || rekey("root", "bob", "admin", 0, "b3", "b4", 4);

    // Stale parent or wrong epoch.
    let mut request = base();
    request["parent_branch"] = json!("b2");
    k.rejected(request, "stale_frontier");
    let mut request = base();
    request["parent_branch"] = json!("other");
    k.rejected(request, "stale_frontier");
    let mut request = base();
    request["epoch"] = json!(3);
    k.rejected(request, "stale_frontier");
    let mut request = base();
    request["epoch"] = json!(5);
    k.rejected(request, "stale_frontier");

    // The successor branch must differ from the parent.
    let mut request = base();
    request["new_branch"] = json!("b3");
    k.rejected(request, "invalid_transition");

    // The subject must be a roster member.
    let mut request = base();
    request["subject"] = json!("dave");
    k.rejected(request, "invalid_transition");

    // Read is never re-authorized by rekey; it needs re-admission.
    let mut request = base();
    request["right"] = json!("read");
    request["generation"] = json!(1);
    k.rejected(request, "malformed");
    let mut request = base();
    request["right"] = json!("bogus");
    k.rejected(request, "malformed");

    // Missing or mistyped fields.
    for field in [
        "actor",
        "subject",
        "right",
        "generation",
        "parent_branch",
        "new_branch",
        "epoch",
        "now",
    ] {
        let mut request = base();
        request
            .as_object_mut()
            .expect("request object")
            .remove(field);
        k.rejected(request, "malformed");
    }
    let mut request = base();
    request["epoch"] = json!("4");
    k.rejected(request, "malformed");

    // The actor needs an effective admin right.
    let mut request = base();
    request["actor"] = json!("bob");
    k.rejected(request, "unauthorized");
    let mut request = base();
    request["actor"] = json!("carol");
    k.rejected(request, "unauthorized");

    // Generation rules of `grant` with fresh_keys true.
    let mut request = base();
    request["generation"] = json!(1);
    k.rejected(request, "invalid_generation");
    k.rejected(
        rekey("root", "bob", "write", 1, "b3", "b4", 4),
        "invalid_generation",
    );
    k.rejected(
        rekey("root", "bob", "write", 2, "b3", "b4", 4),
        "invalid_generation",
    );

    // A read-fenced group refuses rekey.
    let response = k.revoke("carol", "read");
    assert_eq!(response["read_fenced"], json!(true));
    k.rejected(base(), "read_fenced");

    // So does a pending repair, which keeps the fence closed.
    let policy_revision = k.policy_revision();
    let response = k.ok(json!({
        "command":"repair_stage", "parent_branch":"b3", "new_branch":"r4", "epoch":4,
        "policy_revision":policy_revision, "removed":["carol"], "update_path":true,
        "durable":true
    }));
    assert_eq!(response["branch"], json!("r4"));
    assert_eq!(k.checkpoint()["repair_pending"], json!("r4"));
    k.rejected(
        rekey("root", "bob", "admin", 0, "r4", "b5", 5),
        "read_fenced",
    );

    // Once the repair is open, the same rekey succeeds at the new frontier.
    k.ok(json!({"command":"repair_open", "branch":"r4", "confirmed":true}));
    let policy_revision = k.policy_revision();
    let response = k.ok(rekey("root", "bob", "admin", 0, "r4", "b5", 5));
    assert_eq!(
        response,
        json!({"epoch":5, "branch":"b5", "policy_revision":policy_revision + 1})
    );
    assert_eq!(k.status("bob", "admin")["effective"], json!(true));

    // A re-grant must be exactly the old generation + 1.
    k.revoke("bob", "write");
    k.rejected(
        rekey("root", "bob", "write", 3, "b5", "b6", 6),
        "invalid_generation",
    );
    k.ok(rekey("root", "bob", "write", 2, "b5", "b6", 6));
    assert_eq!(
        k.record("bob", "write"),
        Some(json!({"subject":"bob", "right":"write", "generation":2, "active":true}))
    );
}
