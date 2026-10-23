//! R-8 resource attenuation (approved 2026-10-23, amendment A-1).
//!
//! Normative text: `docs/authority-contract.md`, bullet "R-8 resource attenuation".
//! `release` requires the operation resource to be in the `resources` of every
//! delegation on the actor's chain up to the root; for an invocation-bound
//! operation the same check applies to every origin and executor in the
//! invocation chain. A direct root-anchored grant holds only `[group]`.
//! `allocate` makes no authorization decision. `init` accepts an optional
//! `resources` array that must contain the group.
//!
//! Every positive release in this file is made while every roster reader holds
//! the released resource, so the assertions do not depend on whether readers
//! are resource-checked (the contract scopes the check to actor, origin and
//! executor chains only).
use agent_trust::authority::Authority;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT_STORE: AtomicU64 = AtomicU64::new(0);

const GROUP: &str = "g";
const KV: &str = "backend:kv";
const NOW: u64 = 10;

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
            "agent-trust-resource-contract-{}-{nanos}-{serial}",
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

fn code<T: std::fmt::Debug>(result: Result<T, String>, expected: &str, why: &str) {
    let err = match result {
        Err(err) => err,
        Ok(value) => panic!("{why}: expected {expected}, but request succeeded with {value:?}"),
    };
    assert!(
        err == expected || err.starts_with(&format!("{expected}:")),
        "{why}: expected {expected}, got {err}"
    );
}

fn request(authority: &mut Authority, value: Value, why: &str) -> Value {
    match authority.execute(value) {
        Ok(response) => response,
        Err(err) => panic!("{why}: request failed with {err}"),
    }
}

fn open(store: &Store) -> Authority {
    Authority::open(store.path()).unwrap()
}

/// Initializes group `g` with root `root`; `resources` is omitted when `None`.
fn init(authority: &mut Authority, resources: Option<&[&str]>) {
    let mut payload = json!({"command":"init", "group":GROUP, "root":"root"});
    if let Some(resources) = resources {
        payload["resources"] = json!(resources);
    }
    let response = request(authority, payload, "valid init must succeed");
    assert_eq!(
        response,
        json!({"revision":0, "epoch":0, "branch":"genesis"})
    );
}

fn checkpoint(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}), "checkpoint")
}

fn grant(authority: &mut Authority, subject: &str, right: &str) {
    request(
        authority,
        json!({
            "command":"grant", "actor":"root", "subject":subject, "right":right,
            "generation":0, "fresh_keys":true, "now":NOW
        }),
        "direct root grant must succeed",
    );
}

fn delegate(
    authority: &mut Authority,
    actor: &str,
    subject: &str,
    rights: &[&str],
    resources: &[&str],
    depth: u64,
) {
    request(
        authority,
        json!({
            "command":"delegate", "actor":actor, "subject":subject, "rights":rights,
            "resources":resources, "expires_at":1000, "not_before":0, "depth":depth, "now":NOW
        }),
        "delegation within the parent's resources must succeed (R-8c: init resources bound the root record)",
    );
}

fn admit(authority: &mut Authority, subject: &str) {
    request(
        authority,
        json!({"command":"admit", "actor":"root", "subject":subject, "now":NOW}),
        "admission of a delegated reader must succeed",
    );
}

fn try_invoke(
    authority: &mut Authority,
    origin: &str,
    executor: &str,
    rights: &[&str],
    resources: &[&str],
    parent_invocation: Option<&str>,
) -> Result<String, String> {
    let mut payload = json!({
        "command":"invoke", "actor":origin, "executor":executor,
        "rights":rights, "resources":resources, "now":NOW
    });
    if let Some(parent) = parent_invocation {
        payload["parent_invocation"] = json!(parent);
    }
    authority.execute(payload).map(|response| {
        response["invocation"]
            .as_str()
            .expect("APF-issued invocation id")
            .to_owned()
    })
}

fn invoke(
    authority: &mut Authority,
    origin: &str,
    executor: &str,
    rights: &[&str],
    resources: &[&str],
    parent_invocation: Option<&str>,
) -> String {
    match try_invoke(
        authority,
        origin,
        executor,
        rights,
        resources,
        parent_invocation,
    ) {
        Ok(id) => id,
        Err(err) => {
            panic!("group-resource invocation must be issued (invoke is unchanged by R-8): {err}")
        }
    }
}

/// A-1: allocation is a reservation only; it must succeed for any resource.
fn allocate(
    authority: &mut Authority,
    actor: &str,
    op: &str,
    resource: &str,
    invocation: Option<&str>,
) {
    let mut payload = json!({"command":"allocate", "actor":actor, "op":op, "resource":resource});
    if let Some(invocation) = invocation {
        payload["invocation"] = json!(invocation);
    }
    let response = request(
        authority,
        payload,
        "allocate makes no authorization decision (A-1)",
    );
    assert_eq!(response, json!({"op":op}));
}

fn active_generation(snapshot: &Value, subject: &str, right: &str) -> u64 {
    snapshot["grants"]
        .as_array()
        .expect("checkpoint grants")
        .iter()
        .find(|g| g["subject"] == subject && g["right"] == right && g["active"] == true)
        .and_then(|g| g["generation"].as_u64())
        .unwrap_or_else(|| panic!("{subject} must hold an active {right} grant"))
}

/// Sound cover: the writer singleton plus every current roster reader singleton.
fn sound_cover(snapshot: &Value, actor: &str) -> Vec<Value> {
    let mut cover = vec![json!([{
        "subject":actor, "right":"write",
        "generation":active_generation(snapshot, actor, "write")
    }])];
    for reader in snapshot["roster"].as_array().expect("checkpoint roster") {
        let reader = reader.as_str().expect("roster member");
        cover.push(json!([{
            "subject":reader, "right":"read",
            "generation":active_generation(snapshot, reader, "read")
        }]));
    }
    cover
}

/// Write release at the exact current frontier with a sound cover.
fn release(
    authority: &mut Authority,
    actor: &str,
    op: &str,
    resource: &str,
) -> Result<Value, String> {
    let current = checkpoint(authority);
    authority.execute(json!({
        "command":"release", "actor":actor, "op":op, "right":"write", "resource":resource,
        "revision":current["revision"], "epoch":current["epoch"], "branch":current["branch"],
        "digest":"aa", "cover":sound_cover(&current, actor), "now":NOW
    }))
}

fn released(authority: &mut Authority, actor: &str, op: &str, resource: &str, why: &str) {
    let response = match release(authority, actor, op, resource) {
        Ok(response) => response,
        Err(err) => panic!("{why}: release failed with {err}"),
    };
    assert_eq!(response["op"], op);
    assert_eq!(response["resource"], resource);
}

/// Asserts the release is `unauthorized` and that the failed request changed nothing.
fn refused(authority: &mut Authority, actor: &str, op: &str, resource: &str, why: &str) {
    let before = checkpoint(authority);
    code(release(authority, actor, op, resource), "unauthorized", why);
    assert_eq!(
        checkpoint(authority),
        before,
        "{why}: a refused release must leave the whole checkpoint unchanged"
    );
}

#[test]
fn direct_release_outside_delegated_resources_is_unauthorized() {
    let store = Store::new();
    let mut authority = open(&store);
    init(&mut authority, None);
    delegate(
        &mut authority,
        "root",
        "sib",
        &["read", "write", "admit"],
        &[GROUP],
        7,
    );
    admit(&mut authority, "sib");

    allocate(&mut authority, "sib", "sib-group-write", GROUP, None);
    released(
        &mut authority,
        "sib",
        "sib-group-write",
        GROUP,
        "a write on the delegated group resource is authorized",
    );

    allocate(&mut authority, "sib", "sib-kv-write", KV, None);
    refused(
        &mut authority,
        "sib",
        "sib-kv-write",
        KV,
        "R-8: sib's delegation covers only the group resource",
    );

    // The reservation stays `allocated`: it is not released (persist rejects it),
    // not abandoned (abandon is idempotent on an abandoned op and rejects only
    // allocated or persisted ops), still exists (no reuse) and cannot be retried.
    let before = checkpoint(&mut authority);
    code(
        authority.execute(json!({
            "command":"persist", "op":"sib-kv-write", "digest":"aa", "envelope":"00"
        })),
        "invalid_transition",
        "refused reservation must not be released",
    );
    code(
        authority.execute(json!({"command":"abandon", "op":"sib-kv-write"})),
        "invalid_transition",
        "refused reservation must still be allocated",
    );
    code(
        authority.execute(json!({
            "command":"allocate", "actor":"sib", "op":"sib-kv-write", "resource":KV
        })),
        "duplicate_operation",
        "refused reservation must still exist",
    );
    code(
        release(&mut authority, "sib", "sib-kv-write", KV),
        "unauthorized",
        "a retried release must still be refused for the resource",
    );
    assert_eq!(checkpoint(&mut authority), before);
}

#[test]
fn root_resources_at_init_bound_every_descendant() {
    let store = Store::new();
    let mut authority = open(&store);
    init(&mut authority, Some(&[GROUP, KV]));

    allocate(&mut authority, "root", "root-kv-write", KV, None);
    released(
        &mut authority,
        "root",
        "root-kv-write",
        KV,
        "root holds backend:kv from init resources",
    );

    delegate(
        &mut authority,
        "root",
        "sib",
        &["read", "write", "admit"],
        &[GROUP, KV],
        7,
    );
    admit(&mut authority, "sib");
    allocate(&mut authority, "sib", "sib-kv-write", KV, None);
    released(
        &mut authority,
        "sib",
        "sib-kv-write",
        KV,
        "sib was delegated backend:kv by root",
    );

    delegate(
        &mut authority,
        "sib",
        "grand",
        &["read", "write", "admit"],
        &[GROUP],
        6,
    );
    admit(&mut authority, "grand");
    allocate(&mut authority, "grand", "grand-group-write", GROUP, None);
    released(
        &mut authority,
        "grand",
        "grand-group-write",
        GROUP,
        "grand holds the group resource",
    );

    allocate(&mut authority, "grand", "grand-kv-write", KV, None);
    refused(
        &mut authority,
        "grand",
        "grand-kv-write",
        KV,
        "R-8: grand's own record lacks backend:kv although its parent holds it",
    );
}

#[test]
fn init_resources_must_contain_the_group_and_be_well_formed() {
    let store = Store::new();
    let mut authority = open(&store);
    let malformed = [
        ("without the group", json!([KV])),
        ("with a duplicate", json!([GROUP, GROUP])),
        ("empty", json!([])),
        ("with a non-string entry", json!([GROUP, 7])),
        ("with an empty identifier", json!([GROUP, ""])),
        ("not an array", json!(GROUP)),
    ];
    for (case, resources) in malformed {
        let result = authority.execute(json!({
            "command":"init", "group":GROUP, "root":"root", "resources":resources
        }));
        match result {
            Ok(response) => panic!("init resources {case} must be malformed, got {response}"),
            Err(err) => assert!(
                err.starts_with("malformed"),
                "init resources {case}: expected malformed, got {err}"
            ),
        }
        code(
            authority.execute(json!({"command":"checkpoint"})),
            "uninitialized",
            "a malformed init must leave the store uninitialized",
        );
    }
    // The group need not be first.
    init(&mut authority, Some(&[KV, GROUP]));
    allocate(&mut authority, "root", "root-kv-write", KV, None);
    released(
        &mut authority,
        "root",
        "root-kv-write",
        KV,
        "an explicit init resource is held by root",
    );

    let default_store = Store::new();
    let mut authority = open(&default_store);
    init(&mut authority, None);
    allocate(&mut authority, "root", "root-group-write", GROUP, None);
    released(
        &mut authority,
        "root",
        "root-group-write",
        GROUP,
        "the default root resource is the group",
    );
    allocate(&mut authority, "root", "root-kv-write", KV, None);
    refused(
        &mut authority,
        "root",
        "root-kv-write",
        KV,
        "R-8c: the default root resources are exactly [group]",
    );
}

/// Invocation releases (R-8b).
///
/// `invoke` is unchanged by R-8: a root invocation may carry only the group
/// resource, and a nested invocation a subset of its parent. An invocation can
/// therefore never carry `backend:kv`, and an invocation-bound release on
/// `backend:kv` is already refused by the invocation-resource check. The
/// resource attenuation of the origin and executor chains is made observable
/// with subjects delegated only `["backend:kv"]`, whose chains lack the group
/// resource that the invocation does carry. Before R-8 those releases succeed.
#[test]
fn invocation_release_requires_resource_in_origin_and_executor_chains() {
    // Scenario A: parent holds [g, kv]; child holds [g].
    {
        let store = Store::new();
        let mut authority = open(&store);
        init(&mut authority, Some(&[GROUP, KV]));
        delegate(
            &mut authority,
            "root",
            "parent",
            &["read", "write", "admit"],
            &[GROUP, KV],
            7,
        );
        admit(&mut authority, "parent");
        delegate(
            &mut authority,
            "parent",
            "child",
            &["read", "write", "admit"],
            &[GROUP],
            6,
        );
        admit(&mut authority, "child");

        let parent_origin = invoke(
            &mut authority,
            "parent",
            "child",
            &["write"],
            &[GROUP],
            None,
        );
        allocate(
            &mut authority,
            "child",
            "parent-origin-group",
            GROUP,
            Some(&parent_origin),
        );
        released(
            &mut authority,
            "child",
            "parent-origin-group",
            GROUP,
            "parent-originated invocation on the group: origin and executor hold it",
        );

        let child_origin = invoke(
            &mut authority,
            "child",
            "parent",
            &["write"],
            &[GROUP],
            None,
        );
        allocate(
            &mut authority,
            "parent",
            "child-origin-group",
            GROUP,
            Some(&child_origin),
        );
        released(
            &mut authority,
            "parent",
            "child-origin-group",
            GROUP,
            "child-originated invocation on the group: origin and executor hold it",
        );

        // The child cannot even mint an invocation that names backend:kv.
        code(
            try_invoke(&mut authority, "child", "parent", &["write"], &[KV], None),
            "invalid_invocation",
            "a child-originated invocation must not name backend:kv",
        );
        // Nor can the parent launder backend:kv through a child-originated
        // invocation, although the parent itself holds backend:kv.
        allocate(
            &mut authority,
            "parent",
            "child-origin-kv",
            KV,
            Some(&child_origin),
        );
        refused(
            &mut authority,
            "parent",
            "child-origin-kv",
            KV,
            "a child-originated invocation must not release on backend:kv",
        );
    }

    // Scenario B: the executor's own chain lacks the resource, the origin holds it.
    {
        let store = Store::new();
        let mut authority = open(&store);
        init(&mut authority, Some(&[GROUP, KV]));
        delegate(
            &mut authority,
            "root",
            "parent",
            &["read", "write", "admit"],
            &[GROUP, KV],
            7,
        );
        admit(&mut authority, "parent");
        delegate(
            &mut authority,
            "root",
            "kv-exec",
            &["read", "write", "admit"],
            &[KV],
            7,
        );
        admit(&mut authority, "kv-exec");

        allocate(&mut authority, "kv-exec", "kv-exec-own-kv", KV, None);
        released(
            &mut authority,
            "kv-exec",
            "kv-exec-own-kv",
            KV,
            "kv-exec is a working writer on its delegated resource",
        );

        let invocation = invoke(
            &mut authority,
            "parent",
            "kv-exec",
            &["write"],
            &[GROUP],
            None,
        );
        allocate(
            &mut authority,
            "kv-exec",
            "exec-lacks-group",
            GROUP,
            Some(&invocation),
        );
        refused(
            &mut authority,
            "kv-exec",
            "exec-lacks-group",
            GROUP,
            "R-8b: the executor's chain lacks the resource although the origin holds it",
        );
    }

    // Scenario C: the origin's chain lacks the resource, the executor holds it.
    {
        let store = Store::new();
        let mut authority = open(&store);
        init(&mut authority, Some(&[GROUP, KV]));
        delegate(
            &mut authority,
            "root",
            "parent",
            &["read", "write", "admit"],
            &[GROUP, KV],
            7,
        );
        admit(&mut authority, "parent");
        delegate(&mut authority, "root", "kv-origin", &["write"], &[KV], 7);

        let root_origin = invoke(&mut authority, "root", "parent", &["write"], &[GROUP], None);
        allocate(
            &mut authority,
            "parent",
            "root-origin-group",
            GROUP,
            Some(&root_origin),
        );
        released(
            &mut authority,
            "parent",
            "root-origin-group",
            GROUP,
            "an origin holding the group authorizes the executor",
        );

        let invocation = invoke(
            &mut authority,
            "kv-origin",
            "parent",
            &["write"],
            &[GROUP],
            None,
        );
        allocate(
            &mut authority,
            "parent",
            "origin-lacks-group",
            GROUP,
            Some(&invocation),
        );
        refused(
            &mut authority,
            "parent",
            "origin-lacks-group",
            GROUP,
            "R-8b: the origin's chain lacks the resource although the executor holds it",
        );
    }

    // Scenario D: an intermediate executor of a multi-hop chain lacks the resource.
    {
        let store = Store::new();
        let mut authority = open(&store);
        init(&mut authority, Some(&[GROUP, KV]));
        delegate(
            &mut authority,
            "root",
            "parent",
            &["read", "write", "admit"],
            &[GROUP, KV],
            7,
        );
        admit(&mut authority, "parent");
        delegate(
            &mut authority,
            "parent",
            "child",
            &["read", "write", "admit"],
            &[GROUP],
            6,
        );
        admit(&mut authority, "child");

        let direct = invoke(
            &mut authority,
            "parent",
            "child",
            &["write"],
            &[GROUP],
            None,
        );
        allocate(
            &mut authority,
            "child",
            "direct-hop-group",
            GROUP,
            Some(&direct),
        );
        released(
            &mut authority,
            "child",
            "direct-hop-group",
            GROUP,
            "a single hop between group holders is authorized",
        );

        delegate(
            &mut authority,
            "root",
            "kv-mid",
            &["read", "write", "admit"],
            &[KV],
            7,
        );
        admit(&mut authority, "kv-mid");
        let first = invoke(
            &mut authority,
            "parent",
            "kv-mid",
            &["write"],
            &[GROUP],
            None,
        );
        let second = invoke(
            &mut authority,
            "kv-mid",
            "child",
            &["write"],
            &[GROUP],
            Some(&first),
        );
        allocate(
            &mut authority,
            "child",
            "mid-lacks-group",
            GROUP,
            Some(&second),
        );
        refused(
            &mut authority,
            "child",
            "mid-lacks-group",
            GROUP,
            "R-8b: every executor in the invocation chain must hold the resource",
        );
    }
}

#[test]
fn direct_grant_subjects_hold_only_the_group_resource() {
    let store = Store::new();
    let mut authority = open(&store);
    init(&mut authority, Some(&[GROUP, KV]));

    allocate(&mut authority, "root", "root-kv-write", KV, None);
    released(
        &mut authority,
        "root",
        "root-kv-write",
        KV,
        "root holds backend:kv from init resources",
    );

    for right in ["read", "write", "admit"] {
        grant(&mut authority, "direct", right);
    }
    admit(&mut authority, "direct");

    allocate(&mut authority, "direct", "direct-group-write", GROUP, None);
    released(
        &mut authority,
        "direct",
        "direct-group-write",
        GROUP,
        "a direct root-anchored grant holds the group resource",
    );

    allocate(&mut authority, "direct", "direct-kv-write", KV, None);
    refused(
        &mut authority,
        "direct",
        "direct-kv-write",
        KV,
        "R-8: a subject without a delegation record holds only [group]",
    );
}

#[test]
fn allocate_still_makes_no_authorization_decision() {
    let store = Store::new();
    let mut authority = open(&store);
    init(&mut authority, None);
    delegate(
        &mut authority,
        "root",
        "sib",
        &["read", "write", "admit"],
        &[GROUP],
        7,
    );
    admit(&mut authority, "sib");

    let before = checkpoint(&mut authority);
    allocate(&mut authority, "sib", "sib-group-op", GROUP, None);
    allocate(&mut authority, "sib", "sib-kv-op", KV, None);
    allocate(&mut authority, "sib", "sib-other-op", "backend:other", None);
    allocate(&mut authority, "root", "root-kv-op", KV, None);
    let after = checkpoint(&mut authority);
    assert_eq!(
        after["policy_revision"], before["policy_revision"],
        "allocation is not a policy decision (R-3)"
    );
    assert_eq!(after["policy_digest"], before["policy_digest"]);
}
