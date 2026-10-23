//! R-9 invocation resources (approved 2026-10-23, D-8, amendment A-2).
//!
//! Normative text: `docs/authority-contract.md`, bullet "R-9 invocation
//! resources", and `docs/adapter-contract.md`, paragraph "R-9". A root
//! invocation (one without `parent_invocation`) requires every requested
//! resource to be held by the origin under the R-8 chain check; this replaces
//! the earlier subset-of-`[group]` rule. A violation is `invalid_invocation`.
//! Nested invocations stay a subset of their parent invocation's resources, and
//! every R-8 release-time check (origin and executor chains) still applies.
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
const OTHER: &str = "backend:other";
const NOW: u64 = 10;
const RWA: &[&str] = &["read", "write", "admit"];

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
            "agent-trust-invocation-resources-{}-{nanos}-{serial}",
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

/// Initializes group `g` with root `root` holding `resources` (R-8c).
fn init(authority: &mut Authority, resources: &[&str]) {
    let response = request(
        authority,
        json!({"command":"init", "group":GROUP, "root":"root", "resources":resources}),
        "valid init must succeed",
    );
    assert_eq!(
        response,
        json!({"revision":0, "epoch":0, "branch":"genesis"})
    );
}

fn checkpoint(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}), "checkpoint")
}

fn policy_revision(authority: &mut Authority) -> u64 {
    checkpoint(authority)["policy_revision"]
        .as_u64()
        .expect("checkpoint policy_revision (R-3)")
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
        "delegation within the parent's resources must succeed",
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

/// Issues an invocation that must succeed, and checks the stored record and
/// that `policy_revision` advanced by exactly one (R-3).
fn invoke(
    authority: &mut Authority,
    origin: &str,
    executor: &str,
    resources: &[&str],
    parent_invocation: Option<&str>,
    why: &str,
) -> String {
    let before = policy_revision(authority);
    let id = match try_invoke(
        authority,
        origin,
        executor,
        &["write"],
        resources,
        parent_invocation,
    ) {
        Ok(id) => id,
        Err(err) => panic!("{why}: invocation must be issued, got {err}"),
    };
    let after = checkpoint(authority);
    assert_eq!(
        after["policy_revision"].as_u64(),
        Some(before + 1),
        "{why}: a successful invoke advances policy_revision by exactly one (R-3)"
    );
    let record = after["invocations"]
        .as_array()
        .expect("checkpoint invocations")
        .iter()
        .find(|x| x["id"] == id.as_str())
        .unwrap_or_else(|| panic!("{why}: issued invocation {id} must be stored"))
        .clone();
    assert_eq!(record["resources"], json!(resources), "{why}");
    assert_eq!(record["executor"], executor, "{why}");
    id
}

/// Asserts the invocation is `invalid_invocation` and that the failed request
/// changed nothing, `policy_revision` included.
fn invalid(
    authority: &mut Authority,
    origin: &str,
    executor: &str,
    resources: &[&str],
    parent_invocation: Option<&str>,
    why: &str,
) {
    let before = checkpoint(authority);
    code(
        try_invoke(
            authority,
            origin,
            executor,
            &["write"],
            resources,
            parent_invocation,
        ),
        "invalid_invocation",
        why,
    );
    let after = checkpoint(authority);
    assert_eq!(
        after["policy_revision"], before["policy_revision"],
        "{why}: a refused invoke must not advance policy_revision"
    );
    assert_eq!(
        after, before,
        "{why}: a refused invoke must leave the whole checkpoint unchanged"
    );
}

/// A-1: allocation is a reservation only; it must succeed for any resource.
fn allocate(authority: &mut Authority, actor: &str, op: &str, resource: &str, invocation: &str) {
    let response = request(
        authority,
        json!({
            "command":"allocate", "actor":actor, "op":op, "resource":resource,
            "invocation":invocation
        }),
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

/// Root holds `[g, kv]`; `parent` and `kv-exec` are root-delegated `[g, kv]`
/// with read, write and admit, and both are admitted.
fn kv_holders(authority: &mut Authority) {
    init(authority, &[GROUP, KV]);
    delegate(authority, "root", "parent", RWA, &[GROUP, KV], 7);
    admit(authority, "parent");
    delegate(authority, "root", "kv-exec", RWA, &[GROUP, KV], 7);
    admit(authority, "kv-exec");
}

#[test]
fn root_invocation_on_an_origin_held_resource_releases() {
    let store = Store::new();
    let mut authority = open(&store);
    kv_holders(&mut authority);

    let kv_only = invoke(
        &mut authority,
        "parent",
        "kv-exec",
        &[KV],
        None,
        "R-9: the origin holds backend:kv, so a root invocation may name it",
    );
    allocate(&mut authority, "kv-exec", "kv-only-write", KV, &kv_only);
    released(
        &mut authority,
        "kv-exec",
        "kv-only-write",
        KV,
        "R-9 with R-8b: origin, executor and the invocation all hold backend:kv",
    );

    let both = invoke(
        &mut authority,
        "parent",
        "kv-exec",
        &[GROUP, KV],
        None,
        "R-9: every requested resource is held by the origin",
    );
    allocate(&mut authority, "kv-exec", "both-group-write", GROUP, &both);
    released(
        &mut authority,
        "kv-exec",
        "both-group-write",
        GROUP,
        "the [g, kv] invocation authorizes a group write",
    );
    allocate(&mut authority, "kv-exec", "both-kv-write", KV, &both);
    released(
        &mut authority,
        "kv-exec",
        "both-kv-write",
        KV,
        "the [g, kv] invocation authorizes a backend:kv write",
    );
}

#[test]
fn root_invocation_on_a_resource_the_origin_lacks_is_invalid() {
    let store = Store::new();
    let mut authority = open(&store);
    kv_holders(&mut authority);
    // sib: root-delegated [g] only, although root holds backend:kv.
    delegate(&mut authority, "root", "sib", RWA, &[GROUP], 7);
    // grand: two hops below root through mid. Delegation requires a subset of
    // the parent's resources, so a chain missing backend:kv at an intermediate
    // record also misses it at the origin's own record.
    delegate(&mut authority, "root", "mid", RWA, &[GROUP], 7);
    delegate(&mut authority, "mid", "grand", RWA, &[GROUP], 6);
    // direct: a root-anchored grant without a delegation record holds only [g].
    grant(&mut authority, "direct", "write");

    // Positive paths: each origin may invoke on a resource it holds.
    invoke(
        &mut authority,
        "parent",
        "kv-exec",
        &[KV],
        None,
        "R-9: an origin holding backend:kv may name it",
    );
    invoke(
        &mut authority,
        "root",
        "kv-exec",
        &[GROUP, KV],
        None,
        "R-9: root holds its init resources",
    );
    for origin in ["sib", "grand", "direct"] {
        invoke(
            &mut authority,
            origin,
            "kv-exec",
            &[GROUP],
            None,
            "an origin holding the group may name it",
        );
    }

    // Negative paths: the executor kv-exec holds every named resource except
    // backend:other, so each refusal is due to the origin's chain.
    invalid(
        &mut authority,
        "sib",
        "kv-exec",
        &[KV],
        None,
        "R-9: sib's record lacks backend:kv although root holds it",
    );
    invalid(
        &mut authority,
        "sib",
        "kv-exec",
        &[GROUP, KV],
        None,
        "R-9: every requested resource must be held, not only one",
    );
    invalid(
        &mut authority,
        "grand",
        "kv-exec",
        &[KV],
        None,
        "R-9: grand's chain (grand, mid) lacks backend:kv although root holds it",
    );
    invalid(
        &mut authority,
        "direct",
        "kv-exec",
        &[KV],
        None,
        "R-9 with R-8: a direct root-anchored grant holds only the group",
    );
    invalid(
        &mut authority,
        "parent",
        "kv-exec",
        &[OTHER],
        None,
        "R-9: a resource outside every chain, root's included",
    );
    invalid(
        &mut authority,
        "root",
        "kv-exec",
        &[GROUP, OTHER],
        None,
        "R-9: root does not hold a resource outside its init resources",
    );
}

#[test]
fn executor_resource_check_still_applies_to_root_invocations() {
    let store = Store::new();
    let mut authority = open(&store);
    kv_holders(&mut authority);

    // Positive path: an executor that holds backend:kv releases on it.
    let to_holder = invoke(
        &mut authority,
        "parent",
        "kv-exec",
        &[KV],
        None,
        "R-9: the origin holds backend:kv",
    );
    allocate(&mut authority, "kv-exec", "holder-kv-write", KV, &to_holder);
    released(
        &mut authority,
        "kv-exec",
        "holder-kv-write",
        KV,
        "origin and executor both hold backend:kv",
    );

    // g-exec: root-delegated [g] only, admitted after the backend:kv release
    // so that every positive release above ran with readers holding the resource.
    delegate(&mut authority, "root", "g-exec", RWA, &[GROUP], 7);
    admit(&mut authority, "g-exec");

    let group_hop = invoke(
        &mut authority,
        "parent",
        "g-exec",
        &[GROUP],
        None,
        "a root invocation on the group",
    );
    allocate(
        &mut authority,
        "g-exec",
        "g-exec-group-write",
        GROUP,
        &group_hop,
    );
    released(
        &mut authority,
        "g-exec",
        "g-exec-group-write",
        GROUP,
        "g-exec holds the group resource",
    );

    // R-9 checks only the origin at invoke; the executor check is at release (R-8b).
    let lacking = invoke(
        &mut authority,
        "parent",
        "g-exec",
        &[KV],
        None,
        "R-9: the origin holds backend:kv; invoke does not check the executor's resources",
    );
    allocate(&mut authority, "g-exec", "g-exec-kv-write", KV, &lacking);
    refused(
        &mut authority,
        "g-exec",
        "g-exec-kv-write",
        KV,
        "R-8b: the executor's chain lacks backend:kv although the origin and invocation carry it",
    );
}

#[test]
fn nested_invocations_stay_bounded_by_their_parent() {
    let store = Store::new();
    let mut authority = open(&store);
    kv_holders(&mut authority);
    delegate(&mut authority, "root", "leaf", RWA, &[GROUP, KV], 7);
    admit(&mut authority, "leaf");

    // The parent invocation carries only the group, although origin, both
    // executors and every reader hold backend:kv.
    let first = invoke(
        &mut authority,
        "parent",
        "kv-exec",
        &[GROUP],
        None,
        "a root invocation on the group",
    );
    let nested = invoke(
        &mut authority,
        "kv-exec",
        "leaf",
        &[GROUP],
        Some(&first),
        "a nested invocation on a subset of its parent's resources",
    );
    allocate(&mut authority, "leaf", "nested-group-write", GROUP, &nested);
    released(
        &mut authority,
        "leaf",
        "nested-group-write",
        GROUP,
        "a nested invocation within its parent authorizes the release",
    );

    invalid(
        &mut authority,
        "kv-exec",
        "leaf",
        &[KV],
        Some(&first),
        "a nested invocation must not name a resource outside its parent invocation",
    );
    invalid(
        &mut authority,
        "kv-exec",
        "leaf",
        &[GROUP, KV],
        Some(&first),
        "a nested invocation must be a subset of its parent invocation",
    );
}
