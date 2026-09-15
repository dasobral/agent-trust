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
            "agent-trust-confused-deputy-{}-{nanos}-{serial}",
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

fn request(authority: &mut Authority, request: Value) -> Value {
    authority.execute(request).expect("request should succeed")
}

fn init(authority: &mut Authority) {
    request(
        authority,
        json!({"command":"init", "group":"group-a", "root":"root"}),
    );
}

fn grant(authority: &mut Authority, subject: &str, right: &str) {
    request(
        authority,
        json!({
            "command":"grant", "actor":"root", "subject":subject, "right":right,
            "generation":0, "fresh_keys":true, "now":10
        }),
    );
}

fn prepare_parent(authority: &mut Authority) {
    for right in ["read", "write", "admit"] {
        grant(authority, "parent", right);
    }
    request(
        authority,
        json!({"command":"admit", "actor":"root", "subject":"parent", "now":10}),
    );
    grant(authority, "child", "read");
}

fn frontier(authority: &mut Authority) -> Value {
    request(authority, json!({"command":"checkpoint"}))
}

fn cover_for_parent() -> Vec<Value> {
    vec![
        json!([{"subject":"root", "right":"read", "generation":0}]),
        json!([{"subject":"parent", "right":"read", "generation":0}]),
        json!([{"subject":"parent", "right":"write", "generation":0}]),
    ]
}

fn invoke(
    authority: &mut Authority,
    origin: &str,
    executor: &str,
    rights: &[&str],
    resources: &[&str],
    parent_invocation: Option<&str>,
) -> String {
    let mut payload = json!({
        "command":"invoke", "actor":origin, "executor":executor,
        "rights":rights, "resources":resources, "now":10
    });
    if let Some(parent_invocation) = parent_invocation {
        payload["parent_invocation"] = json!(parent_invocation);
    }
    request(authority, payload)["invocation"]
        .as_str()
        .expect("APF-issued invocation id")
        .to_owned()
}

fn allocate(
    authority: &mut Authority,
    actor: &str,
    op: &str,
    resource: &str,
    invocation: Option<&str>,
) {
    let mut payload = json!({
        "command":"allocate", "actor":actor, "op":op, "resource":resource
    });
    if let Some(invocation) = invocation {
        payload["invocation"] = json!(invocation);
    }
    request(authority, payload);
}

fn release(
    authority: &mut Authority,
    actor: &str,
    op: &str,
    right: &str,
    resource: &str,
) -> Result<Value, String> {
    let current = frontier(authority);
    authority.execute(json!({
        "command":"release", "actor":actor, "op":op, "right":right,
        "resource":resource,
        "revision":current["revision"], "epoch":current["epoch"], "branch":current["branch"],
        "digest":"aa", "cover":cover_for_parent(), "now":10
    }))
}

#[test]
fn direct_confused_deputy_is_rejected_while_parent_independent_write_is_allowed() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    prepare_parent(&mut authority);

    let invocation = invoke(
        &mut authority,
        "child",
        "parent",
        &["read"],
        &["group-a"],
        None,
    );
    allocate(
        &mut authority,
        "parent",
        "laundered-write",
        "group-a",
        Some(&invocation),
    );
    assert_eq!(
        release(
            &mut authority,
            "parent",
            "laundered-write",
            "write",
            "group-a"
        )
        .expect_err("child authority must not authorize parent write"),
        "unauthorized"
    );

    allocate(
        &mut authority,
        "parent",
        "independent-write",
        "group-a",
        None,
    );
    release(
        &mut authority,
        "parent",
        "independent-write",
        "write",
        "group-a",
    )
    .expect("independent parent authority must remain usable");
}

#[test]
fn child_originated_read_through_parent_is_allowed() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    prepare_parent(&mut authority);

    let invocation = invoke(
        &mut authority,
        "child",
        "parent",
        &["read"],
        &["group-a"],
        None,
    );
    allocate(
        &mut authority,
        "parent",
        "delegated-read",
        "group-a",
        Some(&invocation),
    );
    release(
        &mut authority,
        "parent",
        "delegated-read",
        "read",
        "group-a",
    )
    .expect("delegated read is within the child authority");
}

#[test]
fn child_cannot_launder_parent_only_resource() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    prepare_parent(&mut authority);

    let invocation = invoke(
        &mut authority,
        "child",
        "parent",
        &["read"],
        &["group-a"],
        None,
    );
    allocate(
        &mut authority,
        "parent",
        "resource-laundering",
        "group-b",
        Some(&invocation),
    );
    assert_eq!(
        release(
            &mut authority,
            "parent",
            "resource-laundering",
            "read",
            "group-b"
        )
        .expect_err("child resource authority must not widen"),
        "unauthorized"
    );
}

#[test]
fn multi_hop_and_attenuation_cannot_restore_removed_authority() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    prepare_parent(&mut authority);
    for right in ["read", "write", "admin", "admit"] {
        grant(&mut authority, "high", right);
    }
    request(
        &mut authority,
        json!({"command":"admit", "actor":"root", "subject":"high", "now":10}),
    );

    let low_to_parent = invoke(
        &mut authority,
        "child",
        "parent",
        &["read"],
        &["group-a"],
        None,
    );
    let parent_to_high = invoke(
        &mut authority,
        "parent",
        "high",
        &["read"],
        &["group-a"],
        Some(&low_to_parent),
    );
    allocate(
        &mut authority,
        "high",
        "multi-hop-write",
        "group-a",
        Some(&parent_to_high),
    );
    assert_eq!(
        release(
            &mut authority,
            "high",
            "multi-hop-write",
            "write",
            "group-a"
        )
        .expect_err("multi-hop authority must remain attenuated"),
        "unauthorized"
    );
}

#[test]
fn revocation_of_origin_authority_invalidates_a_still_authorized_executor() {
    let store = Store::new();
    let mut authority = Authority::open(store.path()).unwrap();
    init(&mut authority);
    prepare_parent(&mut authority);

    let invocation = invoke(
        &mut authority,
        "child",
        "parent",
        &["read"],
        &["group-a"],
        None,
    );
    allocate(
        &mut authority,
        "parent",
        "revoked-origin",
        "group-a",
        Some(&invocation),
    );
    request(
        &mut authority,
        json!({
            "command":"revoke", "actor":"root", "subject":"child", "right":"read", "now":11
        }),
    );
    let error = release(
        &mut authority,
        "parent",
        "revoked-origin",
        "read",
        "group-a",
    )
    .expect_err("revoked origin must invalidate delegated authority");
    assert!(
        error == "unauthorized" || error == "read_fenced",
        "unexpected rejection: {error}"
    );
}
