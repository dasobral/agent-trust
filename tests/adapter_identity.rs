//! Phase 4.1 contract tests: APF key, client identities, signed requests and the
//! trusted clock (`docs/adapter-contract.md` §4.8, §4.9 C-1 to C-6, §7, §8).
//!
//! The tests use only the public adapter API, the files it creates and the kernel
//! checkpoint it returns. Every negative case runs after the matching positive path in
//! the same test, so an adapter that rejects everything cannot pass.

mod common;

use agent_trust::adapter::{
    Adapter, ClientIdentity, SignedRequest, ADAPTER_FILE, APF_KEY_FILE, AUTHORITY_FILE,
    REQUEST_LABEL,
};
use common::{
    adapter_dir, code, contains, dalek_public, files_in, independent_tbs, lower_hex,
    scripted_provider, sign, DalekSigner, FailingRand, FixedClock, ScriptedRand, TestProvider,
    TEST_REQUEST_LABEL,
};
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::SignatureScheme;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const GROUP: &str = "group-a";
const ROOT: &str = "root";
/// Deterministic test-only seed for the root's request key. Not a real key.
const ROOT_SEED: [u8; 32] = [0x11; 32];

type TestAdapter = Adapter<TestProvider<ScriptedRand>, FixedClock>;

struct Fixture {
    dir: tempfile::TempDir,
    adapter: TestAdapter,
    rand: ScriptedRand,
    clock: FixedClock,
    root: DalekSigner,
}

fn setup(rand_seed: &[u8], now: u64) -> Fixture {
    let dir = adapter_dir();
    let (provider, rand) = scripted_provider(rand_seed);
    let clock = FixedClock::new(now);
    let root = DalekSigner::from_seed(ROOT_SEED);
    let adapter = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        clock.clone(),
    )
    .expect("adapter create should succeed");
    Fixture {
        dir,
        adapter,
        rand,
        clock,
        root,
    }
}

fn reopen(dir: &Path, rand_seed: &[u8], clock: FixedClock) -> TestAdapter {
    let (provider, _) = scripted_provider(rand_seed);
    Adapter::open(dir, provider, clock).expect("adapter open should succeed")
}

/// A fresh client identity from its own deterministic rand.
fn identity(seed: &[u8]) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(seed)).expect("client identity generation")
}

fn checkpoint(adapter: &mut TestAdapter) -> Value {
    adapter.checkpoint().expect("checkpoint should succeed")
}

fn accept(adapter: &mut TestAdapter, request: &SignedRequest) -> Value {
    let trace_len = adapter.trace().len();
    let response = adapter.handle(request).unwrap_or_else(|err| {
        panic!(
            "request {}#{} should be accepted, got {err}",
            request.actor, request.sequence
        )
    });
    let trace = adapter.trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!("ok"));
    response
}

/// Asserts the error code, an unchanged kernel checkpoint and one trace event whose
/// outcome is that code.
fn reject(adapter: &mut TestAdapter, request: &SignedRequest, expected: &str) -> String {
    let before = checkpoint(adapter);
    let trace_len = adapter.trace().len();
    let err = code(adapter.handle(request), expected);
    assert_eq!(
        checkpoint(adapter),
        before,
        "rejected request ({err}) must leave the kernel unchanged"
    );
    let trace = adapter.trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!(expected));
    err
}

fn has_grant(checkpoint: &Value, subject: &str, right: &str, generation: u64) -> bool {
    checkpoint["grants"]
        .as_array()
        .expect("grants array")
        .iter()
        .any(|g| {
            g["subject"] == json!(subject)
                && g["right"] == json!(right)
                && g["generation"] == json!(generation)
                && g["active"] == json!(true)
        })
}

fn last_history_event(checkpoint: &Value) -> Value {
    checkpoint["history"]
        .as_array()
        .and_then(|h| h.last())
        .map(|entry| entry["event"].clone())
        .expect("history entry")
}

fn assert_trace_event(event: &Value, actor: &str, sequence: u64, command: &str, outcome: &str) {
    assert_eq!(event["actor"], json!(actor), "trace actor in {event}");
    assert_eq!(
        event["sequence"],
        json!(sequence),
        "trace sequence in {event}"
    );
    assert_eq!(event["command"], json!(command), "trace command in {event}");
    assert_eq!(event["outcome"], json!(outcome), "trace outcome in {event}");
}

fn grant_new(subject: &str, right: &str, key: &[u8]) -> Value {
    json!({
        "command":"grant", "subject":subject, "right":right, "generation":0,
        "fresh_keys":true, "subject_key":lower_hex(key)
    })
}

fn grant_known(subject: &str, right: &str, generation: u64) -> Value {
    json!({
        "command":"grant", "subject":subject, "right":right, "generation":generation,
        "fresh_keys":true
    })
}

fn delegate(subject: &str, rights: &[&str], expires_at: u64, key: &[u8]) -> Value {
    json!({
        "command":"delegate", "subject":subject, "rights":rights, "resources":[GROUP],
        "expires_at":expires_at, "not_before":0, "depth":1, "subject_key":lower_hex(key)
    })
}

fn allocate(op: &str) -> Value {
    json!({"command":"allocate", "op":op})
}

fn verify(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    RustCrypto::default()
        .verify_signature(SignatureScheme::ED25519, data, public_key, signature)
        .is_ok()
}

/// A request whose body bytes are given verbatim, signed over the independent encoding.
fn sign_raw(signer: &impl Signer, actor: &str, sequence: u64, body: &[u8]) -> SignedRequest {
    SignedRequest {
        actor: actor.to_owned(),
        sequence,
        body: body.to_vec(),
        signature: signer
            .sign(&independent_tbs(GROUP, actor, sequence, body))
            .expect("test signature"),
    }
}

#[test]
fn apf_key_is_drawn_from_provider_rand() {
    let f = setup(b"apf-key-draw-a", 10);
    let draws = f.rand.draws();
    assert_eq!(draws.len(), 1, "create draws exactly one seed: {draws:?}");
    assert_eq!(draws[0].len, 32, "the APF seed draw is exactly 32 bytes");
    assert_eq!(draws[0].bytes.len(), 32);
    let expected_public = dalek_public(&draws[0].bytes);
    assert_eq!(f.adapter.apf_public_key(), expected_public.as_slice());
    assert_eq!(f.adapter.apf_public_key().len(), 32);
    assert_eq!(
        f.adapter.apf_key_id(),
        Sha256::digest(&expected_public).to_vec(),
        "apf_key_id = SHA-256(APF public key)"
    );
    assert_ne!(f.adapter.apf_public_key(), f.root.public_key().as_slice());

    // A different rand stream yields a different key, again equal to its own draw.
    let other = setup(b"apf-key-draw-b", 10);
    let other_draws = other.rand.draws();
    assert_eq!(other_draws.len(), 1);
    assert_eq!(other_draws[0].len, 32);
    assert_eq!(
        other.adapter.apf_public_key(),
        dalek_public(&other_draws[0].bytes).as_slice()
    );
    assert_ne!(other.adapter.apf_public_key(), f.adapter.apf_public_key());
    assert_ne!(other.adapter.apf_key_id(), f.adapter.apf_key_id());
}

#[test]
fn apf_private_key_never_appears_in_kernel_database_or_trace() {
    let mut f = setup(b"apf-key-secrecy", 10);
    let seed = f.rand.draws()[0].bytes.clone();
    assert_eq!(seed.len(), 32);
    let alice = identity(b"secrecy-alice");

    // Accepted and rejected requests.
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            1,
            &grant_new("alice", "read", alice.public_key()),
        ),
    );
    accept(
        &mut f.adapter,
        &sign(alice.signer(), GROUP, "alice", 1, &allocate("op-1")),
    );
    let mut bad = sign(&f.root, GROUP, ROOT, 2, &grant_known("alice", "write", 0));
    bad.signature[0] ^= 0x01;
    reject(&mut f.adapter, &bad, "unauthenticated");
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 2, &json!({"command":"frobnicate"})),
        "malformed",
    );
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 3, &grant_known("alice", "write", 5)),
        "invalid_generation",
    );
    accept(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 4, &grant_known("alice", "write", 0)),
    );

    let needles = [
        seed.clone(),
        lower_hex(&seed).into_bytes(),
        lower_hex(&seed).to_uppercase().into_bytes(),
    ];
    let scan = |dir: &Path, stage: &str| {
        let files = files_in(dir);
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert!(names.contains(&AUTHORITY_FILE), "{stage}: files {names:?}");
        assert!(names.contains(&ADAPTER_FILE), "{stage}: files {names:?}");
        assert!(names.contains(&APF_KEY_FILE), "{stage}: files {names:?}");
        for (name, bytes) in &files {
            if name == APF_KEY_FILE {
                continue;
            }
            for needle in &needles {
                assert!(
                    !contains(bytes, needle),
                    "{stage}: APF seed found in {name}"
                );
            }
        }
    };

    // While the adapter is open (WAL and SHM siblings may exist) ...
    scan(f.dir.path(), "open adapter");
    let trace = serde_json::to_vec(&f.adapter.trace()).expect("trace JSON");
    assert!(!f.adapter.trace().is_empty());
    let snapshot = serde_json::to_vec(&checkpoint(&mut f.adapter)).expect("checkpoint JSON");
    for needle in &needles {
        assert!(!contains(&trace, needle), "APF seed found in the trace");
        assert!(
            !contains(&snapshot, needle),
            "APF seed found in the checkpoint"
        );
    }

    // The key file holds exactly the seed, owner-only.
    let key_path = f.dir.path().join(APF_KEY_FILE);
    assert_eq!(std::fs::read(&key_path).expect("APF key file"), seed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path)
            .expect("APF key metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "APF key file mode is {:o}",
            mode & 0o777
        );
    }

    // ... and after it is closed.
    let public = f.adapter.apf_public_key().to_vec();
    let key_id = f.adapter.apf_key_id();
    let Fixture {
        dir,
        adapter,
        clock,
        ..
    } = f;
    drop(adapter);
    scan(dir.path(), "closed adapter");

    // Reopening yields the same APF key.
    let reopened = reopen(dir.path(), b"apf-key-secrecy-reopen", clock.clone());
    assert_eq!(reopened.apf_public_key(), public.as_slice());
    assert_eq!(reopened.apf_key_id(), key_id);
    drop(reopened);

    // `create` on an existing adapter directory fails and keeps the key.
    let (provider, _) = scripted_provider(b"apf-key-secrecy-second-create");
    let root = DalekSigner::from_seed(ROOT_SEED);
    let second = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        clock.clone(),
    );
    assert!(second.is_err(), "create on an existing directory must fail");
    drop(second);
    assert_eq!(std::fs::read(&key_path).expect("APF key file"), seed);
    let again = reopen(dir.path(), b"apf-key-secrecy-reopen-2", clock.clone());
    assert_eq!(again.apf_public_key(), public.as_slice());
    drop(again);

    // `create` also fails if only one of the three files already exists.
    let partial = adapter_dir();
    let placeholder = vec![0x5a; 32];
    std::fs::write(partial.path().join(APF_KEY_FILE), &placeholder).expect("placeholder");
    let (provider, _) = scripted_provider(b"apf-key-secrecy-partial");
    let result = Adapter::create(
        partial.path(),
        GROUP,
        ROOT,
        &root.public_key(),
        provider,
        clock,
    );
    assert!(
        result.is_err(),
        "create must not overwrite an existing APF key file"
    );
    drop(result);
    assert_eq!(
        std::fs::read(partial.path().join(APF_KEY_FILE)).expect("placeholder"),
        placeholder
    );
}

#[test]
fn client_signature_key_derives_from_provider_rand_seed() {
    let rand = ScriptedRand::new(b"client-key-derivation");
    let client = ClientIdentity::generate(&rand).expect("client identity generation");
    let draws = rand.draws();
    assert_eq!(draws.len(), 1, "generate draws exactly one seed: {draws:?}");
    assert_eq!(draws[0].len, 32);
    let seed: [u8; 32] = draws[0].bytes.as_slice().try_into().expect("32-byte seed");
    assert_eq!(client.public_key(), dalek_public(&seed).as_slice());
    assert_eq!(client.signer().public(), client.public_key());
    assert_eq!(client.signer().signature_scheme(), SignatureScheme::ED25519);

    let message = b"agent-trust phase 4.1 test message";
    let signature = client.signer().sign(message).expect("client signature");
    assert!(verify(client.public_key(), message, &signature));
    assert!(!verify(client.public_key(), b"another message", &signature));
    assert_eq!(
        signature,
        DalekSigner::from_seed(seed)
            .sign(message)
            .expect("dalek signature"),
        "Ed25519 signature equals ed25519-dalek over the same seed and bytes"
    );

    // A second identity takes the next draw and differs.
    let second = ClientIdentity::generate(&rand).expect("second identity");
    let draws = rand.draws();
    assert_eq!(draws.len(), 2);
    assert_eq!(draws[1].len, 32);
    assert_eq!(
        second.public_key(),
        dalek_public(&draws[1].bytes).as_slice()
    );
    assert_ne!(second.public_key(), client.public_key());

    // Positive adapter path: a working provider creates the adapter and its key.
    let good = adapter_dir();
    let (provider, _) = scripted_provider(b"client-key-good-adapter");
    let created = Adapter::create(
        good.path(),
        GROUP,
        ROOT,
        client.public_key(),
        provider,
        FixedClock::new(10),
    );
    assert!(created.is_ok(), "create with working rand should succeed");
    drop(created);
    assert!(good.path().join(APF_KEY_FILE).exists());

    // Failing rand: no identity, no adapter, nothing created.
    code(
        ClientIdentity::generate(&FailingRand),
        "entropy_unavailable",
    );
    let dir = adapter_dir();
    code(
        Adapter::create(
            dir.path(),
            GROUP,
            ROOT,
            client.public_key(),
            TestProvider::new(FailingRand),
            FixedClock::new(10),
        ),
        "entropy_unavailable",
    );
    for file in [APF_KEY_FILE, AUTHORITY_FILE, ADAPTER_FILE] {
        assert!(
            !dir.path().join(file).exists(),
            "{file} must not exist after entropy failure"
        );
    }
    // The failed attempt left nothing behind that would block a later create.
    let (provider, _) = scripted_provider(b"client-key-after-failure");
    let retry = Adapter::create(
        dir.path(),
        GROUP,
        ROOT,
        client.public_key(),
        provider,
        FixedClock::new(10),
    );
    assert!(
        retry.is_ok(),
        "create after an entropy failure should succeed"
    );
}

#[test]
fn valid_signed_request_reaches_kernel() {
    // Hand-built bytes pin the independent encoder first.
    // Opaque vectors shorter than 64 bytes have a one-byte QUIC length prefix.
    let manual = [
        vec![22],
        b"agent-trust/request/v1".to_vec(),
        vec![1],
        b"g".to_vec(),
        vec![4],
        b"root".to_vec(),
        0x0102_0304_0506_0708u64.to_be_bytes().to_vec(),
        vec![2],
        b"{}".to_vec(),
    ]
    .concat();
    assert_eq!(
        independent_tbs("g", "root", 0x0102_0304_0506_0708, b"{}"),
        manual
    );
    // The adapter's TBS equals the independent encoding.
    assert_eq!(REQUEST_LABEL, TEST_REQUEST_LABEL);
    let long_body = vec![b'x'; 300];
    let cases: [(&str, &str, u64, &[u8]); 4] = [
        (GROUP, ROOT, 1, b"{\"command\":\"allocate\",\"op\":\"x\"}"),
        ("g", "a", u64::MAX, b""),
        ("group-\u{e9}", "actor-\u{3bb}", 42, b"{}"),
        (GROUP, "child", 7, &long_body),
    ];
    for (group, actor, sequence, body) in cases {
        assert_eq!(
            SignedRequest::to_be_signed(group, actor, sequence, body).expect("to_be_signed"),
            independent_tbs(group, actor, sequence, body),
            "RequestTBS for {group}/{actor}/{sequence}"
        );
    }
    assert_eq!(
        SignedRequest::to_be_signed("g", "root", 0x0102_0304_0506_0708, b"{}")
            .expect("to_be_signed"),
        manual
    );

    let mut f = setup(b"valid-request", 10);
    let alice = identity(b"valid-alice");
    let child = identity(b"valid-child");
    let before = checkpoint(&mut f.adapter);
    assert_eq!(before["group"], json!(GROUP));
    assert_eq!(before["roster"], json!([ROOT]));
    let policy_before = before["policy_revision"].as_u64().expect("policy_revision");

    // Root requests signed with ed25519-dalek over the independent encoding.
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            1,
            &grant_new("alice", "read", alice.public_key()),
        ),
    );
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            2,
            &delegate("child", &["read", "write"], 1000, child.public_key()),
        ),
    );
    let after = checkpoint(&mut f.adapter);
    assert!(has_grant(&after, "alice", "read", 0), "{after}");
    assert!(has_grant(&after, "child", "read", 0), "{after}");
    assert!(has_grant(&after, "child", "write", 0), "{after}");
    assert_eq!(after["policy_revision"], json!(policy_before + 2));
    let delegations = last_history_event(&after)["snapshot"]["delegations"].clone();
    assert!(
        delegations
            .as_array()
            .expect("delegations")
            .iter()
            .any(|d| d["subject"] == json!("child") && d["parent"] == json!(ROOT)),
        "the adapter filled the authenticated actor as parent: {delegations}"
    );

    // The child authenticates with its own key, signed through the adapter API.
    let body = allocate("op-1");
    let request =
        SignedRequest::sign(GROUP, "child", 1, &body, child.signer()).expect("SignedRequest::sign");
    assert_eq!(request.actor, "child");
    assert_eq!(request.sequence, 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&request.body).expect("body JSON"),
        body
    );
    assert!(verify(
        child.public_key(),
        &independent_tbs(GROUP, "child", 1, &request.body),
        &request.signature
    ));
    let response = accept(&mut f.adapter, &request);
    assert_eq!(response["op"], json!("op-1"));
    let operations =
        last_history_event(&checkpoint(&mut f.adapter))["snapshot"]["operations"].clone();
    assert!(
        operations
            .as_array()
            .expect("operations")
            .iter()
            .any(|o| o["op"] == json!("op-1") && o["actor"] == json!("child")),
        "the kernel saw the authenticated actor: {operations}"
    );

    // The grant-created subject also authenticates with its own key.
    let response = accept(
        &mut f.adapter,
        &sign(alice.signer(), GROUP, "alice", 1, &allocate("op-2")),
    );
    assert_eq!(response["op"], json!("op-2"));

    let trace = f.adapter.trace();
    assert_eq!(trace.len(), 4, "{trace:?}");
    assert_trace_event(&trace[0], ROOT, 1, "grant", "ok");
    assert_trace_event(&trace[1], ROOT, 2, "delegate", "ok");
    assert_trace_event(&trace[2], "child", 1, "allocate", "ok");
    assert_trace_event(&trace[3], "alice", 1, "allocate", "ok");
}

#[test]
fn bad_signature_is_unauthenticated_and_kernel_unchanged() {
    let mut f = setup(b"bad-signature", 10);
    let alice = identity(b"bad-signature-alice");
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            1,
            &grant_new("alice", "read", alice.public_key()),
        ),
    );

    let body = grant_known("alice", "write", 0);
    let valid = sign(&f.root, GROUP, ROOT, 2, &body);

    let mut flipped = valid.clone();
    flipped.signature[0] ^= 0x01;
    reject(&mut f.adapter, &flipped, "unauthenticated");

    let mut flipped_last = valid.clone();
    let last = flipped_last.signature.len() - 1;
    flipped_last.signature[last] ^= 0x80;
    reject(&mut f.adapter, &flipped_last, "unauthenticated");

    let mut truncated = valid.clone();
    truncated.signature.truncate(63);
    reject(&mut f.adapter, &truncated, "unauthenticated");

    let mut empty = valid.clone();
    empty.signature.clear();
    reject(&mut f.adapter, &empty, "unauthenticated");

    let stranger = DalekSigner::from_seed([0x22; 32]);
    reject(
        &mut f.adapter,
        &sign(&stranger, GROUP, ROOT, 2, &body),
        "unauthenticated",
    );
    // Another registered actor's key does not authenticate as root.
    reject(
        &mut f.adapter,
        &sign(alice.signer(), GROUP, ROOT, 2, &body),
        "unauthenticated",
    );

    let mut modified = valid.clone();
    modified.body = serde_json::to_vec(&grant_known("alice", "admin", 0)).expect("JSON");
    reject(&mut f.adapter, &modified, "unauthenticated");

    let mut resequenced = valid.clone();
    resequenced.sequence = 3;
    reject(&mut f.adapter, &resequenced, "unauthenticated");

    reject(
        &mut f.adapter,
        &sign(&f.root, "group-b", ROOT, 2, &body),
        "unauthenticated",
    );

    // C-4: none of the rejected requests consumed sequence 2.
    accept(&mut f.adapter, &valid);
    let after = checkpoint(&mut f.adapter);
    assert!(has_grant(&after, "alice", "write", 0), "{after}");
    assert!(!has_grant(&after, "alice", "admin", 0), "{after}");
}

#[test]
fn replayed_or_decreasing_sequence_is_unauthenticated() {
    let mut f = setup(b"sequence", 10);
    let alice = identity(b"sequence-alice");
    let child = identity(b"sequence-child");

    let first = sign(
        &f.root,
        GROUP,
        ROOT,
        1,
        &grant_new("alice", "read", alice.public_key()),
    );
    accept(&mut f.adapter, &first);
    reject(&mut f.adapter, &first, "unauthenticated");

    // Gaps are allowed; a lower sequence is not.
    accept(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 5, &grant_known("alice", "write", 0)),
    );
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 3, &grant_known("alice", "admin", 0)),
        "unauthenticated",
    );
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 5, &grant_known("alice", "admin", 0)),
        "unauthenticated",
    );

    // A sequence whose request the kernel rejects is still consumed.
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 6, &grant_known("alice", "admin", 1)),
        "invalid_generation",
    );
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 6, &grant_known("alice", "admin", 0)),
        "unauthenticated",
    );
    accept(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 7, &grant_known("alice", "admin", 0)),
    );

    // A sequence whose body is malformed is still consumed.
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 8, &json!({"command":"frobnicate"})),
        "malformed",
    );
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, 8, &grant_known("alice", "admit", 0)),
        "unauthenticated",
    );
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            9,
            &delegate("child", &["read"], 1000, child.public_key()),
        ),
    );

    // Sequences are independent per actor.
    let child_first = sign(child.signer(), GROUP, "child", 1, &allocate("child-op-1"));
    accept(&mut f.adapter, &child_first);
    reject(&mut f.adapter, &child_first, "unauthenticated");
    accept(
        &mut f.adapter,
        &sign(alice.signer(), GROUP, "alice", 1, &allocate("alice-op-1")),
    );

    // Last-accepted sequences survive reopening.
    let Fixture {
        dir,
        adapter,
        clock,
        root,
        ..
    } = f;
    drop(adapter);
    let mut adapter = reopen(dir.path(), b"sequence-reopen", clock);
    reject(
        &mut adapter,
        &sign(&root, GROUP, ROOT, 9, &grant_known("alice", "admit", 0)),
        "unauthenticated",
    );
    reject(
        &mut adapter,
        &sign(child.signer(), GROUP, "child", 1, &allocate("child-op-2")),
        "unauthenticated",
    );
    reject(
        &mut adapter,
        &sign(alice.signer(), GROUP, "alice", 1, &allocate("alice-op-2")),
        "unauthenticated",
    );
    accept(
        &mut adapter,
        &sign(&root, GROUP, ROOT, 10, &grant_known("alice", "admit", 0)),
    );
    accept(
        &mut adapter,
        &sign(child.signer(), GROUP, "child", 2, &allocate("child-op-2")),
    );
    accept(
        &mut adapter,
        &sign(alice.signer(), GROUP, "alice", 2, &allocate("alice-op-2")),
    );
    let after = checkpoint(&mut adapter);
    assert!(has_grant(&after, "alice", "admit", 0), "{after}");
}

#[test]
fn request_body_actor_and_now_fields_cannot_override_adapter_values() {
    let mut f = setup(b"reserved-fields", 50);
    let child = identity(b"reserved-child");
    let invoke =
        json!({"command":"invoke", "executor":ROOT, "rights":["read"], "resources":[GROUP]});

    // Positive paths: the child, delegated until 100, invokes at clock 50.
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            1,
            &delegate("child", &["read"], 100, child.public_key()),
        ),
    );
    let response = accept(
        &mut f.adapter,
        &sign(child.signer(), GROUP, "child", 1, &invoke),
    );
    assert!(response["invocation"].is_string(), "{response}");
    let invocations = checkpoint(&mut f.adapter)["invocations"].clone();
    assert!(
        invocations
            .as_array()
            .expect("invocations")
            .iter()
            .any(|i| i["origin"] == json!("child") && i["executor"] == json!(ROOT)),
        "{invocations}"
    );

    // C-2: `actor` and `now` are reserved.
    let mut seq = 2;
    for body in [
        json!({"command":"grant", "actor":ROOT, "subject":"child", "right":"write",
               "generation":0, "fresh_keys":true}),
        json!({"command":"grant", "now":50, "subject":"child", "right":"write",
               "generation":0, "fresh_keys":true}),
        json!({"command":"grant", "actor":null, "subject":"child", "right":"write",
               "generation":0, "fresh_keys":true}),
    ] {
        reject(
            &mut f.adapter,
            &sign(&f.root, GROUP, ROOT, seq, &body),
            "malformed",
        );
        seq += 1;
    }
    reject(
        &mut f.adapter,
        &sign(
            child.signer(),
            GROUP,
            "child",
            2,
            &json!({"command":"allocate", "op":"forged", "actor":ROOT}),
        ),
        "malformed",
    );

    // The kernel uses the adapter clock; a body `now` is malformed whatever its value.
    f.clock.set(200);
    let mut stale_now = invoke.clone();
    stale_now["now"] = json!(50);
    reject(
        &mut f.adapter,
        &sign(child.signer(), GROUP, "child", 3, &stale_now),
        "malformed",
    );
    // At adapter time 200 the child's delegation (until 100) has expired. R-12 (amendment
    // A-5): the kernel records the expiry in the step's transaction and refuses the
    // invocation, so the kernel changes by exactly that `expire` event.
    let before = checkpoint(&mut f.adapter);
    code(
        f.adapter
            .handle(&sign(child.signer(), GROUP, "child", 4, &invoke)),
        "unauthorized",
    );
    let after = checkpoint(&mut f.adapter);
    assert_eq!(
        after["revision"],
        json!(before["revision"].as_u64().expect("revision") + 1)
    );
    assert_eq!(
        after["history"]
            .as_array()
            .and_then(|history| history.last())
            .map(|entry| entry["event"]["kind"].clone()),
        Some(json!("expire"))
    );
    assert!(after["grants"]
        .as_array()
        .expect("grants")
        .iter()
        .any(|g| g["subject"] == json!("child") && g["active"] == json!(false)));
    // The expiry is a ledger event: moving the clock back does not restore the grant.
    f.clock.set(50);
    reject(
        &mut f.adapter,
        &sign(child.signer(), GROUP, "child", 5, &invoke),
        "unauthorized",
    );

    // C-3: adapter-only commands are unauthorized, even for the root.
    for body in [
        json!({"command":"init", "group":"group-z", "root":"mallory"}),
        json!({"command":"admit", "subject":"child"}),
        json!({"command":"repair", "parent_branch":"genesis", "new_branch":"b1", "epoch":1,
               "revision":0, "removed":[], "update_path":true, "confirmed":true,
               "durable":true}),
        json!({"command":"repair_stage", "parent_branch":"genesis", "new_branch":"b1",
               "epoch":1, "policy_revision":0, "removed":[], "update_path":true,
               "durable":true}),
        json!({"command":"repair_open", "branch":"genesis", "confirmed":true}),
    ] {
        reject(
            &mut f.adapter,
            &sign(&f.root, GROUP, ROOT, seq, &body),
            "unauthorized",
        );
        seq += 1;
    }

    // C-3: commands not yet routed, unknown commands and non-object bodies are malformed.
    for body in [
        json!({"command":"release", "op":"op-1", "right":"write", "policy_revision":0,
               "epoch":0, "branch":"genesis", "digest":"00", "cover":[]}),
        json!({"command":"persist", "op":"op-1", "digest":"00", "envelope":"00"}),
        json!({"command":"emit", "op":"op-1", "envelope":"00"}),
        json!({"command":"consume", "op":"op-1", "recipient":ROOT}),
        json!({"command":"abandon", "op":"op-1"}),
        json!({"command":"frobnicate"}),
        json!({"op":"op-1"}),
        json!(["allocate"]),
    ] {
        reject(
            &mut f.adapter,
            &sign(&f.root, GROUP, ROOT, seq, &body),
            "malformed",
        );
        seq += 1;
    }
    reject(
        &mut f.adapter,
        &sign_raw(&f.root, ROOT, seq, b"not json"),
        "malformed",
    );
    seq += 1;

    // The root still operates normally afterwards.
    accept(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, seq, &grant_known("child", "write", 0)),
    );
    let after = checkpoint(&mut f.adapter);
    assert!(has_grant(&after, "child", "write", 0), "{after}");
}

#[test]
fn unknown_actor_is_unauthenticated() {
    let mut f = setup(b"unknown-actor", 10);
    let alice = identity(b"unknown-alice");
    let bob = identity(b"unknown-bob");
    let carol = identity(b"unknown-carol");
    let mallory = identity(b"unknown-mallory");

    // Positive path: a registered subject authenticates.
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            1,
            &grant_new("alice", "read", alice.public_key()),
        ),
    );
    accept(
        &mut f.adapter,
        &sign(alice.signer(), GROUP, "alice", 1, &allocate("alice-op-1")),
    );

    // Unregistered actors are unauthenticated and traced with a null actor.
    for request in [
        sign(mallory.signer(), GROUP, "mallory", 1, &allocate("m-1")),
        sign(alice.signer(), GROUP, "mallory", 1, &allocate("m-1")),
        sign(&f.root, GROUP, "mallory", 1, &allocate("m-1")),
    ] {
        reject(&mut f.adapter, &request, "unauthenticated");
        let trace = f.adapter.trace();
        let event = trace.last().expect("trace event");
        assert_eq!(event["actor"], Value::Null, "{event}");
        assert_eq!(event["outcome"], json!("unauthenticated"), "{event}");
    }

    // C-1: missing, malformed or unexpected `subject_key`.
    let mut seq = 2;
    let bob_key = lower_hex(bob.public_key());
    let without_key = json!({
        "command":"delegate", "subject":"bob", "rights":["read"], "resources":[GROUP],
        "expires_at":1000, "not_before":0, "depth":1
    });
    let mut malformed_bodies = vec![without_key.clone()];
    for bad_key in [
        json!(lower_hex(&bob.public_key()[..31])),
        json!(format!("{bob_key}00")),
        json!("zz".repeat(32)),
        json!(bob_key.to_uppercase()),
        json!(""),
        json!(42),
        json!(bob.public_key()),
    ] {
        let mut body = without_key.clone();
        body["subject_key"] = bad_key;
        malformed_bodies.push(body);
    }
    // A grant to a known subject must not carry a key; a grant creating one must.
    malformed_bodies.push(grant_new("alice", "write", bob.public_key()));
    malformed_bodies.push(grant_new(ROOT, "read", bob.public_key()));
    malformed_bodies.push(grant_known("dave", "read", 0));
    for body in malformed_bodies {
        let err = reject(
            &mut f.adapter,
            &sign(&f.root, GROUP, ROOT, seq, &body),
            "malformed",
        );
        assert!(err.contains("subject_key"), "{err} for {body}");
        seq += 1;
    }

    // C-1: an already registered key cannot be registered again.
    for body in [
        delegate("bob", &["read"], 1000, alice.public_key()),
        delegate("bob", &["read"], 1000, &f.root.public_key()),
        grant_new("erin", "read", alice.public_key()),
    ] {
        reject(
            &mut f.adapter,
            &sign(&f.root, GROUP, ROOT, seq, &body),
            "binding_mismatch",
        );
        seq += 1;
    }

    // A delegate that the kernel rejects registers nobody.
    let mut too_deep = delegate("carol", &["read"], 1000, carol.public_key());
    too_deep["depth"] = json!(9);
    reject(
        &mut f.adapter,
        &sign(&f.root, GROUP, ROOT, seq, &too_deep),
        "invalid_delegation",
    );
    seq += 1;
    reject(
        &mut f.adapter,
        &sign(carol.signer(), GROUP, "carol", 1, &allocate("carol-op-1")),
        "unauthenticated",
    );

    // Positive paths afterwards: fresh keys register and authenticate.
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            seq,
            &delegate("carol", &["read"], 1000, carol.public_key()),
        ),
    );
    seq += 1;
    accept(
        &mut f.adapter,
        &sign(
            &f.root,
            GROUP,
            ROOT,
            seq,
            &delegate("bob", &["read"], 1000, bob.public_key()),
        ),
    );
    accept(
        &mut f.adapter,
        &sign(carol.signer(), GROUP, "carol", 1, &allocate("carol-op-1")),
    );
    accept(
        &mut f.adapter,
        &sign(bob.signer(), GROUP, "bob", 1, &allocate("bob-op-1")),
    );
    let after = checkpoint(&mut f.adapter);
    assert!(has_grant(&after, "bob", "read", 0), "{after}");
    assert!(has_grant(&after, "carol", "read", 0), "{after}");
    assert!(!has_grant(&after, "erin", "read", 0), "{after}");
    assert!(!has_grant(&after, "dave", "read", 0), "{after}");
}
