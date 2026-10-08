//! Entropy-source contract for the real OpenMLS laboratory.
//!
//! A local fake QRNG Open API server stands in for Entropy Core so that the
//! offline gates can prove (a) OpenMLS randomness and laboratory identity keys
//! are drawn from the configured QRNG source and (b) unavailability fails closed
//! without partial membership changes. Live Entropy Core is exercised only by the
//! ignored test at the end, and only when an endpoint is explicitly supplied.

use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use agent_trust::mls::{EntropySource, MlsLab};
use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_qrand::{ApiAuth, QrngClient, QrngConfig, TransportMode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct FakeState {
    unavailable: bool,
    entropy_posts: usize,
    served_blocks: Vec<Vec<u8>>,
    counter: u64,
}

/// Minimal QRNG Open API: `GET /capabilities` and `POST /entropy`. Served bytes
/// are a SHA-256 counter stream: test-only and deliberately non-random, but
/// distinct per block so MLS key-uniqueness checks behave as with real entropy.
struct FakeQrng {
    server: Arc<tiny_http::Server>,
    state: Arc<Mutex<FakeState>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeQrng {
    fn start() -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind fake QRNG"));
        let state = Arc::new(Mutex::new(FakeState::default()));
        let thread = {
            let server = server.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);
                    let (status, payload) = respond(&state, request.method(), request.url(), &body);
                    let header = tiny_http::Header::from_bytes("Content-Type", "application/json")
                        .expect("static header");
                    let _ = request.respond(
                        tiny_http::Response::from_string(payload.to_string())
                            .with_status_code(status)
                            .with_header(header),
                    );
                }
            })
        };
        Self {
            server,
            state,
            thread: Some(thread),
        }
    }

    fn client(&self) -> Arc<QrngClient> {
        let base_url = format!("http://{}", self.server.server_addr());
        Arc::new(
            QrngClient::connect(QrngConfig {
                base_url: base_url.parse().expect("fake QRNG URL"),
                transport: TransportMode::PlainHttp,
                auth: ApiAuth::None,
                entropy_type: None,
                request_timeout: Duration::from_secs(5),
                health_poll_interval: None,
            })
            .expect("connect to fake QRNG"),
        )
    }

    fn set_unavailable(&self, unavailable: bool) {
        self.state.lock().expect("fake state").unavailable = unavailable;
    }

    fn entropy_posts(&self) -> usize {
        self.state.lock().expect("fake state").entropy_posts
    }

    fn served_blocks(&self) -> Vec<Vec<u8>> {
        self.state.lock().expect("fake state").served_blocks.clone()
    }
}

impl Drop for FakeQrng {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(
    state: &Mutex<FakeState>,
    method: &tiny_http::Method,
    url: &str,
    body: &str,
) -> (u16, Value) {
    let mut state = state.lock().expect("fake state");
    match (method, url) {
        (tiny_http::Method::Get, "/capabilities") => (
            200,
            json!({"entropy": {"min_block_size": 1, "max_block_size": 1024,
                               "min_block_count": 1, "max_block_count": 1}}),
        ),
        (tiny_http::Method::Post, "/entropy") => {
            if state.unavailable {
                return (503, json!({"detail": "entropy unavailable"}));
            }
            let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let Some(size) = request["block_size"].as_u64() else {
                return (422, json!({"detail": "block_size required"}));
            };
            let mut block = Vec::with_capacity(size as usize);
            while block.len() < size as usize {
                state.counter += 1;
                block.extend_from_slice(&Sha256::digest(state.counter.to_be_bytes()));
            }
            block.truncate(size as usize);
            state.entropy_posts += 1;
            state.served_blocks.push(block.clone());
            (200, json!({"entropy": [STANDARD.encode(&block)]}))
        }
        _ => (404, json!({"detail": "not found"})),
    }
}

fn ed25519_public(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: [u8; 32] = seed.try_into().ok()?;
    Some(
        ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes()
            .to_vec(),
    )
}

#[test]
fn qrng_source_supplies_openmls_randomness_for_group_operations() {
    // Catches a laboratory that accepts a QRNG source but keeps drawing OpenMLS
    // randomness from the local generator.
    let qrng = FakeQrng::start();
    let mut lab =
        MlsLab::with_entropy(EntropySource::Qrng(qrng.client())).expect("QRNG-backed lab");
    let after_create = qrng.entropy_posts();
    assert!(after_create > 0, "group creation must draw QRNG entropy");

    lab.add_member("bob").expect("bob joins with QRNG entropy");
    let after_add = qrng.entropy_posts();
    assert!(after_add > after_create, "admission must draw QRNG entropy");

    lab.add_member("carol").expect("carol joins");
    lab.remove_member("bob").expect("bob is removed");
    assert!(
        qrng.entropy_posts() > after_add,
        "removal commit with UpdatePath must draw QRNG entropy"
    );

    let wire = lab
        .protect("alice", b"qrng epoch", b"aad")
        .expect("alice protects");
    let (payload, aad) = lab.decrypt("carol", &wire).expect("carol decrypts");
    assert_eq!(payload, b"qrng epoch");
    assert_eq!(aad, b"aad");
    lab.verify_member_admission("carol")
        .expect("staged admission binding still verifies under QRNG");
}

#[test]
fn qrng_source_seeds_member_signature_keys() {
    // Catches identity keys generated by SignatureKeyPair::new (OsRng) while the
    // laboratory claims a QRNG entropy source.
    let qrng = FakeQrng::start();
    let mut lab =
        MlsLab::with_entropy(EntropySource::Qrng(qrng.client())).expect("QRNG-backed lab");
    lab.add_member("bob").expect("bob joins");

    let derived: Vec<Vec<u8>> = qrng
        .served_blocks()
        .iter()
        .filter_map(|block| ed25519_public(block))
        .collect();
    for member in ["alice", "bob"] {
        let key = lab
            .member_signature_key(member)
            .expect("member has a signature key");
        assert!(
            derived.contains(&key),
            "{member}'s signature key must derive from a QRNG-served 32-byte seed"
        );
    }
}

#[test]
fn qrng_unavailable_fails_closed_without_partial_membership() {
    // Catches silent fallback to local randomness and admission that leaves a
    // half-applied membership change when entropy is unavailable; then checks
    // that authorized progress resumes once entropy returns.
    let qrng = FakeQrng::start();
    let mut lab =
        MlsLab::with_entropy(EntropySource::Qrng(qrng.client())).expect("QRNG-backed lab");
    let epoch = lab.epoch();

    qrng.set_unavailable(true);
    let error = lab
        .add_member("bob")
        .expect_err("admission must fail closed while QRNG is unavailable");
    assert!(
        error.contains("Qrng("),
        "the failure must come from the QRNG source, got: {error}"
    );
    assert_eq!(lab.members(), vec!["alice".to_owned()]);
    assert_eq!(
        lab.epoch(),
        epoch,
        "failed admission must not advance the epoch"
    );

    qrng.set_unavailable(false);
    lab.add_member("bob")
        .expect("admission proceeds once QRNG entropy is available again");
    assert_eq!(lab.members(), vec!["alice".to_owned(), "bob".to_owned()]);
    let wire = lab
        .protect("alice", b"resumed", b"")
        .expect("alice protects");
    assert_eq!(
        lab.decrypt("bob", &wire).expect("bob decrypts").0,
        b"resumed"
    );
}

#[test]
fn qrng_unavailable_inside_openmls_commit_leaves_group_unchanged() {
    // Characterization test (written after implementation): removal needs no
    // new signature key, so the outage reaches OpenMLS commit/UpdatePath
    // creation itself. The removal must fail without a half-applied epoch, and
    // the same removal must succeed and exclude the retained copy afterwards.
    let qrng = FakeQrng::start();
    let mut lab =
        MlsLab::with_entropy(EntropySource::Qrng(qrng.client())).expect("QRNG-backed lab");
    lab.add_member("bob").expect("bob joins");
    lab.add_member("carol").expect("carol joins");
    lab.snapshot_member("bob", "revoked-copy")
        .expect("snapshot");
    let epoch = lab.epoch();

    qrng.set_unavailable(true);
    let posts = qrng.entropy_posts();
    let error = lab
        .remove_member("bob")
        .expect_err("removal commit must fail closed while QRNG is unavailable");
    assert!(
        error.contains("InsufficientRandomness"),
        "the failure must come from OpenMLS randomness, got: {error}"
    );
    assert_eq!(qrng.entropy_posts(), posts, "no entropy was served");
    assert_eq!(
        lab.epoch(),
        epoch,
        "failed removal must not advance the epoch"
    );
    assert_eq!(
        lab.members(),
        vec!["alice".to_owned(), "bob".to_owned(), "carol".to_owned()]
    );

    qrng.set_unavailable(false);
    lab.remove_member("bob")
        .expect("removal proceeds once QRNG entropy is available again");
    assert!(lab.epoch() > epoch);
    let wire = lab
        .protect("alice", b"successor", b"")
        .expect("alice protects");
    assert_eq!(
        lab.decrypt("carol", &wire).expect("carol decrypts").0,
        b"successor"
    );
    assert!(lab.decrypt("revoked-copy", &wire).is_err());
}

#[test]
fn qrng_unavailable_blocks_group_creation() {
    // Catches a constructor that falls back to local randomness.
    let qrng = FakeQrng::start();
    let client = qrng.client();
    qrng.set_unavailable(true);

    assert!(
        MlsLab::with_entropy(EntropySource::Qrng(client)).is_err(),
        "group creation must fail closed while QRNG is unavailable"
    );
}

/// Live Entropy Core smoke test. Run only against an endpoint you are
/// authorized to use; do not record the endpoint in evidence:
///
/// `QRNG_LIVE_BASE_URL=http://<host>:<port> cargo test --test mls_entropy -- --ignored`
#[test]
#[ignore = "requires a reachable QRNG Open API endpoint (QRNG_LIVE_BASE_URL)"]
fn live_qrng_removal_excludes_retained_reader() {
    let base_url = std::env::var("QRNG_LIVE_BASE_URL").expect("QRNG_LIVE_BASE_URL is required");
    let client = Arc::new(
        QrngClient::connect(QrngConfig {
            base_url: base_url.parse().expect("QRNG_LIVE_BASE_URL must be a URL"),
            transport: TransportMode::PlainHttp,
            auth: ApiAuth::None,
            entropy_type: None,
            request_timeout: Duration::from_secs(10),
            health_poll_interval: None,
        })
        .expect("connect to live QRNG"),
    );
    let mut lab = MlsLab::with_entropy(EntropySource::Qrng(client.clone())).expect("live lab");
    lab.add_member("bob").expect("bob joins");
    lab.add_member("carol").expect("carol joins");
    lab.snapshot_member("bob", "revoked-copy")
        .expect("snapshot");
    lab.remove_member("bob").expect("bob removed");

    let wire = lab
        .protect("alice", b"live successor", b"")
        .expect("alice protects");
    assert_eq!(
        lab.decrypt("carol", &wire).expect("carol decrypts").0,
        b"live successor"
    );
    assert!(lab.decrypt("revoked-copy", &wire).is_err());
    let metrics = client.metrics_snapshot();
    assert!(metrics.entropy_requests_total > 0);
    assert_eq!(metrics.entropy_failures_total, 0);
    println!(
        "live QRNG: {} entropy requests, {} bytes",
        metrics.entropy_requests_total, metrics.entropy_bytes_total
    );
}
