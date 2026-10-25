//! Phase 4.6 contract tests: the entropy seam (`docs/adapter-contract.md` §8, C-6, §12).
//!
//! Four things are checked here:
//!
//! - every key the adapter and its clients generate comes from one 32-byte draw of the
//!   configured `OpenMlsRand` (C-6), and the MLS flows draw through the same provider;
//! - a rand that fails makes every operation that needs randomness fail closed, with
//!   `entropy_unavailable` where §8/§12 name it (adapter construction, identity
//!   generation) and "fails, no kernel or adapter mutation" everywhere else;
//! - the adapter and its clients run unchanged on `openmls_qrand::QrngOpenMlsProvider`,
//!   here against a loopback MOCK of the QRNG Open API;
//! - an outage of that mock mid-session fails closed with no other entropy source, and
//!   restoring it restores operation.
//!
//! The mock QRNG server below is a MOCK. It is not an entropy source: its "entropy" is a
//! SHA-256 counter stream, so its output is predictable by design. Nothing in this file
//! makes, or supports, any claim about quantum origin or entropy quality. HPKE
//! encapsulation randomness is DRBG output of the lab crypto provider (§8). The fork's
//! `libcrux_crypto/tests/entropy_source.rs` checks that it comes from the DRBG's source;
//! `tests/lab_entropy.rs` checks that connecting a lab source seeds that provider.
//!
//! `live_entropy_core_gate` is the only test that may reach a real endpoint. It is
//! ignored by default, reads its endpoint only from the environment, and stays an unmet
//! gate until it is executed.

mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use agent_trust::adapter::{Adapter, ClientIdentity, APF_KEY_FILE};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin};
use agent_trust::wire::{operation_digest, Frontier, Right};
use common::{
    adapter_dir, code, dalek_public, lower_hex, sign, Draw, EntropyFailure, FailingRand,
    FixedClock, ScriptedRand, TestProvider,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_qrand::{
    ApiAuth, QrngClient, QrngConfig, QrngError, QrngOpenMlsProvider, QrngRand, TransportMode,
};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tiny_http::{Header, Response, Server};

const GROUP: &str = "g";
const ROOT: &str = "root";
/// Trusted adapter time for every test.
const NOW: u64 = 1_000;
/// Default delegation expiry.
const EXPIRES: u64 = 1_000_000;
/// Content type used by every release.
const CONTENT_TYPE: &[u8] = b"text/plain";
/// C-6 seed length.
const SEED_LEN: usize = 32;

const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];

// ---------------------------------------------------------------------------
// A switchable, recording rand (test-only)
// ---------------------------------------------------------------------------

/// Test-only rand: `ScriptedRand` draws while healthy, and every draw fails while
/// `failing` is set. Clones share state, so a test keeps a handle after the provider
/// has been moved into an adapter or a client.
#[derive(Clone, Debug)]
struct SwitchRand {
    inner: ScriptedRand,
    failing: Arc<AtomicBool>,
    refused: Arc<AtomicU64>,
}

impl SwitchRand {
    fn new(label: &str) -> Self {
        Self {
            inner: ScriptedRand::new(format!("entropy/{label}").as_bytes()),
            failing: Arc::new(AtomicBool::new(false)),
            refused: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Every successful draw so far, in order.
    fn draws(&self) -> Vec<Draw> {
        self.inner.draws()
    }

    fn set_failing(&self, failing: bool) {
        self.failing.store(failing, Ordering::SeqCst);
    }

    /// Number of draws refused while failing.
    fn refused(&self) -> u64 {
        self.refused.load(Ordering::SeqCst)
    }

    fn refuse(&self) -> bool {
        if self.failing.load(Ordering::SeqCst) {
            self.refused.fetch_add(1, Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

impl OpenMlsRand for SwitchRand {
    type Error = EntropyFailure;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        if self.refuse() {
            return Err(EntropyFailure);
        }
        self.inner
            .random_array::<N>()
            .map_err(|never| match never {})
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        if self.refuse() {
            return Err(EntropyFailure);
        }
        self.inner.random_vec(len).map_err(|never| match never {})
    }
}

type SProv = TestProvider<SwitchRand>;

fn switch_provider(label: &str) -> (SProv, SwitchRand) {
    let rand = SwitchRand::new(label);
    (TestProvider::new(rand.clone()), rand)
}

/// The lengths of `draws[from..]`.
fn lengths_since(rand: &SwitchRand, from: usize) -> Vec<usize> {
    rand.draws()[from..].iter().map(|draw| draw.len).collect()
}

/// A C-6 identity drawn from `rand`: exactly one new 32-byte draw, and the public key is
/// the ed25519-dalek public key of exactly those bytes.
fn drawn_identity(rand: &SwitchRand, who: &str) -> ClientIdentity {
    let before = rand.draws().len();
    let identity = ClientIdentity::generate(rand).expect("client identity");
    let draws = rand.draws();
    assert_eq!(
        lengths_since(rand, before),
        vec![SEED_LEN],
        "{who}: identity generation is one 32-byte draw from the configured rand (C-6)"
    );
    assert_eq!(
        identity.public_key(),
        dalek_public(&draws[before].bytes).as_slice(),
        "{who}: identity key is the ed25519-dalek key of the drawn seed (C-6)"
    );
    identity
}

// ---------------------------------------------------------------------------
// MOCK QRNG Open API server (loopback, plain HTTP, test-only)
// ---------------------------------------------------------------------------

/// How the MOCK answers `POST /entropy` while an outage is configured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MockFault {
    /// An HTTP error status with a small JSON error body.
    Status(u16),
    /// HTTP 200 with a body that is not JSON.
    Malformed,
    /// HTTP 200 with one block of the wrong length.
    WrongLength,
    /// HTTP 200 with two blocks instead of one.
    TwoBlocks,
}

/// One request the MOCK received, and what it answered.
#[derive(Clone, Debug)]
struct MockRecord {
    method: String,
    path: String,
    block_size: Option<usize>,
    status: u16,
    /// The exact well-formed entropy block served, if any.
    served: Option<Vec<u8>>,
}

#[derive(Debug, Default)]
struct MockState {
    /// While non-empty, every `POST /entropy` gets the next fault, cyclically.
    faults: Vec<MockFault>,
    next_fault: usize,
    /// Number of well-formed blocks served so far; the mock stream's counter.
    blocks: u64,
    log: Vec<MockRecord>,
}

/// A loopback MOCK of the QRNG Open API (`GET /capabilities`, `POST /entropy`,
/// `GET /healthtest`) on `127.0.0.1` with an OS-assigned port.
///
/// MOCK ONLY: the served bytes are `SHA-256(label || counter || chunk)`, deterministic and
/// predictable. They stand in for an entropy endpoint so the provider's request path and
/// its fail-closed behavior can be tested; they are not random and not quantum.
struct MockQrng {
    server: Arc<Server>,
    state: Arc<Mutex<MockState>>,
    port: u16,
    join: Option<JoinHandle<()>>,
}

const MOCK_MAX_BLOCK: usize = 4096;
const MOCK_LABEL: &[u8] = b"agent-trust/MOCK-qrng-stream/v1";

impl MockQrng {
    fn start() -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("bind the mock QRNG on 127.0.0.1:0");
        let port = listener.local_addr().expect("mock local address").port();
        let server =
            Arc::new(Server::from_listener(listener, None).expect("mock QRNG tiny_http server"));
        let state = Arc::new(Mutex::new(MockState::default()));
        let (server_thread, state_thread) = (Arc::clone(&server), Arc::clone(&state));
        let join = thread::Builder::new()
            .name("mock-qrng".into())
            .spawn(move || mock_serve(&server_thread, &state_thread))
            .expect("spawn the mock QRNG thread");
        Self {
            server,
            state,
            port,
            join: Some(join),
        }
    }

    fn origin(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Starts an outage: every entropy request gets the next of `faults`, cyclically.
    fn set_outage(&self, faults: &[MockFault]) {
        let mut state = self.state.lock().expect("mock state");
        state.faults = faults.to_vec();
        state.next_fault = 0;
    }

    /// Ends the outage.
    fn restore(&self) {
        self.state.lock().expect("mock state").faults.clear();
    }

    fn log(&self) -> Vec<MockRecord> {
        self.state.lock().expect("mock state").log.clone()
    }

    /// The entropy requests in `log()[from..]`.
    fn entropy_since(&self, from: usize) -> Vec<MockRecord> {
        self.log()[from..]
            .iter()
            .filter(|record| record.method == "POST" && record.path == "/entropy")
            .cloned()
            .collect()
    }

    /// A plain-HTTP provider configuration for this mock.
    fn config(&self) -> QrngConfig {
        QrngConfig {
            base_url: self.origin().parse().expect("mock base URL"),
            transport: TransportMode::PlainHttp,
            auth: ApiAuth::None,
            entropy_type: None,
            request_timeout: Duration::from_secs(10),
            health_poll_interval: None,
            key_exchange: openmls_qrand::KeyExchange::default(),
        }
    }

    fn connect(&self) -> Arc<QrngClient> {
        Arc::new(QrngClient::connect(self.config()).expect("connect to the mock QRNG"))
    }
}

impl Drop for MockQrng {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

/// `block_size` bytes of the MOCK stream for block number `counter`.
fn mock_block(counter: u64, block_size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(block_size);
    let mut chunk = 0u64;
    while out.len() < block_size {
        let mut hasher = Sha256::new();
        hasher.update(MOCK_LABEL);
        hasher.update(counter.to_be_bytes());
        hasher.update(chunk.to_be_bytes());
        out.extend_from_slice(&hasher.finalize());
        chunk += 1;
    }
    out.truncate(block_size);
    out
}

/// Standard base64 with padding (the QRNG Open API's block encoding).
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn mock_serve(server: &Server, state: &Mutex<MockState>) {
    while let Ok(mut request) = server.recv() {
        let method = request.method().to_string();
        let url = request.url().to_string();
        let path = url.split('?').next().unwrap_or("").to_owned();
        let mut body = Vec::new();
        let _ = request.as_reader().read_to_end(&mut body);

        let mut state = state.lock().expect("mock state");
        let mut record = MockRecord {
            method: method.clone(),
            path: path.clone(),
            block_size: None,
            status: 200,
            served: None,
        };
        let response_body: Vec<u8> = match (method.as_str(), path.as_str()) {
            ("GET", "/capabilities") => json!({
                "entropy": {
                    "min_block_size": 1, "max_block_size": MOCK_MAX_BLOCK,
                    "min_block_count": 1, "max_block_count": 1,
                    "entropy_types": [], "extensions": [{"mock": true}]
                },
                "healthtest": {"mock": true},
                "source_count": 1,
                "extensions": [{"mock": "agent-trust test mock, not an entropy source"}]
            })
            .to_string()
            .into_bytes(),
            ("GET", "/healthtest") => json!({
                "test_result": [], "extensions": [{"mock": true}]
            })
            .to_string()
            .into_bytes(),
            ("POST", "/entropy") => {
                let parsed: Option<Value> = serde_json::from_slice(&body).ok();
                let block_size = parsed
                    .as_ref()
                    .and_then(|v| v["block_size"].as_u64())
                    .map(|n| n as usize);
                let block_count = parsed.as_ref().and_then(|v| v["block_count"].as_u64());
                record.block_size = block_size;
                match block_size {
                    Some(n) if (1..=MOCK_MAX_BLOCK).contains(&n) && block_count == Some(1) => {
                        if state.faults.is_empty() {
                            let block = mock_block(state.blocks, n);
                            state.blocks += 1;
                            record.served = Some(block.clone());
                            json!({"entropy": [base64(&block)], "extensions": [{"mock": true}]})
                                .to_string()
                                .into_bytes()
                        } else {
                            let fault = state.faults[state.next_fault % state.faults.len()];
                            state.next_fault += 1;
                            match fault {
                                MockFault::Status(status) => {
                                    record.status = status;
                                    br#"{"error":"mock outage"}"#.to_vec()
                                }
                                MockFault::Malformed => b"mock outage: not json".to_vec(),
                                MockFault::WrongLength => {
                                    json!({"entropy": [base64(&vec![0u8; n + 1])]})
                                        .to_string()
                                        .into_bytes()
                                }
                                MockFault::TwoBlocks => {
                                    let one = base64(&vec![0u8; n]);
                                    json!({"entropy": [one.clone(), one]})
                                        .to_string()
                                        .into_bytes()
                                }
                            }
                        }
                    }
                    _ => {
                        record.status = 422;
                        br#"{"error":"mock: invalid request"}"#.to_vec()
                    }
                }
            }
            _ => {
                record.status = 404;
                Vec::new()
            }
        };
        let status = record.status;
        state.log.push(record);
        drop(state);
        let header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("content-type header");
        let _ = request.respond(
            Response::from_data(response_body)
                .with_status_code(status)
                .with_header(header),
        );
    }
}

type QProv = QrngOpenMlsProvider<RustCrypto, MemoryStorage>;

fn qrng_provider(client: &Arc<QrngClient>) -> QProv {
    QrngOpenMlsProvider::new(
        RustCrypto::default(),
        MemoryStorage::default(),
        QrngRand::new(Arc::clone(client)),
    )
}

// ---------------------------------------------------------------------------
// A provider-generic test world
// ---------------------------------------------------------------------------

struct World<P: OpenMlsProvider> {
    dir: tempfile::TempDir,
    adapter: Adapter<P, FixedClock>,
    apf_public: Vec<u8>,
    seqs: HashMap<String, u64>,
    /// Each subject's registered request key: the signer of its own `ClientIdentity`.
    signers: HashMap<String, SignatureKeyPair>,
}

/// A release accepted by the adapter.
struct Released {
    op: String,
    actor: String,
    payload: Vec<u8>,
    certificate: Vec<u8>,
}

/// Kernel checkpoint, adapter frontier and trace length: the state a failed
/// client-side operation must leave unchanged.
type Snapshot = (Value, Frontier, usize);

/// Full genesis (§5.1) with the given providers and root identity.
fn genesis<P: OpenMlsProvider>(
    adapter_provider: P,
    root_identity: ClientIdentity,
    root_provider: P,
) -> (World<P>, ClientEndpoint<P>) {
    let dir = adapter_dir();
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity.public_key(),
        adapter_provider,
        FixedClock::new(NOW),
    )
    .expect("begin_genesis");
    let apf_public = pending.apf_public_key().to_vec();
    let founder_certificate = pending.founder_certificate().to_vec();
    let apf_anchor = pending.apf_anchor().to_vec();
    let root_signer = root_identity.signer().clone();
    let root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        root_provider,
        &founder_certificate,
        &apf_anchor,
        &apf_public,
    )
    .expect("root founds the group");
    let group_info = root.export_group_info().expect("export GroupInfo");
    let ratchet_tree = root.export_ratchet_tree().expect("export ratchet tree");
    let adapter = pending
        .complete(&group_info, &ratchet_tree)
        .expect("genesis completes");
    let mut signers = HashMap::new();
    signers.insert(ROOT.to_owned(), root_signer);
    (
        World {
            dir,
            adapter,
            apf_public,
            seqs: HashMap::new(),
            signers,
        },
        root,
    )
}

impl<P: OpenMlsProvider> World<P> {
    fn send(&mut self, actor: &str, body: &Value) -> Result<Value, String> {
        let sequence = self.seqs.entry(actor.to_owned()).or_insert(0);
        *sequence += 1;
        let signer = self
            .signers
            .get(actor)
            .unwrap_or_else(|| panic!("{actor} has a registered key"));
        let request = sign(signer, GROUP, actor, *sequence, body);
        self.adapter.handle(&request)
    }

    fn ok(&mut self, actor: &str, body: &Value) -> Value {
        self.send(actor, body)
            .unwrap_or_else(|err| panic!("{actor} request {body} should succeed, got {err}"))
    }

    fn checkpoint(&mut self) -> Value {
        self.adapter.checkpoint().expect("checkpoint")
    }

    fn frontier(&mut self) -> Frontier {
        self.adapter.frontier().expect("adapter frontier")
    }

    fn snapshot(&mut self) -> Snapshot {
        (
            self.checkpoint(),
            self.frontier(),
            self.adapter.trace().len(),
        )
    }

    fn assert_unchanged(&mut self, before: &Snapshot, what: &str) {
        assert_eq!(
            &self.checkpoint(),
            &before.0,
            "{what}: kernel checkpoint must be unchanged"
        );
        assert_eq!(
            &self.frontier(),
            &before.1,
            "{what}: adapter frontier must be unchanged"
        );
        assert_eq!(
            self.adapter.trace().len(),
            before.2,
            "{what}: adapter trace must be unchanged"
        );
    }

    /// `delegate` from the root with the subject's own key (C-1).
    fn delegate(&mut self, subject: &str, identity: &ClientIdentity, rights: &[&str]) {
        let body = json!({
            "command":"delegate", "subject":subject, "rights":rights, "resources":[GROUP],
            "expires_at":EXPIRES, "not_before":0, "depth":4,
            "subject_key":lower_hex(identity.public_key())
        });
        self.ok(ROOT, &body);
        self.signers
            .insert(subject.to_owned(), identity.signer().clone());
    }

    fn revoke(&mut self, subject: &str, right: &str) {
        self.ok(
            ROOT,
            &json!({"command":"revoke", "subject":subject, "right":right}),
        );
    }

    /// The subject's active kernel rights and generations, sorted by right code.
    fn rights_of(&mut self, subject: &str) -> Vec<(Right, u64)> {
        let checkpoint = self.checkpoint();
        let mut rights: Vec<(Right, u64)> = checkpoint["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .filter(|g| g["subject"] == json!(subject) && g["active"] == json!(true))
            .map(|g| {
                (
                    Right::from_name(g["right"].as_str().expect("right")).expect("known right"),
                    g["generation"].as_u64().expect("generation"),
                )
            })
            .collect();
        rights.sort();
        rights
    }

    fn active_generation(&mut self, subject: &str, right: &str) -> u64 {
        self.checkpoint()["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .find(|g| {
                g["subject"] == json!(subject)
                    && g["right"] == json!(right)
                    && g["active"] == json!(true)
            })
            .and_then(|g| g["generation"].as_u64())
            .unwrap_or_else(|| panic!("{subject} has an active {right} grant"))
    }

    /// Honest KeyPackage preparation at the subject's current rights.
    fn prepare(&mut self, subject: &str, identity: ClientIdentity, provider: P) -> PreparedJoin<P> {
        let rights = self.rights_of(subject);
        PreparedJoin::prepare(
            GROUP,
            subject,
            &rights,
            identity,
            provider,
            &self.apf_public,
        )
        .unwrap_or_else(|err| panic!("{subject} prepares its KeyPackage, got {err}"))
    }

    /// Certifies and finalizes a prepared KeyPackage.
    fn certify(&mut self, subject: &str, prepared: PreparedJoin<P>) -> JoinCandidate<P> {
        let body = json!({
            "command":"admission_certificate",
            "key_package_preimage":lower_hex(prepared.preimage())
        });
        let response = self.ok(subject, &body);
        let certificate = hex::decode(
            response["certificate"]
                .as_str()
                .expect("certificate hex string"),
        )
        .expect("certificate is hex");
        prepared
            .finalize(&certificate)
            .expect("finalize KeyPackage")
    }

    /// `submit_commit` of `kind`; returns the successor frontier and the ack.
    fn submit(
        &mut self,
        actor: &str,
        kind: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> (Frontier, Vec<u8>) {
        let body = json!({
            "command":"submit_commit", "kind":kind, "parent_epoch":parent.epoch,
            "parent_branch":parent.branch, "commit":lower_hex(commit)
        });
        let response = self.ok(actor, &body);
        (
            Frontier {
                epoch: response["epoch"].as_u64().expect("response epoch"),
                branch: response["branch"]
                    .as_str()
                    .expect("response branch")
                    .to_owned(),
            },
            hex::decode(response["ack"].as_str().expect("ack hex string")).expect("ack hex"),
        )
    }

    /// The C-14 release cover: the writer singleton plus every roster reader singleton.
    fn cover(&mut self, writer: &str) -> Value {
        let roster: Vec<String> = self.checkpoint()["roster"]
            .as_array()
            .expect("roster")
            .iter()
            .map(|name| name.as_str().expect("roster name").to_owned())
            .collect();
        let mut supports = vec![json!([{
            "subject":writer, "right":"write",
            "generation":self.active_generation(writer, "write")
        }])];
        for reader in roster {
            supports.push(json!([{
                "subject":reader, "right":"read",
                "generation":self.active_generation(&reader, "read")
            }]));
        }
        Value::Array(supports)
    }

    /// Allocates and releases `op` for `actor` (C-16); returns the certificate.
    fn release(&mut self, actor: &str, op: &str) -> Released {
        let payload = format!("frozen payload of {op}").into_bytes();
        self.ok(actor, &json!({"command":"allocate", "op":op}));
        let checkpoint = self.checkpoint();
        let frontier = Frontier {
            epoch: checkpoint["epoch"].as_u64().expect("kernel epoch"),
            branch: checkpoint["branch"]
                .as_str()
                .expect("kernel branch")
                .to_owned(),
        };
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .expect("policy_revision");
        let digest = operation_digest(
            op,
            GROUP,
            CONTENT_TYPE,
            &payload,
            &frontier,
            policy_revision,
        )
        .expect("operation digest");
        let body = json!({
            "command":"release", "op":op, "right":"write", "digest":digest,
            "cover":self.cover(actor), "policy_revision":policy_revision,
            "epoch":frontier.epoch, "branch":frontier.branch
        });
        let response = self.ok(actor, &body);
        let certificate = hex::decode(
            response["certificate"]
                .as_str()
                .expect("release certificate hex"),
        )
        .expect("certificate is hex");
        Released {
            op: op.to_owned(),
            actor: actor.to_owned(),
            payload,
            certificate,
        }
    }

    /// Persists and emits an envelope protected for `released`.
    fn publish(&mut self, released: &Released, envelope: &[u8]) {
        for command in ["persist", "emit"] {
            self.ok(
                &released.actor,
                &json!({"command":command, "op":released.op, "envelope":lower_hex(envelope)}),
            );
        }
    }

    /// Receives, consumes and delivers `envelope` at `receiver`.
    fn deliver(&mut self, receiver: &mut ClientEndpoint<P>, released: &Released, envelope: &[u8]) {
        let name = receiver.subject().to_owned();
        let pending = receiver
            .receive(envelope)
            .unwrap_or_else(|err| panic!("{name} receives {}, got {err}", released.op));
        let response = self.ok(&name, &json!({"command":"consume", "op":released.op}));
        let receipt =
            hex::decode(response["receipt"].as_str().expect("receipt hex")).expect("receipt hex");
        let delivered = pending
            .deliver(&receipt)
            .unwrap_or_else(|err| panic!("{name} delivers {}, got {err}", released.op));
        assert_eq!(delivered, (CONTENT_TYPE.to_vec(), released.payload.clone()));
    }
}

/// Stages an Add of `candidate` at `committer`, submits it, merges it at the committer
/// and `others`, and joins the candidate.
fn admit_candidate<P: OpenMlsProvider>(
    w: &mut World<P>,
    committer: &mut ClientEndpoint<P>,
    candidate: JoinCandidate<P>,
    others: &mut [&mut ClientEndpoint<P>],
) -> ClientEndpoint<P> {
    let staged = committer
        .stage_add(candidate.key_package())
        .expect("stage add");
    let actor = committer.subject().to_owned();
    let (frontier, ack) = w.submit(&actor, "admit", &staged.parent, &staged.commit);
    assert_eq!(frontier.epoch, staged.parent.epoch + 1);
    assert_eq!(
        committer
            .apply_ack(&staged.commit, &ack)
            .expect("committer merges"),
        frontier
    );
    for other in others.iter_mut() {
        assert_eq!(
            other
                .apply_ack(&staged.commit, &ack)
                .expect("member merges"),
            frontier
        );
    }
    let joined = candidate
        .join(&staged.welcome, &ack)
        .expect("candidate joins");
    assert_eq!(joined.frontier().expect("joined frontier"), frontier);
    joined
}

/// Plans, stages, submits and merges a read repair (C-20 to C-22) committed by
/// `committer`, then confirms it at the committer and `confirmer` (C-23).
fn repair<P: OpenMlsProvider>(
    w: &mut World<P>,
    committer: &mut ClientEndpoint<P>,
    confirmer: &mut ClientEndpoint<P>,
    removed: &[&str],
) {
    let actor = committer.subject().to_owned();
    let plan = w.ok(&actor, &json!({"command":"repair_plan"}));
    let planned: Vec<String> = plan["removed"]
        .as_array()
        .expect("removed list")
        .iter()
        .map(|name| name.as_str().expect("removed name").to_owned())
        .collect();
    assert_eq!(planned, removed);
    let staged = committer
        .stage_repair(&planned)
        .expect("stage the planned repair");
    let (frontier, ack) = w.submit(&actor, "repair", &staged.parent, &staged.commit);
    for member in [&mut *committer, &mut *confirmer] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &ack)
                .expect("merge the acked repair"),
            frontier
        );
    }
    confirm_repair(w, committer, false);
    confirm_repair(w, confirmer, true);
}

fn confirm_repair<P: OpenMlsProvider>(w: &mut World<P>, member: &ClientEndpoint<P>, opens: bool) {
    let actor = member.subject().to_owned();
    let confirmation = member.confirmation().expect("confirmation");
    let response = w.ok(
        &actor,
        &json!({"command":"confirm_repair", "confirmation":lower_hex(&confirmation)}),
    );
    assert_eq!(response["opened"], json!(opens), "{response}");
}

/// Asserts that `result` failed; returns the error for the message.
fn fails<T>(what: &str, result: Result<T, String>) -> String {
    match result {
        Ok(_) => panic!("{what} must fail while the rand is unavailable"),
        Err(err) => err,
    }
}

/// True if `dir` has no entries at all.
fn dir_is_empty(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir)
        .expect("read directory")
        .next()
        .is_none()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn every_adapter_key_generation_draws_from_configured_rand() {
    // Policy-only adapter (C-5, C-6): one 32-byte draw for the APF key, stored as the seed.
    {
        let dir = adapter_dir();
        let root_rand = SwitchRand::new("create/root-identity");
        let root_identity = drawn_identity(&root_rand, "create root");
        let (provider, apf_rand) = switch_provider("create/apf");
        let adapter = Adapter::create(
            dir.path(),
            GROUP,
            ROOT,
            root_identity.public_key(),
            provider,
            FixedClock::new(NOW),
        )
        .expect("create");
        let draws = apf_rand.draws();
        assert_eq!(
            lengths_since(&apf_rand, 0),
            vec![SEED_LEN],
            "create: the APF key is one 32-byte draw from the configured rand"
        );
        assert_eq!(adapter.apf_public_key(), dalek_public(&draws[0].bytes));
        assert_eq!(
            std::fs::read(dir.path().join(APF_KEY_FILE)).expect("APF key file"),
            draws[0].bytes,
            "the key file holds exactly the drawn seed (C-5)"
        );
    }

    // Full genesis (C-8, §5.1 step 1).
    let (adapter_provider, apf_rand) = switch_provider("genesis/apf");
    let root_rand = SwitchRand::new("genesis/root-identity");
    let root_identity = drawn_identity(&root_rand, ROOT);
    let (root_provider, root_mls) = switch_provider("genesis/root-mls");
    let (mut w, mut root) = genesis(adapter_provider, root_identity, root_provider);
    let apf_draws = apf_rand.draws();
    assert_eq!(
        apf_draws.first().map(|draw| draw.len),
        Some(SEED_LEN),
        "genesis: the first adapter draw is the 32-byte APF seed"
    );
    assert_eq!(
        w.apf_public,
        dalek_public(&apf_draws[0].bytes),
        "genesis: the APF key is the ed25519-dalek key of the drawn seed (C-6)"
    );
    assert_eq!(
        std::fs::read(w.dir.path().join(APF_KEY_FILE)).expect("APF key file"),
        apf_draws[0].bytes
    );
    assert!(
        !root_mls.draws().is_empty(),
        "founding the group draws from the root's configured rand"
    );

    // Identities of bob and carol: one 32-byte draw each from their own rand.
    let mut members = HashMap::new();
    for subject in ["bob", "carol"] {
        let identity_rand = SwitchRand::new(&format!("genesis/{subject}-identity"));
        let identity = drawn_identity(&identity_rand, subject);
        w.delegate(subject, &identity, &["read", "write", "admit"]);
        members.insert(subject, identity);
    }

    // Admission: the candidate's KeyPackage and the committer's Add both draw.
    let admit_draws = |w: &mut World<SProv>,
                       root: &mut ClientEndpoint<SProv>,
                       others: &mut [&mut ClientEndpoint<SProv>],
                       subject: &str,
                       identity: ClientIdentity| {
        let (provider, mls_rand) = switch_provider(&format!("genesis/{subject}-mls"));
        let prepared = w.prepare(subject, identity, provider);
        let prepare_draws = mls_rand.draws().len();
        assert!(
            prepare_draws > 0,
            "{subject}: PreparedJoin::prepare draws from the candidate's rand"
        );
        let candidate = w.certify(subject, prepared);
        let committer_before = root_mls.draws().len();
        let joined = admit_candidate(w, root, candidate, others);
        let committer_lengths = lengths_since(&root_mls, committer_before);
        assert!(
            !committer_lengths.is_empty(),
            "{subject}: the committer's stage_add draws from its rand"
        );
        eprintln!("draws: {subject} prepare {prepare_draws}, committer add {committer_lengths:?}");
        (joined, mls_rand)
    };
    let bob_identity = members.remove("bob").expect("bob identity");
    let (mut bob, bob_mls) = admit_draws(&mut w, &mut root, &mut [], "bob", bob_identity);
    let carol_identity = members.remove("carol").expect("carol identity");
    let (mut carol, _carol_mls) =
        admit_draws(&mut w, &mut root, &mut [&mut bob], "carol", carol_identity);

    // Release: protecting the frozen content draws from the sender's rand.
    let released = w.release(ROOT, "op-entropy");
    let before = root_mls.draws().len();
    let envelope = root
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("protect");
    let protect_lengths = lengths_since(&root_mls, before);
    assert!(
        !protect_lengths.is_empty(),
        "protect draws from the sender's configured rand"
    );
    eprintln!("draws: root protect {protect_lengths:?}");
    w.publish(&released, &envelope);
    w.deliver(&mut bob, &released, &envelope);
    w.deliver(&mut carol, &released, &envelope);

    // Repair: revoking carol's read right forces a repair commit with an UpdatePath.
    w.revoke("carol", "read");
    let before = root_mls.draws().len();
    let bob_before = bob_mls.draws().len();
    repair(&mut w, &mut root, &mut bob, &["carol"]);
    let repair_lengths = lengths_since(&root_mls, before);
    assert!(
        !repair_lengths.is_empty(),
        "stage_repair draws from the committer's configured rand"
    );
    eprintln!(
        "draws: root repair {repair_lengths:?}, bob merge {:?}",
        lengths_since(&bob_mls, bob_before)
    );
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));

    // The adapter's own draws: the APF seed first; record the total for the evidence.
    let adapter_draws = lengths_since(&apf_rand, 0);
    assert_eq!(adapter_draws[0], SEED_LEN);
    eprintln!("draws: adapter over the whole flow {adapter_draws:?}");
}

#[test]
fn failing_rand_fails_closed_without_kernel_mutation() {
    let root_public = dalek_public(&[7u8; 32]);

    // Adapter construction: `entropy_unavailable`, and nothing is created (C-6, §12).
    let dir = adapter_dir();
    code(
        Adapter::create(
            dir.path(),
            GROUP,
            ROOT,
            &root_public,
            TestProvider::new(FailingRand),
            FixedClock::new(NOW),
        ),
        "entropy_unavailable",
    );
    assert!(dir_is_empty(dir.path()), "create left files behind");
    let dir = adapter_dir();
    code(
        Adapter::begin_genesis(
            dir.path(),
            GROUP,
            ROOT,
            &root_public,
            TestProvider::new(FailingRand),
            FixedClock::new(NOW),
        )
        .map(|_| ()),
        "entropy_unavailable",
    );
    assert!(dir_is_empty(dir.path()), "begin_genesis left files behind");

    // Identity generation: `entropy_unavailable` (C-6).
    code(
        ClientIdentity::generate(&FailingRand).map(|_| ()),
        "entropy_unavailable",
    );

    // A working session whose clients' rands can be switched off.
    let (adapter_provider, _) = switch_provider("fail/apf");
    let root_identity =
        ClientIdentity::generate(&SwitchRand::new("fail/root-identity")).expect("root identity");
    let (root_provider, root_mls) = switch_provider("fail/root-mls");
    let (mut w, mut root) = genesis(adapter_provider, root_identity, root_provider);
    let mut identities = HashMap::new();
    for subject in ["bob", "carol", "dave"] {
        let identity = ClientIdentity::generate(&SwitchRand::new(&format!("fail/{subject}-id")))
            .expect("identity");
        w.delegate(subject, &identity, &["read", "write", "admit"]);
        identities.insert(subject, identity);
    }
    let (bob_provider, _) = switch_provider("fail/bob-mls");
    let prepared = w.prepare(
        "bob",
        identities.remove("bob").expect("bob identity"),
        bob_provider,
    );
    let candidate = w.certify("bob", prepared);
    let mut bob = admit_candidate(&mut w, &mut root, candidate, &mut []);
    let (carol_provider, _) = switch_provider("fail/carol-mls");
    let prepared = w.prepare(
        "carol",
        identities.remove("carol").expect("carol identity"),
        carol_provider,
    );
    let carol_candidate = w.certify("carol", prepared);
    let released = w.release(ROOT, "op-during-failure");

    // The rand fails: every client operation that needs randomness fails, and neither
    // the kernel nor the adapter changes.
    let before = w.snapshot();
    let failing_identity_rand = SwitchRand::new("fail/eve-id");
    failing_identity_rand.set_failing(true);
    code(
        ClientIdentity::generate(&failing_identity_rand).map(|_| ()),
        "entropy_unavailable",
    );
    assert!(failing_identity_rand.refused() > 0);

    let (dave_provider, dave_mls) = switch_provider("fail/dave-mls");
    dave_mls.set_failing(true);
    let dave_rights = w.rights_of("dave");
    let err = fails(
        "PreparedJoin::prepare",
        PreparedJoin::prepare(
            GROUP,
            "dave",
            &dave_rights,
            identities.remove("dave").expect("dave identity"),
            dave_provider,
            &w.apf_public,
        )
        .map(|_| ()),
    );
    assert!(
        dave_mls.refused() > 0,
        "prepare failed ({err}) without a draw"
    );
    w.assert_unchanged(&before, "failed prepare");

    root_mls.set_failing(true);
    let refused = root_mls.refused();
    let err = fails(
        "stage_add",
        root.stage_add(carol_candidate.key_package()).map(|_| ()),
    );
    assert!(
        root_mls.refused() > refused,
        "stage_add failed ({err}) without a draw"
    );
    w.assert_unchanged(&before, "failed stage_add");

    let refused = root_mls.refused();
    let err = fails(
        "protect",
        root.protect(&released.certificate, CONTENT_TYPE, &released.payload),
    );
    assert!(
        root_mls.refused() > refused,
        "protect failed ({err}) without a draw"
    );
    w.assert_unchanged(&before, "failed protect");
    assert_eq!(
        root.frontier().expect("root frontier"),
        before.1,
        "the root stays at the canonical frontier"
    );

    // The rand recovers: the same operations now succeed from the unchanged state.
    root_mls.set_failing(false);
    let envelope = root
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("protect after the rand recovers");
    w.publish(&released, &envelope);
    w.deliver(&mut bob, &released, &envelope);
    let _carol = admit_candidate(&mut w, &mut root, carol_candidate, &mut [&mut bob]);
    assert_eq!(
        w.checkpoint()["roster"],
        json!([ROOT, "bob", "carol"]),
        "admission completes after the rand recovers"
    );

    // Repair: a failed stage_repair leaves the fenced kernel unchanged.
    w.revoke("carol", "read");
    let before = w.snapshot();
    root_mls.set_failing(true);
    w.ok(ROOT, &json!({"command":"repair_plan"}));
    let after_plan = w.snapshot();
    let refused = root_mls.refused();
    let err = fails(
        "stage_repair",
        root.stage_repair(&["carol".to_owned()]).map(|_| ()),
    );
    assert!(
        root_mls.refused() > refused,
        "stage_repair failed ({err}) without a draw"
    );
    w.assert_unchanged(&after_plan, "failed stage_repair");
    assert_eq!(
        after_plan.0, before.0,
        "repair_plan does not change the kernel"
    );
    root_mls.set_failing(false);
    repair(&mut w, &mut root, &mut bob, &["carol"]);
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));
}

#[test]
fn mock_qrng_provider_runs_genesis_admission_and_release() {
    // MOCK QRNG: loopback test double of the QRNG Open API; no quantum-origin claim.
    let mock = MockQrng::start();
    let qrng = mock.connect();

    // The root's identity: exactly one 32-byte mock block, and the key is its dalek key.
    let mark = mock.log().len();
    let root_identity =
        ClientIdentity::generate(&QrngRand::new(Arc::clone(&qrng))).expect("root identity");
    let requests = mock.entropy_since(mark);
    assert_eq!(requests.len(), 1, "one entropy request per identity");
    let seed = requests[0].served.clone().expect("the mock served a block");
    assert_eq!(seed.len(), SEED_LEN);
    assert_eq!(root_identity.public_key(), dalek_public(&seed));

    // Genesis: the APF seed is exactly one 32-byte mock block.
    let adapter_provider = qrng_provider(&qrng);
    let dir = adapter_dir();
    let mark = mock.log().len();
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity.public_key(),
        adapter_provider,
        FixedClock::new(NOW),
    )
    .expect("begin_genesis on the QRNG provider");
    let requests = mock.entropy_since(mark);
    assert_eq!(
        requests.len(),
        1,
        "begin_genesis: one entropy request for the APF seed"
    );
    let apf_seed = requests[0].served.clone().expect("the mock served a block");
    assert_eq!(apf_seed.len(), SEED_LEN);
    assert_eq!(pending.apf_public_key(), dalek_public(&apf_seed));
    let apf_public = pending.apf_public_key().to_vec();
    let founder_certificate = pending.founder_certificate().to_vec();
    let apf_anchor = pending.apf_anchor().to_vec();
    let root_signer = root_identity.signer().clone();
    let mark = mock.log().len();
    let mut root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        qrng_provider(&qrng),
        &founder_certificate,
        &apf_anchor,
        &apf_public,
    )
    .expect("root founds the group on the QRNG provider");
    assert!(
        !mock.entropy_since(mark).is_empty(),
        "founding the group requested mock entropy"
    );
    let adapter = pending
        .complete(
            &root.export_group_info().expect("GroupInfo"),
            &root.export_ratchet_tree().expect("ratchet tree"),
        )
        .expect("genesis completes");
    let mut w = World {
        dir,
        adapter,
        apf_public,
        seqs: HashMap::new(),
        signers: HashMap::from([(ROOT.to_owned(), root_signer)]),
    };

    // Admission of bob, all randomness from the mock.
    let bob_identity =
        ClientIdentity::generate(&QrngRand::new(Arc::clone(&qrng))).expect("bob identity");
    w.delegate("bob", &bob_identity, &["read", "write", "admit"]);
    let mark = mock.log().len();
    let prepared = w.prepare("bob", bob_identity, qrng_provider(&qrng));
    assert!(
        !mock.entropy_since(mark).is_empty(),
        "bob's KeyPackage requested mock entropy"
    );
    let candidate = w.certify("bob", prepared);
    let mark = mock.log().len();
    let mut bob = admit_candidate(&mut w, &mut root, candidate, &mut []);
    assert!(
        !mock.entropy_since(mark).is_empty(),
        "the Add commit requested mock entropy"
    );
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob"]));

    // A release delivered to bob.
    let released = w.release(ROOT, "op-mock-qrng");
    let mark = mock.log().len();
    let envelope = root
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("protect on the QRNG provider");
    assert!(
        !mock.entropy_since(mark).is_empty(),
        "protect requested mock entropy"
    );
    w.publish(&released, &envelope);
    w.deliver(&mut bob, &released, &envelope);

    // Every entropy request was served well-formed, and the provider counted each one.
    let entropy = mock.entropy_since(0);
    assert!(entropy
        .iter()
        .all(|r| r.status == 200 && r.served.is_some()));
    let metrics = qrng.metrics_snapshot();
    assert_eq!(metrics.entropy_requests_total, entropy.len() as u64);
    assert_eq!(metrics.entropy_failures_total, 0);
    assert_eq!(
        metrics.entropy_bytes_total,
        entropy
            .iter()
            .map(|r| r.served.as_ref().map_or(0, Vec::len) as u64)
            .sum::<u64>()
    );
    eprintln!(
        "mock QRNG: {} entropy requests, {} bytes",
        metrics.entropy_requests_total, metrics.entropy_bytes_total
    );
}

#[test]
fn qrng_outage_mid_session_fails_closed_without_fallback() {
    // MOCK QRNG: loopback test double of the QRNG Open API; no quantum-origin claim.
    let mock = MockQrng::start();
    let qrng = mock.connect();
    let rand = || QrngRand::new(Arc::clone(&qrng));

    let root_identity = ClientIdentity::generate(&rand()).expect("root identity");
    let (mut w, mut root) = genesis(qrng_provider(&qrng), root_identity, qrng_provider(&qrng));
    let mut identities = HashMap::new();
    for subject in ["bob", "carol", "dave"] {
        let identity = ClientIdentity::generate(&rand()).expect("identity");
        w.delegate(subject, &identity, &["read", "write", "admit"]);
        identities.insert(subject, identity);
    }
    let prepared = w.prepare(
        "bob",
        identities.remove("bob").expect("bob identity"),
        qrng_provider(&qrng),
    );
    let candidate = w.certify("bob", prepared);
    let mut bob = admit_candidate(&mut w, &mut root, candidate, &mut []);
    let prepared = w.prepare(
        "carol",
        identities.remove("carol").expect("carol identity"),
        qrng_provider(&qrng),
    );
    let carol_candidate = w.certify("carol", prepared);
    let released = w.release(ROOT, "op-during-outage");

    // Outage: 5xx, malformed and inconsistent answers, cyclically.
    let before = w.snapshot();
    let metrics_before = qrng.metrics_snapshot();
    let mark = mock.log().len();
    mock.set_outage(&[
        MockFault::Status(503),
        MockFault::Status(500),
        MockFault::Malformed,
        MockFault::WrongLength,
        MockFault::TwoBlocks,
    ]);

    // Identity generation and adapter construction: `entropy_unavailable` (C-6, §12).
    code(
        ClientIdentity::generate(&rand()).map(|_| ()),
        "entropy_unavailable",
    );
    let fresh = adapter_dir();
    code(
        Adapter::begin_genesis(
            fresh.path(),
            GROUP,
            ROOT,
            root.identity().public_key(),
            qrng_provider(&qrng),
            FixedClock::new(NOW),
        )
        .map(|_| ()),
        "entropy_unavailable",
    );
    assert!(
        dir_is_empty(fresh.path()),
        "begin_genesis left files behind"
    );
    let fresh = adapter_dir();
    code(
        Adapter::create(
            fresh.path(),
            GROUP,
            ROOT,
            root.identity().public_key(),
            qrng_provider(&qrng),
            FixedClock::new(NOW),
        )
        .map(|_| ()),
        "entropy_unavailable",
    );
    assert!(dir_is_empty(fresh.path()), "create left files behind");

    // Client operations that need randomness fail, and nothing changes.
    let dave_rights = w.rights_of("dave");
    let err = fails(
        "PreparedJoin::prepare",
        PreparedJoin::prepare(
            GROUP,
            "dave",
            &dave_rights,
            identities.remove("dave").expect("dave identity"),
            qrng_provider(&qrng),
            &w.apf_public,
        )
        .map(|_| ()),
    );
    w.assert_unchanged(&before, &format!("failed prepare ({err})"));
    let err = fails(
        "stage_add",
        root.stage_add(carol_candidate.key_package()).map(|_| ()),
    );
    w.assert_unchanged(&before, &format!("failed stage_add ({err})"));
    let err = fails(
        "protect",
        root.protect(&released.certificate, CONTENT_TYPE, &released.payload),
    );
    w.assert_unchanged(&before, &format!("failed protect ({err})"));

    // No fallback: the mock saw every attempt and served none of them; the provider
    // counted only failures, one per attempt, and no successful fetch.
    let attempts = mock.entropy_since(mark);
    assert!(
        attempts.len() >= 6,
        "every operation reached the mock: {attempts:?}"
    );
    assert!(
        attempts.iter().all(|r| r.served.is_none()),
        "no entropy was served during the outage"
    );
    let metrics = qrng.metrics_snapshot();
    assert_eq!(
        metrics.entropy_requests_total, metrics_before.entropy_requests_total,
        "no entropy fetch succeeded during the outage"
    );
    assert_eq!(
        metrics.entropy_bytes_total,
        metrics_before.entropy_bytes_total
    );
    assert_eq!(
        metrics.entropy_failures_total - metrics_before.entropy_failures_total,
        attempts.len() as u64,
        "each failed fetch is exactly one failed request; nothing was retried elsewhere"
    );
    let faults_seen: Vec<(u16, bool)> = attempts
        .iter()
        .map(|r| (r.status, r.served.is_some()))
        .collect();
    eprintln!("mock QRNG outage attempts (status, served): {faults_seen:?}");

    // Restored: the same operations succeed from the unchanged state.
    mock.restore();
    let mark = mock.log().len();
    let envelope = root
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("protect after the mock is restored");
    w.publish(&released, &envelope);
    w.deliver(&mut bob, &released, &envelope);
    let _carol = admit_candidate(&mut w, &mut root, carol_candidate, &mut [&mut bob]);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob", "carol"]));
    ClientIdentity::generate(&rand()).expect("identity after the mock is restored");
    let restored = mock.entropy_since(mark);
    assert!(!restored.is_empty() && restored.iter().all(|r| r.served.is_some()));
}

/// Live gate (§8): genesis and one admission against a real Entropy Core.
///
/// Environment only; nothing here is ever written to a file, a trace or the output:
/// - `AGENT_TRUST_QRNG_BASE_URL` (required): `http://` or `https://` base URL;
/// - `AGENT_TRUST_QRNG_CA_PEM` (optional): CA PEM path for `https://`;
/// - `AGENT_TRUST_QRNG_CLIENT_CERT_PEM` and `AGENT_TRUST_QRNG_CLIENT_KEY_PEM` (optional,
///   together, with the CA): mTLS client identity paths;
/// - `AGENT_TRUST_QRNG_BEARER_TOKEN` or `AGENT_TRUST_QRNG_API_KEY` (optional): API auth;
/// - `AGENT_TRUST_QRNG_ENTROPY_TYPE` (optional): requested entropy type.
///
/// Without `AGENT_TRUST_QRNG_BASE_URL` the test fails: an unmet gate never passes.
#[test]
#[ignore = "live Entropy Core gate: needs AGENT_TRUST_QRNG_BASE_URL; unmet until executed"]
fn live_entropy_core_gate() {
    let var = |name: &str| std::env::var(name).ok().filter(|value| !value.is_empty());
    let base_url =
        var("AGENT_TRUST_QRNG_BASE_URL").expect("unmet gate: AGENT_TRUST_QRNG_BASE_URL is not set");
    let ca = var("AGENT_TRUST_QRNG_CA_PEM").map(std::path::PathBuf::from);
    let client_cert = var("AGENT_TRUST_QRNG_CLIENT_CERT_PEM").map(std::path::PathBuf::from);
    let client_key = var("AGENT_TRUST_QRNG_CLIENT_KEY_PEM").map(std::path::PathBuf::from);
    let transport = if base_url.starts_with("https://") {
        match (ca, client_cert, client_key) {
            (Some(ca), Some(cert), Some(key)) => TransportMode::MutualTls {
                ca_cert_pem: ca,
                client_cert_pem: cert,
                client_key_pem: key,
            },
            (ca, None, None) => TransportMode::Tls { ca_cert_pem: ca },
            _ => panic!("live gate: mTLS needs the CA, client certificate and client key"),
        }
    } else {
        TransportMode::PlainHttp
    };
    let auth = match (
        var("AGENT_TRUST_QRNG_BEARER_TOKEN"),
        var("AGENT_TRUST_QRNG_API_KEY"),
    ) {
        (Some(token), None) => ApiAuth::Bearer(token),
        (None, Some(key)) => ApiAuth::XApiKey(key),
        (None, None) => ApiAuth::None,
        (Some(_), Some(_)) => panic!("live gate: set at most one of bearer token and API key"),
    };
    let config = QrngConfig {
        base_url: base_url
            .parse()
            .map_err(|_| "unparsable")
            .expect("live gate: AGENT_TRUST_QRNG_BASE_URL does not parse"),
        transport,
        auth,
        entropy_type: var("AGENT_TRUST_QRNG_ENTROPY_TYPE"),
        request_timeout: Duration::from_secs(10),
        health_poll_interval: None,
        // C-42: post quantum TLS only, unless the live endpoint is configured otherwise.
        key_exchange: var("AGENT_TRUST_QRNG_KEY_EXCHANGE")
            .map(|name| {
                openmls_qrand::KeyExchange::parse(&name)
                    .expect("live gate: AGENT_TRUST_QRNG_KEY_EXCHANGE is pq-only or pq-preferred")
            })
            .unwrap_or_default(),
    };
    // Only the error category is reported: QRNG errors can carry the endpoint URL.
    let qrng =
        Arc::new(QrngClient::connect(config).unwrap_or_else(|err| {
            panic!("live gate: connect failed ({})", qrng_error_category(&err))
        }));

    let root_identity =
        ClientIdentity::generate(&QrngRand::new(Arc::clone(&qrng))).expect("live root identity");
    let (mut w, mut root) = genesis(qrng_provider(&qrng), root_identity, qrng_provider(&qrng));
    let bob_identity =
        ClientIdentity::generate(&QrngRand::new(Arc::clone(&qrng))).expect("live bob identity");
    w.delegate("bob", &bob_identity, &["read", "write", "admit"]);
    let prepared = w.prepare("bob", bob_identity, qrng_provider(&qrng));
    let candidate = w.certify("bob", prepared);
    admit_candidate(&mut w, &mut root, candidate, &mut []);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob"]));

    let metrics = qrng.metrics_snapshot();
    assert!(metrics.entropy_requests_total > 0);
    assert_eq!(metrics.entropy_failures_total, 0);
    eprintln!(
        "live gate: {} entropy requests, {} bytes, 0 failures",
        metrics.entropy_requests_total, metrics.entropy_bytes_total
    );
}

/// The variant name of a QRNG error, without its payload.
fn qrng_error_category(err: &QrngError) -> &'static str {
    match err {
        QrngError::InvalidConfig(_) => "invalid configuration",
        QrngError::TlsMaterial(_) => "TLS material",
        QrngError::Transport(_) => "transport",
        QrngError::InvalidRequest => "invalid request",
        QrngError::EntropyUnavailable => "entropy unavailable",
        QrngError::HealthUnavailable => "health unavailable",
        QrngError::HttpStatus(_) => "HTTP status",
        QrngError::Protocol(_) => "protocol",
        QrngError::Base64(_) => "base64",
        QrngError::UnsupportedEntropyType => "unsupported entropy type",
        QrngError::HealthUnsupported => "health unsupported",
    }
}
