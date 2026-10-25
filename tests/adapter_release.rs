//! Phase 4.3 contract tests: release certificates and the receive path
//! (`docs/adapter-contract.md` §4.5, §4.11 C-14 to C-18, §5.3).
//!
//! The operation digest, `FrozenContent`, the release certificate, the consume receipt
//! and the envelope are encoded, decoded or recomputed here with `tls_codec` and `sha2`,
//! independently of `src/wire.rs`. Raw OpenMLS state is used through
//! `ClientEndpoint::mls_parts_mut`, which honest code never uses, to read AADs and to
//! build adversarial application messages outside `protect`.
//!
//! Every negative case runs after the matching positive path in the same test, so an
//! adapter or client that rejects everything cannot pass. `PendingDelivery::deliver`
//! consumes the pending delivery and MLS deletes a message key once it is used, so each
//! negative delivery attempt uses its own operation.

mod common;

use std::collections::HashMap;

use agent_trust::adapter::{Adapter, ClientIdentity, APF_KEY_FILE};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use agent_trust::wire::{
    operation_digest, ConsumeReceipt, Envelope, Frontier, FrozenContent, ReleaseCertificate, Right,
    SignedStructure,
};
use common::{
    adapter_dir, code, contains, lower_hex, scripted_provider, sign, DalekSigner, FixedClock,
    ScriptedRand, TestProvider,
};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::SignatureScheme;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};

const GROUP: &str = "g";
const ROOT: &str = "root";
/// Trusted adapter time for every test.
const NOW: u64 = 1_000;
/// Default delegation expiry.
const EXPIRES: u64 = 1_000_000;
/// Content type used by every honest release.
const CONTENT_TYPE: &[u8] = b"text/plain";

// Spelled out here independently of `src/wire.rs`.
const T_OPERATION_LABEL: &[u8] = b"agent-trust/operation/v1";
const T_RELEASE_LABEL: &[u8] = b"agent-trust/release/v1";
const T_CONSUME_LABEL: &[u8] = b"agent-trust/consume/v1";
/// C-9 right code of `write`.
const WRITE_CODE: u8 = 2;

type Prov = TestProvider<ScriptedRand>;
type TestAdapter = Adapter<Prov, FixedClock>;
type Client = ClientEndpoint<Prov>;

// ---------------------------------------------------------------------------
// Independent encodings
// ---------------------------------------------------------------------------

fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .expect("VLBytes encoding")
}

fn tls_u64(value: u64) -> Vec<u8> {
    value.tls_serialize_detached().expect("uint64 encoding")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let last = out.len() - 1;
    out[last] ^= 0x01;
    out
}

/// Reads TLS fields from the front of a byte slice.
struct TlsReader<'a> {
    rest: &'a [u8],
}

impl<'a> TlsReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn u8(&mut self) -> u8 {
        u8::tls_deserialize(&mut self.rest).expect("uint8 field")
    }

    fn u64(&mut self) -> u64 {
        u64::tls_deserialize(&mut self.rest).expect("uint64 field")
    }

    fn opaque(&mut self) -> Vec<u8> {
        VLBytes::tls_deserialize(&mut self.rest)
            .expect("opaque<V> field")
            .as_slice()
            .to_vec()
    }

    fn string(&mut self) -> String {
        String::from_utf8(self.opaque()).expect("UTF-8 field")
    }

    fn finish(&self) {
        assert!(self.rest.is_empty(), "{} trailing bytes", self.rest.len());
    }
}

/// C-14 operation digest: lowercase hex SHA-256 of
/// `TLS { label, op, resource, content_type, SHA-256(payload) (raw), epoch, branch (ASCII
/// hex), policy_revision }`, computed without `src/wire.rs`.
fn independent_digest(
    op: &str,
    resource: &str,
    content_type: &[u8],
    payload: &[u8],
    frontier: &Frontier,
    policy_revision: u64,
) -> String {
    let mut input = Vec::new();
    input.extend(vl(T_OPERATION_LABEL));
    input.extend(vl(op.as_bytes()));
    input.extend(vl(resource.as_bytes()));
    input.extend(vl(content_type));
    input.extend(vl(&sha256(payload)));
    input.extend(tls_u64(frontier.epoch));
    input.extend(vl(frontier.branch.as_bytes()));
    input.extend(tls_u64(policy_revision));
    lower_hex(&sha256(&input))
}

/// C-14 `FrozenContent { opaque content_type<V>; opaque payload<V>; }`.
fn frozen(content_type: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vl(content_type);
    out.extend(vl(payload));
    out
}

fn decode_frozen(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut reader = TlsReader::new(bytes);
    let content = (reader.opaque(), reader.opaque());
    reader.finish();
    content
}

/// C-14 `Envelope { opaque certificate<V>; opaque mls_message<V>; }`.
fn envelope_bytes(certificate: &[u8], mls_message: &[u8]) -> Vec<u8> {
    let mut out = vl(certificate);
    out.extend(vl(mls_message));
    out
}

fn decode_envelope(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut reader = TlsReader::new(bytes);
    let parts = (reader.opaque(), reader.opaque());
    reader.finish();
    parts
}

fn ed25519_verifies(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    RustCrypto::default()
        .verify_signature(SignatureScheme::ED25519, data, public_key, signature)
        .is_ok()
}

/// §4.5 `ReleaseCertificateTBS` with C-14 field encodings, as plain test data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestCertificate {
    apf_key_id: Vec<u8>,
    group: String,
    op: String,
    actor: String,
    right: u8,
    resource: String,
    invocation: String,
    epoch: u64,
    branch: String,
    policy_revision: u64,
    digest: String,
    writer_generation: u64,
    readers: Vec<(String, u64)>,
    kernel_event_hash: String,
}

/// Decodes a signed release certificate and checks its APF signature, without
/// `src/wire.rs`. `readers` is a `VLBytes` of `{ opaque subject<V>; uint64 generation; }`.
fn decode_certificate(bytes: &[u8], apf_public: &[u8]) -> TestCertificate {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(
        reader.opaque(),
        T_RELEASE_LABEL,
        "release certificate label"
    );
    let apf_key_id = reader.opaque();
    let group = reader.string();
    let op = reader.string();
    let actor = reader.string();
    let right = reader.u8();
    let resource = reader.string();
    let invocation = reader.string();
    let epoch = reader.u64();
    let branch = reader.string();
    let policy_revision = reader.u64();
    let digest = reader.string();
    let writer_generation = reader.u64();
    let readers_bytes = reader.opaque();
    let mut readers_reader = TlsReader::new(&readers_bytes);
    let mut readers = Vec::new();
    while !readers_reader.rest.is_empty() {
        let subject = readers_reader.string();
        let generation = readers_reader.u64();
        readers.push((subject, generation));
    }
    let kernel_event_hash = reader.string();
    let tbs_len = bytes.len() - reader.rest.len();
    let signature = reader.opaque();
    reader.finish();
    assert!(
        ed25519_verifies(apf_public, &bytes[..tbs_len], &signature),
        "release certificate signature covers the TLS encoding of the TBS"
    );
    TestCertificate {
        apf_key_id,
        group,
        op,
        actor,
        right,
        resource,
        invocation,
        epoch,
        branch,
        policy_revision,
        digest,
        writer_generation,
        readers,
        kernel_event_hash,
    }
}

/// C-15 consume receipt TBS, as plain test data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestReceipt {
    apf_key_id: Vec<u8>,
    group: String,
    op: String,
    recipient: String,
    release_certificate_hash: Vec<u8>,
}

fn receipt_tbs(receipt: &TestReceipt) -> Vec<u8> {
    let mut out = vl(T_CONSUME_LABEL);
    out.extend(vl(&receipt.apf_key_id));
    out.extend(vl(receipt.group.as_bytes()));
    out.extend(vl(receipt.op.as_bytes()));
    out.extend(vl(receipt.recipient.as_bytes()));
    out.extend(vl(&receipt.release_certificate_hash));
    out
}

/// Decodes a signed consume receipt and checks its APF signature, without `src/wire.rs`.
fn decode_receipt(bytes: &[u8], apf_public: &[u8]) -> TestReceipt {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.opaque(), T_CONSUME_LABEL, "consume receipt label");
    let receipt = TestReceipt {
        apf_key_id: reader.opaque(),
        group: reader.string(),
        op: reader.string(),
        recipient: reader.string(),
        release_certificate_hash: reader.opaque(),
    };
    let tbs_len = bytes.len() - reader.rest.len();
    let signature = reader.opaque();
    reader.finish();
    assert_eq!(
        &bytes[..tbs_len],
        receipt_tbs(&receipt).as_slice(),
        "receipt TBS re-encodes to the same bytes"
    );
    assert!(
        ed25519_verifies(apf_public, &bytes[..tbs_len], &signature),
        "consume receipt signature covers the TLS encoding of the TBS"
    );
    receipt
}

/// A receipt signed by `signer` over the independent TBS encoding.
fn forge_receipt(signer: &impl Signer, receipt: &TestReceipt) -> Vec<u8> {
    let mut out = receipt_tbs(receipt);
    let signature = signer.sign(&out).expect("test signature");
    out.extend(vl(&signature));
    out
}

// ---------------------------------------------------------------------------
// Raw OpenMLS access
// ---------------------------------------------------------------------------

/// The `PrivateMessage` inside exact `MlsMessage` bytes; panics on any other body.
fn private_message(mls_message: &[u8]) -> PrivateMessageIn {
    match MlsMessageIn::tls_deserialize_exact(mls_message)
        .expect("MLS message decodes")
        .extract()
    {
        MlsMessageBodyIn::PrivateMessage(message) => message,
        _ => panic!("expected a PrivateMessage"),
    }
}

/// An application message built directly with OpenMLS, outside `protect`: `aad` is set
/// only when given, and `plaintext` is sent as is.
fn raw_application(sender: &mut Client, aad: Option<Vec<u8>>, plaintext: &[u8]) -> Vec<u8> {
    let (group, provider, signer) = sender.mls_parts_mut();
    if let Some(aad) = aad {
        group.set_aad(aad);
    }
    group
        .create_message(provider, signer, plaintext)
        .expect("raw application message")
        .tls_serialize_detached()
        .expect("MLS message encoding")
}

/// Processes `mls_message` with raw OpenMLS and returns `(aad, sender identity, plaintext)`.
fn raw_process(receiver: &mut Client, mls_message: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (group, provider, _) = receiver.mls_parts_mut();
    let message = MlsMessageIn::tls_deserialize_exact(mls_message)
        .expect("MLS message decodes")
        .try_into_protocol_message()
        .expect("protocol message");
    let processed = group
        .process_message(provider, message)
        .expect("raw OpenMLS processes the application message");
    let aad = processed.aad().to_vec();
    let sender = BasicCredential::try_from(processed.credential().clone())
        .expect("basic credential")
        .identity()
        .to_vec();
    let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content() else {
        panic!("expected an application message");
    };
    (aad, sender, application.into_bytes())
}

// ---------------------------------------------------------------------------
// Identities, providers and the test world (pattern of `tests/adapter_admission.rs`)
// ---------------------------------------------------------------------------

/// Deterministic client identity: the same name always yields the same key.
fn identity(name: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(
        format!("release-identity/{name}").as_bytes(),
    ))
    .expect("client identity")
}

fn client_provider(label: &str) -> Prov {
    TestProvider::new(ScriptedRand::new(
        format!("release-provider/{label}").as_bytes(),
    ))
}

const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];

/// Outcome of an accepted `submit_commit`.
#[derive(Clone, Debug)]
struct Admitted {
    frontier: Frontier,
    ack: Vec<u8>,
}

struct World {
    tag: String,
    dir: tempfile::TempDir,
    adapter: TestAdapter,
    apf_public: Vec<u8>,
    seqs: HashMap<String, u64>,
    providers: u64,
}

/// A kernel release accepted by the adapter, with the certificate it returned.
#[derive(Clone, Debug)]
struct Released {
    op: String,
    actor: String,
    payload: Vec<u8>,
    digest: String,
    response: Value,
    certificate: Vec<u8>,
}

/// A release whose envelope was protected, persisted and emitted.
#[derive(Clone, Debug)]
struct Published {
    released: Released,
    envelope: Vec<u8>,
}

/// Genesis with the root, then bob and carol admitted by the root, each delegated
/// `read`, `write` and `admit` on the group.
struct Setup {
    w: World,
    root: Client,
    bob: Client,
    carol: Client,
}

/// Full genesis (§5.1).
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(format!("release-apf/{tag}").as_bytes());
    let clock = FixedClock::new(NOW);
    let root_identity = identity(ROOT);
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity.public_key(),
        provider,
        clock,
    )
    .expect("begin_genesis");
    let apf_public = pending.apf_public_key().to_vec();
    let founder_certificate = pending.founder_certificate().to_vec();
    let apf_anchor = pending.apf_anchor().to_vec();
    let root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        client_provider(&format!("{tag}/root")),
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
    (
        World {
            tag: tag.to_owned(),
            dir,
            adapter,
            apf_public,
            seqs: HashMap::new(),
            providers: 0,
        },
        root,
    )
}

fn setup(tag: &str) -> Setup {
    let (mut w, mut root) = genesis(tag);
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    let (mut bob, _) = admit(&mut w, ROOT, &mut root, "bob", &mut []);
    let (carol, _) = admit(&mut w, ROOT, &mut root, "carol", &mut [&mut bob]);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["roster"], json!([ROOT, "bob", "carol"]));
    assert_eq!(checkpoint["epoch"], json!(2));
    Setup {
        w,
        root,
        bob,
        carol,
    }
}

fn persist_body(op: &str, envelope: &[u8]) -> Value {
    json!({"command":"persist", "op":op, "envelope":lower_hex(envelope)})
}

fn emit_body(op: &str, envelope: &[u8]) -> Value {
    json!({"command":"emit", "op":op, "envelope":lower_hex(envelope)})
}

fn consume_body(op: &str) -> Value {
    json!({"command":"consume", "op":op})
}

fn abandon_body(op: &str) -> Value {
    json!({"command":"abandon", "op":op})
}

fn payload_for(op: &str) -> Vec<u8> {
    format!("frozen payload of {op}").into_bytes()
}

impl World {
    fn provider(&mut self, name: &str) -> Prov {
        self.providers += 1;
        client_provider(&format!("{}/{}/{}", self.tag, name, self.providers))
    }

    /// Signs `body` as `actor` at the actor's next sequence and handles it.
    fn send(&mut self, actor: &str, body: &Value) -> Result<Value, String> {
        let sequence = self.seqs.entry(actor.to_owned()).or_insert(0);
        *sequence += 1;
        let request = sign(identity(actor).signer(), GROUP, actor, *sequence, body);
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

    fn kernel_frontier(&mut self) -> Frontier {
        let checkpoint = self.checkpoint();
        Frontier {
            epoch: checkpoint["epoch"].as_u64().expect("kernel epoch"),
            branch: checkpoint["branch"]
                .as_str()
                .expect("kernel branch")
                .to_owned(),
        }
    }

    fn policy_revision(&mut self) -> u64 {
        self.checkpoint()["policy_revision"]
            .as_u64()
            .expect("policy_revision")
    }

    fn delegate(&mut self, subject: &str, rights: &[&str]) {
        let body = json!({
            "command":"delegate", "subject":subject, "rights":rights, "resources":[GROUP],
            "expires_at":EXPIRES, "not_before":0, "depth":4,
            "subject_key":lower_hex(identity(subject).public_key())
        });
        self.ok(ROOT, &body);
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

    /// The generation of the subject's active grant of `right`.
    fn active_generation(&mut self, subject: &str, right: &str) -> u64 {
        let checkpoint = self.checkpoint();
        checkpoint["grants"]
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

    fn prepare(&mut self, subject: &str) -> PreparedJoin<Prov> {
        let rights = self.rights_of(subject);
        let provider = self.provider(subject);
        PreparedJoin::prepare(
            GROUP,
            subject,
            &rights,
            identity(subject),
            provider,
            &self.apf_public,
        )
        .expect("prepare KeyPackage")
    }

    /// Honest candidate: prepare at the current generations, certify, finalize.
    fn candidate(&mut self, subject: &str) -> JoinCandidate<Prov> {
        let prepared = self.prepare(subject);
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

    fn submit(&mut self, actor: &str, parent: &Frontier, commit: &[u8]) -> Admitted {
        let body = json!({
            "command":"submit_commit", "kind":"admit", "parent_epoch":parent.epoch,
            "parent_branch":parent.branch, "commit":lower_hex(commit)
        });
        let response = self.ok(actor, &body);
        Admitted {
            frontier: Frontier {
                epoch: response["epoch"].as_u64().expect("response epoch"),
                branch: response["branch"]
                    .as_str()
                    .expect("response branch")
                    .to_owned(),
            },
            ack: hex::decode(response["ack"].as_str().expect("ack hex string")).expect("ack hex"),
        }
    }

    /// The APF signer, rebuilt from the test-only seed file in the temporary directory.
    /// Used only to forge validly signed but wrongly bound receipts.
    fn apf_signer(&self) -> DalekSigner {
        let seed: [u8; 32] = std::fs::read(self.dir.path().join(APF_KEY_FILE))
            .expect("APF key file")
            .try_into()
            .expect("32-byte APF seed");
        let signer = DalekSigner::from_seed(seed);
        assert_eq!(signer.public_key(), self.apf_public);
        signer
    }

    fn apf_key_id(&self) -> Vec<u8> {
        sha256(&self.apf_public)
    }

    /// The release cover (C-14): the writer singleton plus every roster reader singleton,
    /// each at its current active generation.
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

    fn allocate(&mut self, actor: &str, op: &str) {
        let response = self.ok(actor, &json!({"command":"allocate", "op":op}));
        assert_eq!(response["op"], json!(op));
    }

    /// A C-16 release body in the R-3 `policy_revision` form at the current kernel
    /// frontier, with the digest computed independently (C-14).
    fn release_body(&mut self, actor: &str, op: &str, payload: &[u8]) -> Value {
        let frontier = self.kernel_frontier();
        let policy_revision = self.policy_revision();
        let digest =
            independent_digest(op, GROUP, CONTENT_TYPE, payload, &frontier, policy_revision);
        json!({
            "command":"release", "op":op, "right":"write", "digest":digest,
            "cover":self.cover(actor), "policy_revision":policy_revision,
            "epoch":frontier.epoch, "branch":frontier.branch
        })
    }

    fn release(&mut self, actor: &str, op: &str, payload: &[u8]) -> Released {
        let body = self.release_body(actor, op, payload);
        let response = self.ok(actor, &body);
        let certificate = hex::decode(
            response["certificate"]
                .as_str()
                .expect("release response carries the certificate in hex"),
        )
        .expect("certificate is hex");
        Released {
            op: op.to_owned(),
            actor: actor.to_owned(),
            payload: payload.to_vec(),
            digest: body["digest"].as_str().expect("digest").to_owned(),
            response,
            certificate,
        }
    }

    fn persist(&mut self, actor: &str, op: &str, envelope: &[u8]) -> Value {
        let response = self.ok(actor, &persist_body(op, envelope));
        assert_eq!(response["op"], json!(op));
        response
    }

    fn emit(&mut self, actor: &str, op: &str, envelope: &[u8]) -> Value {
        let response = self.ok(actor, &emit_body(op, envelope));
        assert_eq!(response["op"], json!(op));
        assert_eq!(response["envelope"], json!(lower_hex(envelope)));
        response
    }

    /// C-16 `consume {op}` signed by `actor`; returns the receipt bytes.
    fn consume(&mut self, actor: &str, op: &str) -> Result<Vec<u8>, String> {
        let response = self.send(actor, &consume_body(op))?;
        assert_eq!(response["op"], json!(op));
        assert_eq!(
            response["recipient"],
            json!(actor),
            "recipient is the actor"
        );
        Ok(hex::decode(
            response["receipt"]
                .as_str()
                .expect("consume response carries the receipt in hex"),
        )
        .expect("receipt is hex"))
    }

    fn consumed(&mut self, actor: &str, op: &str) -> Vec<u8> {
        self.consume(actor, op)
            .unwrap_or_else(|err| panic!("{actor} consumes {op}, got {err}"))
    }
}

/// Asserts the error code, an unchanged kernel and adapter frontier, and exactly one
/// trace event whose outcome is that code.
fn rejected(w: &mut World, actor: &str, body: &Value, expected: &str) -> String {
    let before = w.checkpoint();
    let frontier = w.frontier();
    let trace_len = w.adapter.trace().len();
    let err = code(w.send(actor, body), expected);
    assert_eq!(
        w.checkpoint(),
        before,
        "rejected request ({err}) must leave the kernel unchanged"
    );
    assert_eq!(
        w.frontier(),
        frontier,
        "rejected request ({err}) must leave the adapter frontier unchanged"
    );
    let trace = w.adapter.trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!(expected), "{err}");
    err
}

/// Asserts an error whose code is one of `expected`.
fn code_in<T>(context: &str, result: Result<T, String>, expected: &[&str]) -> String {
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("{context}: should be rejected with one of {expected:?}"),
    };
    assert!(
        expected
            .iter()
            .any(|code| err == *code || err.starts_with(&format!("{code}:"))),
        "{context}: expected one of {expected:?}, got {err}"
    );
    err
}

/// Submits an honest staged Add and merges it at the committer and `others`.
fn canonical(
    w: &mut World,
    committer_name: &str,
    committer: &mut Client,
    staged: &StagedAdd,
    others: &mut [&mut Client],
) -> Admitted {
    let parent = w.frontier();
    assert_eq!(staged.parent, parent, "staged on the canonical frontier");
    let admitted = w.submit(committer_name, &staged.parent, &staged.commit);
    assert_eq!(admitted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.kernel_frontier(), admitted.frontier);
    assert_eq!(
        committer
            .apply_ack(&staged.commit, &admitted.ack)
            .expect("committer merges its acked commit"),
        admitted.frontier
    );
    for other in others.iter_mut() {
        assert_eq!(
            other
                .apply_ack(&staged.commit, &admitted.ack)
                .expect("member merges the acked commit"),
            admitted.frontier
        );
    }
    admitted
}

/// Full honest admission of `subject`, committed by `committer`.
fn admit(
    w: &mut World,
    committer_name: &str,
    committer: &mut Client,
    subject: &str,
    others: &mut [&mut Client],
) -> (Client, Admitted) {
    let candidate = w.candidate(subject);
    let staged = committer
        .stage_add(candidate.key_package())
        .expect("stage add");
    let admitted = canonical(w, committer_name, committer, &staged, others);
    let joined = candidate
        .join(&staged.welcome, &admitted.ack)
        .unwrap_or_else(|err| panic!("{subject} joins, got {err}"));
    assert_eq!(
        joined.frontier().expect("joined frontier"),
        admitted.frontier
    );
    (joined, admitted)
}

/// Protects `released` at `sender`, then persists and emits the envelope as its actor.
fn finish(w: &mut World, sender: &mut Client, released: Released) -> Published {
    let envelope = sender
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .unwrap_or_else(|err| panic!("{} protects {}, got {err}", released.actor, released.op));
    w.persist(&released.actor, &released.op, &envelope);
    w.emit(&released.actor, &released.op, &envelope);
    Published { released, envelope }
}

/// Allocate, release, protect, persist and emit one operation of `actor`.
fn publish(w: &mut World, sender: &mut Client, actor: &str, op: &str) -> Published {
    w.allocate(actor, op);
    let released = w.release(actor, op, &payload_for(op));
    finish(w, sender, released)
}

/// Receives, consumes and delivers `published` at `receiver`; returns the receipt.
fn deliver_to(w: &mut World, receiver: &mut Client, name: &str, published: &Published) -> Vec<u8> {
    let released = &published.released;
    let pending = receiver
        .receive(&published.envelope)
        .unwrap_or_else(|err| panic!("{name} receives {}, got {err}", released.op));
    assert_eq!(pending.op(), released.op);
    assert_eq!(pending.actor(), released.actor);
    let receipt = w.consumed(name, &released.op);
    let delivered = pending
        .deliver(&receipt)
        .unwrap_or_else(|err| panic!("{name} delivers {}, got {err}", released.op));
    assert_eq!(delivered, (CONTENT_TYPE.to_vec(), released.payload.clone()));
    receipt
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn released_ciphertext_aad_equals_hash_of_signed_certificate() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("aad");
    let op = "op-aad";
    let payload = payload_for(op);
    w.allocate("bob", op);
    let frontier = w.kernel_frontier();
    assert_eq!(frontier, w.frontier());
    let policy_revision = w.policy_revision();

    // C-14: the digest from the wire API equals the independent recomputation.
    let body = w.release_body("bob", op, &payload);
    let digest = body["digest"].as_str().expect("digest").to_owned();
    assert_eq!(
        operation_digest(
            op,
            GROUP,
            CONTENT_TYPE,
            &payload,
            &frontier,
            policy_revision
        )
        .expect("operation_digest"),
        digest
    );
    assert_ne!(
        independent_digest(
            op,
            GROUP,
            CONTENT_TYPE,
            b"other payload",
            &frontier,
            policy_revision
        ),
        digest,
        "the digest binds the payload"
    );

    // Kernel release through the adapter (C-16).
    let response = w.ok("bob", &body);
    assert_eq!(response["op"], json!(op));
    assert_eq!(response["digest"], json!(digest));
    assert_eq!(response["epoch"], json!(frontier.epoch));
    assert_eq!(response["branch"], json!(frontier.branch));
    assert_eq!(response["policy_revision"], json!(policy_revision));
    let event_hash = response["event_hash"]
        .as_str()
        .expect("release response event_hash")
        .to_owned();
    let checkpoint = w.checkpoint();
    let last = checkpoint["history"]
        .as_array()
        .expect("history")
        .last()
        .expect("history entry")
        .clone();
    assert_eq!(last["hash"], json!(event_hash), "release is the last event");
    assert_eq!(last["event"]["kind"], json!("release"));
    let certificate = hex::decode(
        response["certificate"]
            .as_str()
            .expect("release response carries the certificate in hex"),
    )
    .expect("certificate is hex");

    // §4.5 / C-14 fields, decoded independently.
    let expected = TestCertificate {
        apf_key_id: w.apf_key_id(),
        group: GROUP.to_owned(),
        op: op.to_owned(),
        actor: "bob".to_owned(),
        right: WRITE_CODE,
        resource: GROUP.to_owned(),
        invocation: String::new(),
        epoch: frontier.epoch,
        branch: frontier.branch.clone(),
        policy_revision,
        digest: digest.clone(),
        writer_generation: w.active_generation("bob", "write"),
        readers: vec![
            ("bob".to_owned(), w.active_generation("bob", "read")),
            ("carol".to_owned(), w.active_generation("carol", "read")),
            (ROOT.to_owned(), w.active_generation(ROOT, "read")),
        ],
        kernel_event_hash: event_hash.clone(),
    };
    assert_eq!(decode_certificate(&certificate, &w.apf_public), expected);

    // The wire API decodes the same certificate and rejects a broken signature.
    let crypto = RustCrypto::default();
    let wire = ReleaseCertificate::verify(&certificate, &w.apf_public, &crypto)
        .expect("certificate verifies under the APF key");
    assert_eq!(
        wire,
        ReleaseCertificate {
            apf_key_id: expected.apf_key_id.clone(),
            group: GROUP.to_owned(),
            op: op.to_owned(),
            actor: "bob".to_owned(),
            right: Right::Write,
            resource: GROUP.to_owned(),
            invocation: String::new(),
            frontier: frontier.clone(),
            policy_revision,
            digest: digest.clone(),
            writer_generation: expected.writer_generation,
            readers: expected.readers.clone(),
            kernel_event_hash: event_hash.clone(),
        }
    );
    code(
        ReleaseCertificate::verify(&flip_last(&certificate), &w.apf_public, &crypto),
        "unauthenticated",
    );

    // The envelope holds exactly that certificate and a PrivateMessage whose AAD is
    // SHA-256(certificate), read with raw OpenMLS.
    let envelope = bob
        .protect(&certificate, CONTENT_TYPE, &payload)
        .expect("bob protects under his certificate");
    let (envelope_certificate, mls_message) = decode_envelope(&envelope);
    assert_eq!(envelope_certificate, certificate);
    assert_eq!(
        Envelope::decode(&envelope).expect("Envelope::decode"),
        Envelope {
            certificate: certificate.clone(),
            mls_message: mls_message.clone(),
        }
    );
    assert_eq!(
        Envelope {
            certificate: certificate.clone(),
            mls_message: mls_message.clone(),
        }
        .encode()
        .expect("Envelope::encode"),
        envelope
    );
    let private = private_message(&mls_message);
    assert_eq!(private.group_id().as_slice(), GROUP.as_bytes());
    assert_eq!(private.epoch().as_u64(), frontier.epoch);
    assert_eq!(private.content_type(), ContentType::Application);
    assert_eq!(private.aad(), sha256(&certificate).as_slice());
    assert!(
        !contains(&envelope, &payload),
        "the payload is encrypted in the envelope"
    );

    w.persist("bob", op, &envelope);
    w.emit("bob", op, &envelope);

    // Raw OpenMLS at carol: authenticated AAD, sender credential and FrozenContent.
    let (aad, sender, plaintext) = raw_process(&mut carol, &mls_message);
    assert_eq!(aad, sha256(&certificate));
    assert_eq!(sender, b"bob");
    assert_eq!(plaintext, frozen(CONTENT_TYPE, &payload));
    let (content_type, decrypted) = decode_frozen(&plaintext);
    assert_eq!(
        independent_digest(
            op,
            GROUP,
            &content_type,
            &decrypted,
            &frontier,
            policy_revision
        ),
        expected.digest,
        "the digest recomputed from the decrypted FrozenContent equals the certificate's"
    );
    let frozen_content = FrozenContent {
        content_type: CONTENT_TYPE.to_vec(),
        payload: payload.clone(),
    };
    assert_eq!(
        FrozenContent::decode(&plaintext).expect("FrozenContent::decode"),
        frozen_content
    );
    assert_eq!(
        frozen_content.encode().expect("FrozenContent::encode"),
        plaintext
    );

    // The honest receive path at the root delivers the same content.
    let pending = root.receive(&envelope).expect("root receives");
    assert_eq!(pending.op(), op);
    assert_eq!(pending.actor(), "bob");
    let receipt = w.consumed(ROOT, op);
    assert_eq!(
        pending.deliver(&receipt).expect("root delivers"),
        (CONTENT_TYPE.to_vec(), payload)
    );
}

#[test]
fn receiver_delivers_plaintext_only_after_consume() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("deliver");

    // Positive: receive holds the plaintext; every reader consumes once; delivery
    // happens only with the reader's own receipt.
    let first = publish(&mut w, &mut bob, "bob", "op-1");
    assert!(!contains(&first.envelope, &first.released.payload));
    let root_pending = root.receive(&first.envelope).expect("root receives");
    let carol_pending = carol.receive(&first.envelope).expect("carol receives");
    for pending in [&root_pending, &carol_pending] {
        assert_eq!(pending.op(), "op-1");
        assert_eq!(pending.actor(), "bob");
    }
    let crypto = RustCrypto::default();
    let mut receipts: HashMap<&str, Vec<u8>> = HashMap::new();
    for reader in [ROOT, "bob", "carol"] {
        let receipt = w.consumed(reader, "op-1");
        let expected = TestReceipt {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            op: "op-1".to_owned(),
            recipient: reader.to_owned(),
            release_certificate_hash: sha256(&first.released.certificate),
        };
        assert_eq!(decode_receipt(&receipt, &w.apf_public), expected);
        assert_eq!(
            ConsumeReceipt::verify(&receipt, &w.apf_public, &crypto)
                .expect("receipt verifies under the APF key"),
            ConsumeReceipt {
                apf_key_id: expected.apf_key_id,
                group: expected.group,
                op: expected.op,
                recipient: expected.recipient,
                release_certificate_hash: expected.release_certificate_hash,
            }
        );
        receipts.insert(reader, receipt);
    }
    for reader in [ROOT, "bob", "carol"] {
        rejected(&mut w, reader, &consume_body("op-1"), "replay");
    }
    let expected_content = (CONTENT_TYPE.to_vec(), first.released.payload.clone());
    assert_eq!(
        root_pending
            .deliver(&receipts[ROOT])
            .expect("root delivers with its receipt"),
        expected_content
    );
    assert_eq!(
        carol_pending
            .deliver(&receipts["carol"])
            .expect("carol delivers with her receipt"),
        expected_content
    );

    // A receipt forged with the APF key over correct fields delivers: this validates the
    // independent receipt encoding used by the forgeries below.
    let control = publish(&mut w, &mut bob, "bob", "op-control");
    let pending = root.receive(&control.envelope).expect("root receives");
    let forged = forge_receipt(
        &w.apf_signer(),
        &TestReceipt {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            op: "op-control".to_owned(),
            recipient: ROOT.to_owned(),
            release_certificate_hash: sha256(&control.released.certificate),
        },
    );
    assert_eq!(
        pending.deliver(&forged).expect("correctly bound receipt"),
        (CONTENT_TYPE.to_vec(), control.released.payload.clone())
    );

    // Negative: a failed delivery drops its plaintext, so each case uses a fresh op.
    // Bad APF signature on the real receipt.
    let second = publish(&mut w, &mut bob, "bob", "op-2");
    let pending = root.receive(&second.envelope).expect("root receives");
    let receipt = w.consumed(ROOT, "op-2");
    code(pending.deliver(&flip_last(&receipt)), "unauthenticated");

    // Correct fields signed by a key that is not the APF key.
    let third = publish(&mut w, &mut bob, "bob", "op-3");
    let pending = root.receive(&third.envelope).expect("root receives");
    let impostor = DalekSigner::from_seed([7; 32]);
    let forged = forge_receipt(
        &impostor,
        &TestReceipt {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            op: "op-3".to_owned(),
            recipient: ROOT.to_owned(),
            release_certificate_hash: sha256(&third.released.certificate),
        },
    );
    code(pending.deliver(&forged), "unauthenticated");

    // Another recipient's real receipt.
    let fourth = publish(&mut w, &mut bob, "bob", "op-4");
    let pending = root.receive(&fourth.envelope).expect("root receives");
    let carol_receipt = w.consumed("carol", "op-4");
    code(pending.deliver(&carol_receipt), "binding_mismatch");

    // The root's own real receipt for another op and certificate.
    let fifth = publish(&mut w, &mut bob, "bob", "op-5");
    let pending = root.receive(&fifth.envelope).expect("root receives");
    code(pending.deliver(&receipts[ROOT]), "binding_mismatch");

    // Validly signed, right op and recipient, another certificate hash.
    let sixth = publish(&mut w, &mut bob, "bob", "op-6");
    let pending = root.receive(&sixth.envelope).expect("root receives");
    let forged = forge_receipt(
        &w.apf_signer(),
        &TestReceipt {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            op: "op-6".to_owned(),
            recipient: ROOT.to_owned(),
            release_certificate_hash: sha256(&first.released.certificate),
        },
    );
    code(pending.deliver(&forged), "binding_mismatch");

    // Validly signed, right recipient and certificate hash, another op.
    let seventh = publish(&mut w, &mut bob, "bob", "op-7");
    let pending = root.receive(&seventh.envelope).expect("root receives");
    let forged = forge_receipt(
        &w.apf_signer(),
        &TestReceipt {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            op: "op-1".to_owned(),
            recipient: ROOT.to_owned(),
            release_certificate_hash: sha256(&seventh.released.certificate),
        },
    );
    code(pending.deliver(&forged), "binding_mismatch");
}

#[test]
fn certificate_from_another_operation_is_binding_mismatch() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("other-op");

    // Positive: two operations, each persisted with its own envelope and delivered.
    let a = publish(&mut w, &mut bob, "bob", "op-a");
    let b = publish(&mut w, &mut bob, "bob", "op-b");
    deliver_to(&mut w, &mut root, ROOT, &a);
    deliver_to(&mut w, &mut root, ROOT, &b);

    // Negative, on two fresh released and unpersisted operations C and D.
    w.allocate("bob", "op-c");
    let c = w.release("bob", "op-c", &payload_for("op-c"));
    w.allocate("bob", "op-d");
    let d = w.release("bob", "op-d", &payload_for("op-d"));

    // Protecting D's content under C's certificate: the recomputed digest differs.
    code(
        bob.protect(&c.certificate, CONTENT_TYPE, &d.payload),
        "binding_mismatch",
    );
    let envelope_c = bob
        .protect(&c.certificate, CONTENT_TYPE, &c.payload)
        .expect("protect C");
    let envelope_d = bob
        .protect(&d.certificate, CONTENT_TYPE, &d.payload)
        .expect("protect D");

    // Persisting D with an envelope whose certificate belongs to C.
    rejected(
        &mut w,
        "bob",
        &persist_body("op-d", &envelope_c),
        "binding_mismatch",
    );
    // Persisting C with C's certificate paired with D's ciphertext.
    let (_, mls_d) = decode_envelope(&envelope_d);
    let mixed = envelope_bytes(&c.certificate, &mls_d);
    rejected(
        &mut w,
        "bob",
        &persist_body("op-c", &mixed),
        "binding_mismatch",
    );
    // A receiver given the mixed envelope rejects it.
    let before = w.checkpoint();
    code(carol.receive(&mixed), "binding_mismatch");
    assert_eq!(w.checkpoint(), before);

    // The honest envelopes still persist and deliver afterwards.
    let c = finish_with(&mut w, c, envelope_c);
    let d = finish_with(&mut w, d, envelope_d);
    deliver_to(&mut w, &mut root, ROOT, &c);
    deliver_to(&mut w, &mut root, ROOT, &d);
}

/// Persists and emits an envelope already protected for `released`.
fn finish_with(w: &mut World, released: Released, envelope: Vec<u8>) -> Published {
    w.persist(&released.actor, &released.op, &envelope);
    w.emit(&released.actor, &released.op, &envelope);
    Published { released, envelope }
}

#[test]
fn ciphertext_protected_outside_the_adapter_is_not_delivered() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("outside");

    // Positive.
    let honest = publish(&mut w, &mut bob, "bob", "op-honest");
    deliver_to(&mut w, &mut root, ROOT, &honest);

    // Arbitrary AAD over correct FrozenContent, wrapped with the genuine certificate.
    w.allocate("bob", "op-forged");
    let released = w.release("bob", "op-forged", &payload_for("op-forged"));
    let content = frozen(CONTENT_TYPE, &released.payload);
    let arbitrary = raw_application(&mut bob, Some(b"arbitrary aad".to_vec()), &content);
    assert_eq!(private_message(&arbitrary).aad(), b"arbitrary aad");
    let envelope = envelope_bytes(&released.certificate, &arbitrary);
    rejected(
        &mut w,
        "bob",
        &persist_body("op-forged", &envelope),
        "binding_mismatch",
    );
    // MLS processing succeeds, so the AAD check (C-18) decides: binding_mismatch.
    let before = w.checkpoint();
    code(root.receive(&envelope), "binding_mismatch");
    assert_eq!(w.checkpoint(), before);

    // No AAD at all.
    let empty = raw_application(&mut bob, None, &content);
    assert!(private_message(&empty).aad().is_empty());
    let envelope = envelope_bytes(&released.certificate, &empty);
    rejected(
        &mut w,
        "bob",
        &persist_body("op-forged", &envelope),
        "binding_mismatch",
    );
    code(root.receive(&envelope), "binding_mismatch");

    // The right AAD over a plaintext that is not FrozenContent. The adapter cannot see
    // the plaintext, so only the receiver's digest check applies.
    let aad = sha256(&released.certificate);
    let raw = raw_application(&mut bob, Some(aad.clone()), b"raw application bytes");
    code(
        root.receive(&envelope_bytes(&released.certificate, &raw)),
        "binding_mismatch",
    );

    // The right AAD over FrozenContent that is not the frozen payload.
    let swapped = raw_application(
        &mut bob,
        Some(aad),
        &frozen(CONTENT_TYPE, b"payload that was never released"),
    );
    code(
        root.receive(&envelope_bytes(&released.certificate, &swapped)),
        "binding_mismatch",
    );

    // The kernel is unchanged: the operation is still released and not persisted.
    assert_eq!(w.checkpoint(), before);
    rejected(&mut w, ROOT, &consume_body("op-forged"), "not_persisted");

    // The honest envelope for the same operation is still accepted and delivered.
    let honest = finish(&mut w, &mut bob, released);
    deliver_to(&mut w, &mut root, ROOT, &honest);
}

#[test]
fn sender_leaf_incarnation_not_matching_actor_is_rejected() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("incarnation");

    // Positive.
    let honest = publish(&mut w, &mut bob, "bob", "op-bob-1");
    deliver_to(&mut w, &mut root, ROOT, &honest);

    // Carol's honest endpoint refuses bob's certificate.
    w.allocate("bob", "op-bob-2");
    let released = w.release("bob", "op-bob-2", &payload_for("op-bob-2"));
    code(
        carol.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );

    // Carol bypasses `protect` with raw OpenMLS: right AAD, right FrozenContent.
    let mls_message = raw_application(
        &mut carol,
        Some(sha256(&released.certificate)),
        &frozen(CONTENT_TYPE, &released.payload),
    );
    let forged = envelope_bytes(&released.certificate, &mls_message);
    let before = w.checkpoint();
    code(root.receive(&forged), "binding_mismatch");
    assert_eq!(w.checkpoint(), before);

    // Bob's own envelope for the same certificate is delivered.
    let honest = finish(&mut w, &mut bob, released);
    deliver_to(&mut w, &mut root, ROOT, &honest);
}

#[test]
fn write_revocation_blocks_delivery_of_stale_writer_generation() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("stale-writer");

    // Positive, on another operation.
    let before = publish(&mut w, &mut bob, "bob", "op-before");
    let root_receipt = deliver_to(&mut w, &mut root, ROOT, &before);
    deliver_to(&mut w, &mut carol, "carol", &before);

    // Bob's release is persisted, then the root revokes bob's write.
    let stale = publish(&mut w, &mut bob, "bob", "op-stale");
    let frontier = w.kernel_frontier();
    w.revoke("bob", "write");
    assert_eq!(
        w.kernel_frontier(),
        frontier,
        "write revocation keeps the frontier"
    );
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));

    // The receivers cannot see the revocation; the kernel writer generation check can.
    let root_pending = root
        .receive(&stale.envelope)
        .expect("the envelope still passes the client checks");
    let carol_pending = carol
        .receive(&stale.envelope)
        .expect("the envelope still passes the client checks");
    rejected(&mut w, ROOT, &consume_body("op-stale"), "unauthorized");
    rejected(&mut w, "carol", &consume_body("op-stale"), "unauthorized");
    // Nothing is delivered: the only receipts that exist are for another operation.
    code(root_pending.deliver(&root_receipt), "binding_mismatch");
    drop(carol_pending);

    // Bob can no longer release, even with the cover of his revoked generation.
    w.allocate("bob", "op-after");
    let policy_revision = w.policy_revision();
    let mut cover = vec![json!([{"subject":"bob", "right":"write", "generation":0}])];
    for reader in [ROOT, "bob", "carol"] {
        cover.push(json!([{
            "subject":reader, "right":"read",
            "generation":w.active_generation(reader, "read")
        }]));
    }
    let body = json!({
        "command":"release", "op":"op-after", "right":"write",
        "digest":independent_digest(
            "op-after", GROUP, CONTENT_TYPE, b"x", &frontier, policy_revision
        ),
        "cover":cover, "policy_revision":policy_revision,
        "epoch":frontier.epoch, "branch":frontier.branch
    });
    rejected(&mut w, "bob", &body, "unauthorized");
}

#[test]
fn duplicate_delivery_is_replay() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("replay");

    // Positive.
    let published = publish(&mut w, &mut bob, "bob", "op-once");
    deliver_to(&mut w, &mut root, ROOT, &published);

    // A second consume by the same reader.
    rejected(&mut w, ROOT, &consume_body("op-once"), "replay");
    // The same envelope again: MLS deleted the message key, so no plaintext.
    let before = w.checkpoint();
    code(root.receive(&published.envelope), "undecryptable");
    assert_eq!(w.checkpoint(), before);

    // Another reader still consumes once, then also replays.
    deliver_to(&mut w, &mut carol, "carol", &published);
    rejected(&mut w, "carol", &consume_body("op-once"), "replay");
    code(carol.receive(&published.envelope), "undecryptable");
}

#[test]
fn one_operation_cannot_persist_two_different_ciphertexts() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("two-ciphertexts");
    w.allocate("bob", "op-twice");
    let released = w.release("bob", "op-twice", &payload_for("op-twice"));

    let first = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("first protect");
    let second = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("second protect");
    assert_ne!(first, second, "two protections give two ciphertexts");
    let (first_certificate, first_mls) = decode_envelope(&first);
    let (second_certificate, second_mls) = decode_envelope(&second);
    assert_eq!(first_certificate, released.certificate);
    assert_eq!(second_certificate, released.certificate);
    assert_ne!(first_mls, second_mls);
    for mls_message in [&first_mls, &second_mls] {
        assert_eq!(
            private_message(mls_message).aad(),
            sha256(&released.certificate).as_slice()
        );
    }

    // Positive: the first persists, and the same bytes persist again idempotently.
    w.persist("bob", "op-twice", &first);
    // Negative: the second ciphertext for the same operation.
    rejected(
        &mut w,
        "bob",
        &persist_body("op-twice", &second),
        "binding_mismatch",
    );
    rejected(
        &mut w,
        "bob",
        &emit_body("op-twice", &second),
        "binding_mismatch",
    );
    w.persist("bob", "op-twice", &first);
    w.emit("bob", "op-twice", &first);

    let published = Published {
        released,
        envelope: first,
    };
    deliver_to(&mut w, &mut root, ROOT, &published);
}

#[test]
fn retransmission_is_byte_identical() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("retransmit");
    let published = publish(&mut w, &mut bob, "bob", "op-retransmit");

    // Positive: the exact persisted bytes are emitted repeatedly without a kernel change.
    let before = w.checkpoint();
    for _ in 0..3 {
        w.emit("bob", "op-retransmit", &published.envelope);
    }
    assert_eq!(
        w.checkpoint(),
        before,
        "retransmission is not a kernel transition"
    );

    // Negative: a different, validly protected envelope for the same certificate.
    let other = bob
        .protect(
            &published.released.certificate,
            CONTENT_TYPE,
            &published.released.payload,
        )
        .expect("second protect");
    assert_ne!(other, published.envelope);
    rejected(
        &mut w,
        "bob",
        &emit_body("op-retransmit", &other),
        "binding_mismatch",
    );

    // Receivers process retransmitted copies of the same bytes.
    deliver_to(&mut w, &mut root, ROOT, &published);
    deliver_to(&mut w, &mut carol, "carol", &published);
}

#[test]
fn pre_cut_release_delivers_late_within_same_frontier() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("late-same-frontier");

    // Release, persist and emit before the cut.
    let published = publish(&mut w, &mut bob, "bob", "op-precut");
    w.allocate("bob", "op-old-policy");
    let old_policy_body = w.release_body("bob", "op-old-policy", &payload_for("op-old-policy"));
    let frontier = w.kernel_frontier();
    let policy_revision = w.policy_revision();
    let writer = w.active_generation("bob", "write");
    let readers: Vec<u64> = [ROOT, "bob", "carol"]
        .iter()
        .map(|r| w.active_generation(r, "read"))
        .collect();

    // An unrelated policy change: it moves the policy revision only.
    w.revoke("carol", "admit");
    assert_eq!(w.kernel_frontier(), frontier);
    assert_eq!(w.policy_revision(), policy_revision + 1);
    assert_eq!(w.active_generation("bob", "write"), writer);
    let after: Vec<u64> = [ROOT, "bob", "carol"]
        .iter()
        .map(|r| w.active_generation(r, "read"))
        .collect();
    assert_eq!(after, readers);
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));
    // The cut is real: a new release at the old policy revision is stale.
    rejected(&mut w, "bob", &old_policy_body, "stale_frontier");

    // The late envelope is still retransmitted, received, consumed and delivered.
    w.emit("bob", "op-precut", &published.envelope);
    deliver_to(&mut w, &mut root, ROOT, &published);
    deliver_to(&mut w, &mut carol, "carol", &published);
}

#[test]
fn pre_cut_release_is_not_delivered_across_a_frontier_change() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("frontier-cut");
    w.delegate("dave", &["read", "write", "admit"]);

    // Positive at the old frontier.
    let delivered = publish(&mut w, &mut bob, "bob", "op-before-cut");
    deliver_to(&mut w, &mut root, ROOT, &delivered);
    deliver_to(&mut w, &mut carol, "carol", &delivered);

    // Release and persist, then admit dave: the frontier changes and members merge.
    let stale = publish(&mut w, &mut bob, "bob", "op-stale-frontier");
    let old_frontier = w.kernel_frontier();
    let (mut dave, admitted) = admit(&mut w, ROOT, &mut root, "dave", &mut [&mut bob, &mut carol]);
    assert_ne!(admitted.frontier, old_frontier);
    assert_eq!(w.kernel_frontier(), admitted.frontier);

    // The old envelope is not delivered.
    let before = w.checkpoint();
    for (name, client) in [
        (ROOT, &mut root),
        ("carol", &mut carol),
        ("dave", &mut dave),
    ] {
        code_in(
            name,
            client.receive(&stale.envelope),
            &["binding_mismatch", "undecryptable"],
        );
    }
    assert_eq!(w.checkpoint(), before);
    rejected(
        &mut w,
        ROOT,
        &consume_body("op-stale-frontier"),
        "binding_mismatch",
    );
    rejected(
        &mut w,
        "carol",
        &consume_body("op-stale-frontier"),
        "binding_mismatch",
    );
    rejected(
        &mut w,
        "bob",
        &emit_body("op-stale-frontier", &stale.envelope),
        "binding_mismatch",
    );

    // A new release at the new frontier covers dave and is delivered to every reader.
    let fresh = publish(&mut w, &mut bob, "bob", "op-after-cut");
    let certificate = decode_certificate(&fresh.released.certificate, &w.apf_public);
    assert_eq!(certificate.epoch, admitted.frontier.epoch);
    assert_eq!(certificate.branch, admitted.frontier.branch);
    assert_eq!(
        certificate
            .readers
            .iter()
            .map(|(subject, _)| subject.as_str())
            .collect::<Vec<_>>(),
        vec!["bob", "carol", "dave", ROOT]
    );
    deliver_to(&mut w, &mut root, ROOT, &fresh);
    deliver_to(&mut w, &mut carol, "carol", &fresh);
    deliver_to(&mut w, &mut dave, "dave", &fresh);
}

#[test]
fn invocation_provenance_appears_in_the_release_certificate() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("invocation");

    // A direct release carries an empty invocation.
    let direct = publish(&mut w, &mut bob, "bob", "op-direct");
    let certificate = decode_certificate(&direct.released.certificate, &w.apf_public);
    assert_eq!(certificate.actor, "bob");
    assert_eq!(certificate.invocation, "");
    assert_eq!(direct.released.response["invocation"], Value::Null);
    deliver_to(&mut w, &mut root, ROOT, &direct);

    // Origin bob invokes executor carol, who allocates and releases under it.
    let invocation = w.ok(
        "bob",
        &json!({"command":"invoke", "executor":"carol", "rights":["write"],
                "resources":[GROUP]}),
    );
    let id = invocation["invocation"]
        .as_str()
        .expect("invocation id")
        .to_owned();
    let response = w.ok(
        "carol",
        &json!({"command":"allocate", "op":"op-invoked", "invocation":id}),
    );
    assert_eq!(response["op"], json!("op-invoked"));
    let released = w.release("carol", "op-invoked", &payload_for("op-invoked"));
    assert_eq!(released.response["invocation"], json!(id));
    assert_eq!(released.response["executor"], json!("carol"));

    let certificate = decode_certificate(&released.certificate, &w.apf_public);
    assert_eq!(certificate.actor, "carol");
    assert_eq!(certificate.invocation, id);
    assert_eq!(certificate.digest, released.digest);
    assert_eq!(
        certificate.writer_generation,
        w.active_generation("carol", "write")
    );
    let wire =
        ReleaseCertificate::verify(&released.certificate, &w.apf_public, &RustCrypto::default())
            .expect("certificate verifies");
    assert_eq!(wire.invocation, id);
    assert_eq!(wire.actor, "carol");

    // The executor protects and persists; the origin and the root receive it.
    let invoked = finish(&mut w, &mut carol, released);
    deliver_to(&mut w, &mut root, ROOT, &invoked);
    deliver_to(&mut w, &mut bob, "bob", &invoked);
}

#[test]
fn only_the_allocating_actor_may_release_persist_emit_or_abandon() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("ownership");

    // Positive: bob releases, persists and emits his op, and abandons another one.
    let owned = publish(&mut w, &mut bob, "bob", "op-owned");
    w.allocate("bob", "op-abandoned");
    w.release("bob", "op-abandoned", &payload_for("op-abandoned"));
    let response = w.ok("bob", &abandon_body("op-abandoned"));
    assert_eq!(response["op"], json!("op-abandoned"));

    // Negative: another actor acts on bob's operations.
    w.allocate("bob", "op-unreleased");
    w.allocate("bob", "op-released");
    let released = w.release("bob", "op-released", &payload_for("op-released"));
    let envelope = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("bob protects");
    for intruder in ["carol", ROOT] {
        // A well-formed release with the intruder as writer.
        let body = w.release_body(intruder, "op-unreleased", &payload_for("op-unreleased"));
        rejected(&mut w, intruder, &body, "unauthorized");
        rejected(
            &mut w,
            intruder,
            &persist_body("op-released", &envelope),
            "unauthorized",
        );
        rejected(
            &mut w,
            intruder,
            &abandon_body("op-released"),
            "unauthorized",
        );
        rejected(
            &mut w,
            intruder,
            &emit_body("op-owned", &owned.envelope),
            "unauthorized",
        );
    }
    // Bob still owns every one of them.
    w.release("bob", "op-unreleased", &payload_for("op-unreleased"));
    let released = finish_with(&mut w, released, envelope);
    w.emit("bob", "op-owned", &owned.envelope);
    deliver_to(&mut w, &mut root, ROOT, &released);

    // Any roster reader consumes, as itself; a body naming a recipient is malformed.
    deliver_to(&mut w, &mut root, ROOT, &owned);
    rejected(
        &mut w,
        "carol",
        &json!({"command":"consume", "op":"op-owned", "recipient":"carol"}),
        "malformed",
    );
    rejected(
        &mut w,
        "carol",
        &json!({"command":"consume", "op":"op-owned", "recipient":ROOT}),
        "malformed",
    );
    w.consumed("carol", "op-owned");

    // A release in the state-revision form is malformed; reserved fields too (C-2).
    w.allocate("bob", "op-revision");
    let body = w.release_body("bob", "op-revision", &payload_for("op-revision"));
    let revision = w.checkpoint()["revision"].as_u64().expect("revision");
    let mut with_revision = body.clone();
    let fields = with_revision.as_object_mut().expect("body object");
    fields.remove("policy_revision");
    fields.insert("revision".into(), json!(revision));
    rejected(&mut w, "bob", &with_revision, "malformed");
    let mut with_both = body.clone();
    with_both
        .as_object_mut()
        .expect("body object")
        .insert("revision".into(), json!(revision));
    rejected(&mut w, "bob", &with_both, "malformed");
    let mut with_actor = body.clone();
    with_actor
        .as_object_mut()
        .expect("body object")
        .insert("actor".into(), json!("bob"));
    rejected(&mut w, "bob", &with_actor, "malformed");
    let response = w.ok("bob", &body);
    assert_eq!(response["op"], json!("op-revision"));
}
