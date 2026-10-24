//! Phase 4.4b contract tests: non-read re-authorization of a current member through a
//! rekey (`docs/adapter-contract.md` §4.12 C-25 as amended by C-28 and amendment A-3,
//! §5.5, §13 D-9; `docs/authority-contract.md` R-10).
//!
//! Flow under test: a grant to a current roster member becomes a pending offer and does
//! not reach the kernel. The member stages an update commit with a new signer
//! (`ClientEndpoint::stage_rekey`) and submits it as `submit_commit {kind: "update"}`.
//! The sequencer validates it, the kernel `rekey` applies the grant and advances the
//! frontier, and the member's registered request key is replaced by the new key.
//!
//! The `authz_incarnation` payload is encoded and decoded here with `tls_codec`,
//! independently of `src/wire.rs`. Non-canonical update commits are built with raw
//! OpenMLS through `ClientEndpoint::mls_parts_mut`, which honest code never uses. One
//! test ends by submitting a raw commit built with the honest parameters, which shows
//! that the raw builder alone does not make the variants non-canonical.
//!
//! Rejected requests are checked to leave the kernel checkpoint and the adapter
//! frontier unchanged and to add one trace event with the error code; rejected update
//! commits also leave the key registry unchanged (checked by authentication probes).
//! An accepted update is irreversible, so the honest update runs after the rejected
//! variants, in the same test and on the same state; an adapter that rejects everything
//! still fails.

mod common;

use std::collections::HashMap;

use agent_trust::adapter::{Adapter, ClientIdentity};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use agent_trust::wire::{
    AckKind, CanonicalAck, Frontier, ReleaseCertificate, Right, SignedStructure,
};
use common::{
    adapter_dir, code, lower_hex, scripted_provider, sign, FixedClock, ScriptedRand, TestProvider,
};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
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
const INC_EXT: u16 = 0xf044;

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

/// C-9 right codes, spelled out independently of `src/wire.rs`.
fn right_code(right: Right) -> u8 {
    match right.name() {
        "read" => 1,
        "write" => 2,
        "admin" => 3,
        "admit" => 4,
        other => panic!("unknown right {other}"),
    }
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

    fn finish(&self) {
        assert!(self.rest.is_empty(), "{} trailing bytes", self.rest.len());
    }
}

/// §4.3 `AuthzIncarnation`, as plain test data with right codes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestIncarnation {
    subject: String,
    rights: Vec<(u8, u64)>,
    admission_cert_hash: Vec<u8>,
}

fn encode_incarnation(incarnation: &TestIncarnation) -> Vec<u8> {
    let mut rights = Vec::new();
    for (code, generation) in &incarnation.rights {
        rights.push(*code);
        rights.extend(tls_u64(*generation));
    }
    let mut out = vec![1u8];
    out.extend(vl(incarnation.subject.as_bytes()));
    out.extend(vl(&rights));
    out.extend(vl(&incarnation.admission_cert_hash));
    out
}

fn decode_incarnation(bytes: &[u8]) -> TestIncarnation {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.u8(), 1, "authz_incarnation version");
    let subject = String::from_utf8(reader.opaque()).expect("UTF-8 subject");
    let rights_bytes = reader.opaque();
    let admission_cert_hash = reader.opaque();
    reader.finish();
    let mut rights_reader = TlsReader::new(&rights_bytes);
    let mut rights = Vec::new();
    while !rights_reader.rest.is_empty() {
        rights.push((rights_reader.u8(), rights_reader.u64()));
    }
    TestIncarnation {
        subject,
        rights,
        admission_cert_hash,
    }
}

/// Right codes and generations, sorted by code.
fn codes(rights: &[(Right, u64)]) -> Vec<(u8, u64)> {
    let mut out: Vec<(u8, u64)> = rights
        .iter()
        .map(|(right, generation)| (right_code(*right), *generation))
        .collect();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Raw OpenMLS access
// ---------------------------------------------------------------------------

fn credential_identity(credential: &Credential) -> Vec<u8> {
    BasicCredential::try_from(credential.clone())
        .expect("basic credential")
        .identity()
        .to_vec()
}

/// The payloads of every `Unknown(extension_type)` extension, in order.
fn unknown_payloads<'a>(
    extensions: impl Iterator<Item = &'a Extension>,
    extension_type: u16,
) -> Vec<Vec<u8>> {
    extensions
        .filter_map(|extension| match extension {
            Extension::Unknown(t, UnknownExtension(bytes)) if *t == extension_type => {
                Some(bytes.clone())
            }
            _ => None,
        })
        .collect()
}

/// The leaf of `subject` in `viewer`'s ratchet tree.
fn leaf_of(viewer: &mut Client, subject: &str) -> LeafNode {
    let (group, _, _) = viewer.mls_parts_mut();
    let index = group
        .members()
        .find(|member| credential_identity(&member.credential) == subject.as_bytes())
        .map(|member| member.index)
        .unwrap_or_else(|| panic!("{subject} is in the tree"));
    group
        .public_group()
        .leaf(index)
        .expect("leaf at the member index")
        .clone()
}

/// The single `authz_incarnation` of a leaf.
fn leaf_incarnation(leaf: &LeafNode) -> TestIncarnation {
    let payloads = unknown_payloads(leaf.extensions().iter(), INC_EXT);
    assert_eq!(payloads.len(), 1, "exactly one authz_incarnation");
    decode_incarnation(&payloads[0])
}

/// Extra content of a raw update commit, beyond the committer's own UpdatePath.
enum Extra {
    None,
    /// A GroupContextExtensions proposal that repeats the current extensions exactly.
    SameContextExtensions,
    /// An Add proposal for this KeyPackage.
    Add(Vec<u8>),
}

/// Builds and stages, without merging, an update commit through the raw OpenMLS group.
/// The new leaf keeps its capabilities and every extension except `authz_incarnation`,
/// which becomes `incarnation`. With `new_signer`, the commit rotates the leaf signature
/// key (`build_with_new_signer`, signed by the old key); without it, the leaf keeps the
/// old signature key.
fn raw_update(
    client: &mut Client,
    new_signer: Option<&ClientIdentity>,
    incarnation: &TestIncarnation,
    extra: Extra,
) -> Vec<u8> {
    try_raw_update(client, new_signer, incarnation, extra).expect("build update commit")
}

/// Like [`raw_update`], but returns the error when OpenMLS refuses to build the commit.
fn try_raw_update(
    client: &mut Client,
    new_signer: Option<&ClientIdentity>,
    incarnation: &TestIncarnation,
    extra: Extra,
) -> Result<Vec<u8>, CreateCommitError> {
    let subject = client.subject().to_owned();
    let incarnation = encode_incarnation(incarnation);
    let (group, provider, signer) = client.mls_parts_mut();
    let own = group.own_leaf_node().expect("own leaf").clone();
    let leaf_extensions: Vec<Extension> = own
        .extensions()
        .iter()
        .map(|extension| match extension {
            Extension::Unknown(t, _) if *t == INC_EXT => {
                Extension::Unknown(INC_EXT, UnknownExtension(incarnation.clone()))
            }
            other => other.clone(),
        })
        .collect();
    let parameters = LeafNodeParameters::builder()
        .with_capabilities(own.capabilities().clone())
        .with_extensions(Extensions::from_vec(leaf_extensions).expect("leaf extensions"))
        .build();
    let context_extensions = group.public_group().group_context().extensions().clone();
    let key_package = match &extra {
        Extra::Add(bytes) => Some(
            KeyPackageIn::tls_deserialize_exact(bytes.as_slice())
                .expect("KeyPackage decodes")
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .expect("KeyPackage validates"),
        ),
        _ => None,
    };

    let mut builder = group.commit_builder();
    match extra {
        Extra::None => {}
        Extra::SameContextExtensions => {
            builder = builder
                .propose_group_context_extensions(context_extensions)
                .expect("propose GroupContextExtensions");
        }
        Extra::Add(_) => {
            builder = builder.propose_adds(key_package);
        }
    }
    let builder = builder
        .leaf_node_parameters(parameters)
        .force_self_update(true)
        .load_psks(provider.storage())
        .expect("load psks");
    let complete = match new_signer {
        Some(new) => builder.build_with_new_signer(
            provider.rand(),
            provider.crypto(),
            signer,
            NewSignerBundle {
                signer: new.signer(),
                credential_with_key: CredentialWithKey {
                    credential: BasicCredential::new(subject.into_bytes()).into(),
                    signature_key: new.public_key().to_vec().into(),
                },
            },
            |_| true,
        ),
        None => builder.build(provider.rand(), provider.crypto(), signer, |_| true),
    }?;
    Ok(complete
        .stage_commit(provider)
        .expect("stage update commit")
        .commit()
        .tls_serialize_detached()
        .expect("serialize commit"))
}

// ---------------------------------------------------------------------------
// Identities, providers and the test world (pattern of `tests/adapter_repair.rs`)
// ---------------------------------------------------------------------------

/// The deterministic identity derived from `label`: one label, one key.
fn identity_from(label: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(label.as_bytes())).expect("client identity")
}

/// The label of a subject's original (first registered) identity.
fn original_label(name: &str) -> String {
    format!("rekey-identity/{name}")
}

/// A subject's original identity.
fn identity(name: &str) -> ClientIdentity {
    identity_from(&original_label(name))
}

/// The label of a new identity for a rekey of `name`.
fn new_label(name: &str, tag: &str) -> String {
    format!("rekey-identity/{name}/new/{tag}")
}

fn client_provider(label: &str) -> Prov {
    TestProvider::new(ScriptedRand::new(
        format!("rekey-provider/{label}").as_bytes(),
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
struct Accepted {
    frontier: Frontier,
    ack: Vec<u8>,
}

/// A C-20 repair plan.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Plan {
    removed: Vec<String>,
    acc_context: Vec<u8>,
    parent: Frontier,
}

/// A kernel release accepted by the adapter, with the certificate it returned.
#[derive(Clone, Debug)]
struct Released {
    op: String,
    actor: String,
    payload: Vec<u8>,
    certificate: Vec<u8>,
}

/// A release whose envelope was protected, persisted and emitted.
#[derive(Clone, Debug)]
struct Published {
    released: Released,
    envelope: Vec<u8>,
}

struct World {
    tag: String,
    /// Keeps the adapter's temporary directory alive.
    _dir: tempfile::TempDir,
    adapter: TestAdapter,
    apf_public: Vec<u8>,
    seqs: HashMap<String, u64>,
    /// The label of each actor's currently registered identity, when it is not the
    /// original one.
    keys: HashMap<String, String>,
    providers: u64,
}

/// Genesis with the root; bob, carol and dave delegated `read`, `write` and `admit`;
/// bob and carol admitted by the root, dave not admitted.
struct Setup {
    w: World,
    root: Client,
    bob: Client,
    carol: Client,
}

/// Full genesis (§5.1).
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(format!("rekey-apf/{tag}").as_bytes());
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
    let acc_context = pending.acc_context().to_vec();
    let root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        client_provider(&format!("{tag}/root")),
        &founder_certificate,
        &acc_context,
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
            _dir: dir,
            adapter,
            apf_public,
            seqs: HashMap::new(),
            keys: HashMap::new(),
            providers: 0,
        },
        root,
    )
}

fn setup(tag: &str) -> Setup {
    let (mut w, mut root) = genesis(tag);
    for subject in ["bob", "carol", "dave"] {
        w.delegate(subject, &["read", "write", "admit"]);
    }
    let mut bob = admit(&mut w, &mut root, "bob", &mut []);
    let carol = admit(&mut w, &mut root, "carol", &mut [&mut bob]);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["roster"], json!([ROOT, "bob", "carol"]));
    assert_eq!(checkpoint["epoch"], json!(2));
    assert_eq!(checkpoint["read_fenced"], json!(false));
    Setup {
        w,
        root,
        bob,
        carol,
    }
}

fn update_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"update", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn admit_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"admit", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn repair_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"repair", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn grant_body(subject: &str, right: &str, generation: u64) -> Value {
    json!({"command":"grant", "subject":subject, "right":right,
           "generation":generation, "fresh_keys":true})
}

fn probe_body() -> Value {
    json!({"command":"repair_plan"})
}

fn payload_for(op: &str) -> Vec<u8> {
    format!("frozen payload of {op}").into_bytes()
}

fn accepted_from(response: &Value) -> Accepted {
    Accepted {
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

/// `rights` with `(right, generation)` set: replaced if `right` is present, else added.
fn rights_with(rights: &[(Right, u64)], offered: (Right, u64)) -> Vec<(Right, u64)> {
    let mut out: Vec<(Right, u64)> = rights
        .iter()
        .copied()
        .filter(|(right, _)| *right != offered.0)
        .collect();
    out.push(offered);
    out.sort();
    out
}

impl World {
    fn provider(&mut self, name: &str) -> Prov {
        self.providers += 1;
        client_provider(&format!("{}/{}/{}", self.tag, name, self.providers))
    }

    /// The actor's currently registered identity, as far as the test knows.
    fn current_identity(&self, actor: &str) -> ClientIdentity {
        match self.keys.get(actor) {
            Some(label) => identity_from(label),
            None => identity(actor),
        }
    }

    /// Signs `body` as `actor` with `signer_identity` at the actor's next sequence.
    fn send_with(
        &mut self,
        actor: &str,
        signer_identity: &ClientIdentity,
        body: &Value,
    ) -> Result<Value, String> {
        let sequence = self.seqs.entry(actor.to_owned()).or_insert(0);
        *sequence += 1;
        let request = sign(signer_identity.signer(), GROUP, actor, *sequence, body);
        self.adapter.handle(&request)
    }

    /// Signs `body` with the actor's current identity and handles it.
    fn send(&mut self, actor: &str, body: &Value) -> Result<Value, String> {
        let signer_identity = self.current_identity(actor);
        self.send_with(actor, &signer_identity, body)
    }

    fn ok(&mut self, actor: &str, body: &Value) -> Value {
        self.send(actor, body)
            .unwrap_or_else(|err| panic!("{actor} request {body} should succeed, got {err}"))
    }

    /// True unless the adapter refuses `actor` signing with `signer_identity` as
    /// `unauthenticated`. The probe body is read-only.
    fn authenticates(&mut self, actor: &str, signer_identity: &ClientIdentity) -> bool {
        match self.send_with(actor, signer_identity, &probe_body()) {
            Err(err) => !(err == "unauthenticated" || err.starts_with("unauthenticated:")),
            Ok(_) => true,
        }
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

    fn roster(&mut self) -> Vec<String> {
        self.checkpoint()["roster"]
            .as_array()
            .expect("roster")
            .iter()
            .map(|name| name.as_str().expect("roster name").to_owned())
            .collect()
    }

    fn delegate(&mut self, subject: &str, rights: &[&str]) {
        let body = json!({
            "command":"delegate", "subject":subject, "rights":rights, "resources":[GROUP],
            "expires_at":EXPIRES, "not_before":0, "depth":4,
            "subject_key":lower_hex(identity(subject).public_key())
        });
        self.ok(ROOT, &body);
    }

    fn revoke(&mut self, subject: &str, right: &str) -> Value {
        self.ok(
            ROOT,
            &json!({"command":"revoke", "subject":subject, "right":right}),
        )
    }

    /// The kernel grant record of `subject` for `right`, active or not.
    fn grant_record(&mut self, subject: &str, right: &str) -> Option<Value> {
        let checkpoint = self.checkpoint();
        checkpoint["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .find(|g| g["subject"] == json!(subject) && g["right"] == json!(right))
            .cloned()
    }

    /// The latest generation of `subject`'s `right`, active or not.
    fn generation(&mut self, subject: &str, right: &str) -> u64 {
        self.grant_record(subject, right)
            .and_then(|g| g["generation"].as_u64())
            .unwrap_or_else(|| panic!("{subject} has a {right} grant record"))
    }

    fn active(&mut self, subject: &str, right: &str) -> bool {
        self.grant_record(subject, right)
            .is_some_and(|g| g["active"] == json!(true))
    }

    /// The subject's active kernel rights and generations, sorted.
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

    fn prepare_with(&mut self, subject: &str, rights: &[(Right, u64)]) -> PreparedJoin<Prov> {
        let provider = self.provider(subject);
        PreparedJoin::prepare(
            GROUP,
            subject,
            rights,
            identity(subject),
            provider,
            &self.apf_public,
        )
        .expect("prepare KeyPackage")
    }

    /// Certifies `prepared` at the current generations and finalizes it.
    fn certify(&mut self, subject: &str, prepared: PreparedJoin<Prov>) -> JoinCandidate<Prov> {
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

    /// Honest candidate: prepare at the current generations, certify, finalize.
    fn candidate(&mut self, subject: &str) -> JoinCandidate<Prov> {
        let rights = self.rights_of(subject);
        let prepared = self.prepare_with(subject, &rights);
        self.certify(subject, prepared)
    }

    /// C-20 `repair_plan {}` sent by `actor`.
    fn plan(&mut self, actor: &str) -> Plan {
        let response = self.ok(actor, &probe_body());
        Plan {
            removed: response["removed"]
                .as_array()
                .expect("removed list")
                .iter()
                .map(|name| name.as_str().expect("removed name").to_owned())
                .collect(),
            acc_context: hex::decode(
                response["acc_context"]
                    .as_str()
                    .expect("acc_context hex string"),
            )
            .expect("acc_context is hex"),
            parent: Frontier {
                epoch: response["parent_epoch"].as_u64().expect("parent_epoch"),
                branch: response["parent_branch"]
                    .as_str()
                    .expect("parent_branch")
                    .to_owned(),
            },
        }
    }

    fn submit_admit(&mut self, actor: &str, parent: &Frontier, commit: &[u8]) -> Accepted {
        let response = self.ok(actor, &admit_body(parent, commit));
        accepted_from(&response)
    }

    /// `confirm_repair` with the member's own honest confirmation.
    fn confirm(&mut self, member: &mut Client) -> Value {
        let actor = member.subject().to_owned();
        let confirmation = member
            .confirmation()
            .unwrap_or_else(|err| panic!("{actor} builds its confirmation, got {err}"));
        self.ok(
            &actor,
            &json!({"command":"confirm_repair", "confirmation":lower_hex(&confirmation)}),
        )
    }

    fn verify_ack(&self, ack: &[u8]) -> CanonicalAck {
        CanonicalAck::verify(ack, &self.apf_public, &RustCrypto::default())
            .expect("ack verifies under the APF key")
    }

    /// The release cover (C-14): the writer singleton plus every roster reader singleton,
    /// each at its latest generation (the active one for an honest release).
    fn cover(&mut self, writer: &str) -> Value {
        let mut supports = vec![json!([{
            "subject":writer, "right":"write",
            "generation":self.generation(writer, "write")
        }])];
        for reader in self.roster() {
            supports.push(json!([{
                "subject":reader, "right":"read",
                "generation":self.generation(&reader, "read")
            }]));
        }
        Value::Array(supports)
    }

    fn allocate(&mut self, actor: &str, op: &str) {
        let response = self.ok(actor, &json!({"command":"allocate", "op":op}));
        assert_eq!(response["op"], json!(op));
    }

    /// A C-16 release body at the current kernel frontier and policy revision.
    fn release_body(&mut self, actor: &str, op: &str, payload: &[u8]) -> Value {
        let frontier = self.kernel_frontier();
        let policy_revision = self.policy_revision();
        let digest = independent_digest(op, CONTENT_TYPE, payload, &frontier, policy_revision);
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
            certificate,
        }
    }

    fn consumed(&mut self, actor: &str, op: &str) -> Vec<u8> {
        let response = self.ok(actor, &json!({"command":"consume", "op":op}));
        assert_eq!(response["recipient"], json!(actor));
        hex::decode(
            response["receipt"]
                .as_str()
                .expect("consume response carries the receipt in hex"),
        )
        .expect("receipt is hex")
    }
}

/// C-14 operation digest, recomputed without `src/wire.rs`.
fn independent_digest(
    op: &str,
    content_type: &[u8],
    payload: &[u8],
    frontier: &Frontier,
    policy_revision: u64,
) -> String {
    let mut input = Vec::new();
    input.extend(vl(b"agent-trust/operation/v1"));
    input.extend(vl(op.as_bytes()));
    input.extend(vl(GROUP.as_bytes()));
    input.extend(vl(content_type));
    input.extend(vl(&sha256(payload)));
    input.extend(tls_u64(frontier.epoch));
    input.extend(vl(frontier.branch.as_bytes()));
    input.extend(tls_u64(policy_revision));
    lower_hex(&sha256(&input))
}

// ---------------------------------------------------------------------------
// Checks and flows
// ---------------------------------------------------------------------------

/// Asserts the error code, an unchanged kernel and adapter frontier, and exactly one
/// trace event whose outcome is that code. The request is signed by `signer_identity`.
fn rejected_with(
    w: &mut World,
    actor: &str,
    signer_identity: &ClientIdentity,
    body: &Value,
    expected: &str,
) -> String {
    let before = w.checkpoint();
    let frontier = w.frontier();
    let trace_len = w.adapter.trace().len();
    let err = code(w.send_with(actor, signer_identity, body), expected);
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

/// `rejected_with` signed by the actor's current identity.
fn rejected(w: &mut World, actor: &str, body: &Value, expected: &str) -> String {
    let signer_identity = w.current_identity(actor);
    rejected_with(w, actor, &signer_identity, body, expected)
}

/// C-28 offer: root grants `right` at `generation` to a current member. The response is
/// `{pending: true}`, the kernel and the frontier are unchanged, and the request adds
/// one `ok` trace event.
fn offer(w: &mut World, subject: &str, right: &str, generation: u64) {
    assert!(w.roster().contains(&subject.to_owned()), "a current member");
    let before = w.checkpoint();
    let frontier = w.frontier();
    let trace_len = w.adapter.trace().len();
    let response = w.ok(ROOT, &grant_body(subject, right, generation));
    assert_eq!(response, json!({"pending": true}));
    assert_eq!(
        w.checkpoint(),
        before,
        "an offer leaves the kernel unchanged"
    );
    assert_eq!(w.frontier(), frontier);
    let trace = w.adapter.trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!("ok"));
}

/// Revokes the member's write (no fence) and offers write at the next generation.
fn revoke_and_offer_write(w: &mut World, subject: &str) -> u64 {
    let response = w.revoke(subject, "write");
    assert_eq!(response["read_fenced"], json!(false));
    assert!(!w.active(subject, "write"));
    let generation = w.generation(subject, "write") + 1;
    offer(w, subject, "write", generation);
    generation
}

/// The incarnation an honest rekey of `member` carries: its active kernel rights with
/// `offered` set, and the `admission_cert_hash` of its current leaf.
fn honest_incarnation(
    w: &mut World,
    member: &mut Client,
    offered: (Right, u64),
) -> TestIncarnation {
    let subject = member.subject().to_owned();
    let previous = leaf_incarnation(&leaf_of(member, &subject));
    TestIncarnation {
        subject: subject.clone(),
        rights: codes(&rights_with(&w.rights_of(&subject), offered)),
        admission_cert_hash: previous.admission_cert_hash,
    }
}

/// Submits a staged update commit as the member, expects `expected`, then clears the
/// member's pending commit and checks that it stayed at its parent frontier and that
/// its registered key is unchanged: the current key still authenticates, and the key
/// of `attempted`, if any, does not authenticate as the member.
fn refused_update(
    w: &mut World,
    member: &mut Client,
    commit: &[u8],
    expected: &str,
    attempted: Option<&ClientIdentity>,
) -> String {
    let actor = member.subject().to_owned();
    let parent = member.frontier().expect("member frontier");
    assert_eq!(w.frontier(), parent, "staged on the canonical frontier");
    let err = rejected(w, &actor, &update_body(&parent, commit), expected);
    member.discard_pending().expect("discard pending commit");
    assert_eq!(member.frontier().expect("frontier"), parent);
    assert_eq!(w.frontier(), parent);
    let current = w.current_identity(&actor);
    assert!(
        w.authenticates(&actor, &current),
        "the registered key of {actor} is unchanged after {err}"
    );
    if let Some(attempted) = attempted {
        assert!(
            !w.authenticates(&actor, attempted),
            "a refused update ({err}) registers no new key for {actor}"
        );
    }
    err
}

/// Honest rekey (C-28): `stage_rekey` with a new identity from `label` and the active
/// rights with `offered` set, `submit_commit {kind: "update"}`, then `apply_ack` at the
/// member and at `others`.
fn rekey(
    w: &mut World,
    member: &mut Client,
    label: &str,
    offered: (Right, u64),
    others: &mut [&mut Client],
) -> Accepted {
    let subject = member.subject().to_owned();
    let rights = rights_with(&w.rights_of(&subject), offered);
    let new_identity = identity_from(label);
    let new_public = new_identity.public_key().to_vec();
    let parent = w.frontier();
    let policy_revision = w.policy_revision();
    let staged = member
        .stage_rekey(new_identity, &rights)
        .unwrap_or_else(|err| panic!("{subject} stages the rekey, got {err}"));
    assert_eq!(staged.parent, parent, "staged on the canonical frontier");

    let response = w.ok(&subject, &update_body(&staged.parent, &staged.commit));
    let accepted = accepted_from(&response);
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
    assert_ne!(accepted.frontier.branch, parent.branch);
    assert_eq!(w.frontier(), accepted.frontier);
    assert_eq!(w.kernel_frontier(), accepted.frontier);
    assert_eq!(w.policy_revision(), policy_revision + 1);
    assert_eq!(w.rights_of(&subject), rights, "kernel applies the offer");

    let ack = w.verify_ack(&accepted.ack);
    assert_eq!(ack.kind, AckKind::Update);
    assert_eq!(ack.parent, parent);
    assert_eq!(ack.successor, accepted.frontier);
    assert_eq!(ack.commit_hash, sha256(&staged.commit));

    assert_eq!(
        member
            .apply_ack(&staged.commit, &accepted.ack)
            .expect("member merges its acked update"),
        accepted.frontier
    );
    assert_eq!(
        member.identity().public_key(),
        new_public.as_slice(),
        "after its own ack the member's identity is the new identity"
    );
    for other in others.iter_mut() {
        assert_eq!(
            other
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges the acked update"),
            accepted.frontier
        );
    }
    w.keys.insert(subject, label.to_owned());
    accepted
}

/// Submits an honest staged Add and merges it at the committer and `others`.
fn canonical_add(
    w: &mut World,
    committer: &mut Client,
    staged: &StagedAdd,
    others: &mut [&mut Client],
) -> Accepted {
    let actor = committer.subject().to_owned();
    let parent = w.frontier();
    assert_eq!(staged.parent, parent, "staged on the canonical frontier");
    let accepted = w.submit_admit(&actor, &staged.parent, &staged.commit);
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.kernel_frontier(), accepted.frontier);
    assert_eq!(
        committer
            .apply_ack(&staged.commit, &accepted.ack)
            .expect("committer merges its acked commit"),
        accepted.frontier
    );
    for other in others.iter_mut() {
        assert_eq!(
            other
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges the acked commit"),
            accepted.frontier
        );
    }
    accepted
}

/// Full honest admission from `candidate`, committed by `committer`.
fn admit_candidate(
    w: &mut World,
    committer: &mut Client,
    candidate: JoinCandidate<Prov>,
    others: &mut [&mut Client],
) -> Client {
    let staged = committer
        .stage_add(candidate.key_package())
        .expect("stage add");
    let accepted = canonical_add(w, committer, &staged, others);
    let joined = candidate
        .join(&staged.welcome, &accepted.ack)
        .unwrap_or_else(|err| panic!("candidate joins, got {err}"));
    assert_eq!(
        joined.frontier().expect("joined frontier"),
        accepted.frontier
    );
    joined
}

fn admit(
    w: &mut World,
    committer: &mut Client,
    subject: &str,
    others: &mut [&mut Client],
) -> Client {
    let candidate = w.candidate(subject);
    admit_candidate(w, committer, candidate, others)
}

/// Repairs with a plan the committer requests and merges it at the committer and at
/// `others`. The fence stays closed.
fn commit_repair(w: &mut World, committer: &mut Client, others: &mut [&mut Client]) -> Plan {
    let actor = committer.subject().to_owned();
    let plan = w.plan(&actor);
    let staged = committer
        .stage_repair(&plan.removed, &plan.acc_context)
        .unwrap_or_else(|err| panic!("{actor} stages the planned repair, got {err}"));
    assert_eq!(staged.parent, plan.parent, "staged on the planned parent");
    let response = w
        .send(&actor, &repair_body(&staged.parent, &staged.commit))
        .unwrap_or_else(|err| panic!("{actor} repair should be canonical, got {err}"));
    let accepted = accepted_from(&response);
    assert_eq!(w.kernel_frontier(), accepted.frontier);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true), "fence stays closed");
    assert_eq!(
        checkpoint["repair_pending"],
        json!(accepted.frontier.branch)
    );
    assert_eq!(
        committer
            .apply_ack(&staged.commit, &accepted.ack)
            .expect("committer merges its acked repair"),
        accepted.frontier
    );
    for other in others.iter_mut() {
        assert_eq!(
            other
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("continuing member merges the acked repair"),
            accepted.frontier
        );
    }
    plan
}

/// The committer confirms, then another continuing member confirms and the fence opens.
fn open_fence(w: &mut World, committer: &mut Client, other: &mut Client) {
    let first = w.confirm(committer);
    assert_eq!(first["opened"], json!(false), "committer alone: {first}");
    let second = w.confirm(other);
    assert_eq!(second["opened"], json!(true), "{second}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
}

/// Protects `released` at `sender`, then persists and emits the envelope as its actor.
fn finish(w: &mut World, sender: &mut Client, released: Released) -> Published {
    let envelope = sender
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .unwrap_or_else(|err| panic!("{} protects {}, got {err}", released.actor, released.op));
    let hex_envelope = lower_hex(&envelope);
    w.ok(
        &released.actor,
        &json!({"command":"persist", "op":released.op, "envelope":hex_envelope}),
    );
    w.ok(
        &released.actor,
        &json!({"command":"emit", "op":released.op, "envelope":hex_envelope}),
    );
    Published { released, envelope }
}

/// Allocate, release, protect, persist and emit one operation of `sender`.
fn publish(w: &mut World, sender: &mut Client, op: &str) -> Published {
    let actor = sender.subject().to_owned();
    w.allocate(&actor, op);
    let released = w.release(&actor, op, &payload_for(op));
    finish(w, sender, released)
}

/// Receives, consumes and delivers `published` at `receiver`.
fn deliver_to(w: &mut World, receiver: &mut Client, published: &Published) {
    let name = receiver.subject().to_owned();
    let released = &published.released;
    let pending = receiver
        .receive(&published.envelope)
        .unwrap_or_else(|err| panic!("{name} receives {}, got {err}", released.op));
    assert_eq!(pending.op(), released.op);
    assert_eq!(pending.actor(), released.actor);
    let receipt = w.consumed(&name, &released.op);
    let delivered = pending
        .deliver(&receipt)
        .unwrap_or_else(|err| panic!("{name} delivers {}, got {err}", released.op));
    assert_eq!(delivered, (CONTENT_TYPE.to_vec(), released.payload.clone()));
}

fn writer_generation(w: &World, certificate: &[u8]) -> u64 {
    ReleaseCertificate::verify(certificate, &w.apf_public, &RustCrypto::default())
        .expect("certificate verifies")
        .writer_generation
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn reauthorized_writer_requires_update_with_new_signer() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("reauthorized");

    // Positive: bob writes at generation 0 and carol receives.
    let before = publish(&mut w, &mut bob, "op-bob-gen0");
    assert_eq!(writer_generation(&w, &before.released.certificate), 0);
    deliver_to(&mut w, &mut carol, &before);

    // Revocation and offer. The offer does not reach the kernel (checked by `offer`).
    let generation = revoke_and_offer_write(&mut w, "bob");
    assert_eq!(generation, 1);
    assert!(!w.active("bob", "write"));

    // Before the update commit bob still cannot release.
    w.allocate("bob", "op-bob-offered");
    let body = w.release_body("bob", "op-bob-offered", &payload_for("op-bob-offered"));
    rejected(&mut w, "bob", &body, "unauthorized");

    // The rekey.
    let old_public = bob.identity().public_key().to_vec();
    let previous = leaf_incarnation(&leaf_of(&mut root, "bob"));
    let label = new_label("bob", "reauthorized");
    let accepted = rekey(
        &mut w,
        &mut bob,
        &label,
        (Right::Write, 1),
        &mut [&mut root, &mut carol],
    );
    assert!(w.active("bob", "write"));
    assert_eq!(w.generation("bob", "write"), 1);
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol"]);
    for member in [&mut root, &mut bob, &mut carol] {
        assert_eq!(member.frontier().expect("frontier"), accepted.frontier);
    }

    // Every member's tree shows bob's new leaf: same credential, new key, new incarnation.
    let new_public = identity_from(&label).public_key().to_vec();
    assert_ne!(new_public, old_public);
    for viewer in [&mut root, &mut carol, &mut bob] {
        let leaf = leaf_of(viewer, "bob");
        assert_eq!(leaf.signature_key().as_slice(), new_public.as_slice());
        assert_eq!(credential_identity(leaf.credential()), b"bob");
        let incarnation = leaf_incarnation(&leaf);
        assert_eq!(incarnation.subject, "bob");
        assert_eq!(incarnation.rights, vec![(1, 0), (2, 1), (4, 0)]);
        assert_eq!(
            incarnation.admission_cert_hash, previous.admission_cert_hash,
            "the rekey keeps the admission_cert_hash"
        );
    }

    // Bob releases with his new key; carol receives at sender write generation 1.
    let after = publish(&mut w, &mut bob, "op-bob-gen1");
    assert_eq!(writer_generation(&w, &after.released.certificate), 1);
    deliver_to(&mut w, &mut carol, &after);
    deliver_to(&mut w, &mut root, &after);
}

#[test]
fn old_key_no_longer_authenticates_after_rekey() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("old-key");
    let old = identity("bob");

    // Positive: the original key authenticates bob.
    let response = w
        .send_with(
            "bob",
            &old,
            &json!({"command":"allocate", "op":"op-old-key"}),
        )
        .expect("the original key authenticates");
    assert_eq!(response["op"], json!("op-old-key"));

    revoke_and_offer_write(&mut w, "bob");
    // The offer changes no key.
    assert!(w.authenticates("bob", &old));
    let label = new_label("bob", "old-key");
    assert!(!w.authenticates("bob", &identity_from(&label)));

    rekey(
        &mut w,
        &mut bob,
        &label,
        (Right::Write, 1),
        &mut [&mut root, &mut carol],
    );

    // The old key no longer authenticates bob, for any request.
    rejected_with(
        &mut w,
        "bob",
        &old,
        &json!({"command":"allocate", "op":"op-old-key-2"}),
        "unauthenticated",
    );
    rejected_with(&mut w, "bob", &old, &probe_body(), "unauthenticated");

    // The new key does.
    let response = w
        .send_with(
            "bob",
            &identity_from(&label),
            &json!({"command":"allocate", "op":"op-new-key"}),
        )
        .expect("the new key authenticates");
    assert_eq!(response["op"], json!("op-new-key"));
    // Other members are unaffected.
    assert!(w.authenticates("carol", &identity("carol")));
}

#[test]
fn update_commit_reusing_old_signature_key_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("old-signer");
    revoke_and_offer_write(&mut w, "bob");
    let incarnation = honest_incarnation(&mut w, &mut bob, (Right::Write, 1));
    assert_eq!(incarnation.rights, vec![(1, 0), (2, 1), (4, 0)]);
    assert_eq!(
        incarnation.admission_cert_hash,
        vec![0u8; 32],
        "an admitted member's leaf carries the zero placeholder"
    );

    // A self-update that keeps the old signature key.
    let commit = raw_update(&mut bob, None, &incarnation, Extra::None);
    refused_update(&mut w, &mut bob, &commit, "noncanonical_commit", None);

    // A new-signer update whose "new" key is the old key.
    let commit = raw_update(&mut bob, Some(&identity("bob")), &incarnation, Extra::None);
    refused_update(&mut w, &mut bob, &commit, "noncanonical_commit", None);

    // A new key that is already registered to another subject. Dave is delegated, so
    // his key is in the registry, but he was never admitted, so it is in no MLS leaf:
    // OpenMLS builds the commit, and only the adapter can refuse it.
    let commit = raw_update(&mut bob, Some(&identity("dave")), &incarnation, Extra::None);
    refused_update(
        &mut w,
        &mut bob,
        &commit,
        "noncanonical_commit",
        Some(&identity("dave")),
    );

    // A new key that is already in another member's leaf, carol's or the root's.
    // OpenMLS enforces signature-key uniqueness across the tree, both when it builds a
    // commit and when it processes one (`validate_key_uniqueness`), so such a commit
    // can't be built with OpenMLS and is never accepted by an OpenMLS member.
    for other in ["carol", ROOT] {
        let err = try_raw_update(&mut bob, Some(&identity(other)), &incarnation, Extra::None)
            .expect_err("OpenMLS refuses a leaf key that another member holds");
        assert!(
            matches!(
                err,
                CreateCommitError::ProposalValidationError(
                    ProposalValidationError::DuplicateSignatureKey
                )
            ),
            "{other}: {err:?}"
        );
        assert!(!w.authenticates("bob", &identity(other)));
    }

    // The registry is unchanged: each key still authenticates only its own subject.
    assert!(w.authenticates("bob", &identity("bob")));
    assert!(w.authenticates("carol", &identity("carol")));
    assert!(w.authenticates("dave", &identity("dave")));
    assert!(w.authenticates(ROOT, &identity(ROOT)));
    assert!(!w.authenticates("carol", &identity("bob")));
    assert!(!w.active("bob", "write"));

    // The honest rekey with a fresh key is canonical on the same state.
    rekey(
        &mut w,
        &mut bob,
        &new_label("bob", "old-signer"),
        (Right::Write, 1),
        &mut [&mut root, &mut carol],
    );
    assert!(w.active("bob", "write"));
    assert!(w.authenticates("carol", &identity("carol")));
}

#[test]
fn update_commit_with_wrong_incarnation_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("incarnation");
    revoke_and_offer_write(&mut w, "bob");
    let honest = honest_incarnation(&mut w, &mut bob, (Right::Write, 1));
    assert_eq!(honest.rights, vec![(1, 0), (2, 1), (4, 0)]);

    let variants: Vec<(&str, TestIncarnation)> = vec![
        (
            "offered right missing",
            TestIncarnation {
                rights: vec![(1, 0), (4, 0)],
                ..honest.clone()
            },
        ),
        (
            "offered right at the old generation",
            TestIncarnation {
                rights: vec![(1, 0), (2, 0), (4, 0)],
                ..honest.clone()
            },
        ),
        (
            "offered right at a later generation",
            TestIncarnation {
                rights: vec![(1, 0), (2, 2), (4, 0)],
                ..honest.clone()
            },
        ),
        (
            "read at a different generation",
            TestIncarnation {
                rights: vec![(1, 1), (2, 1), (4, 0)],
                ..honest.clone()
            },
        ),
        (
            "an extra right",
            TestIncarnation {
                rights: vec![(1, 0), (2, 1), (3, 0), (4, 0)],
                ..honest.clone()
            },
        ),
        (
            "another subject",
            TestIncarnation {
                subject: "carol".to_owned(),
                ..honest.clone()
            },
        ),
        (
            "a changed admission_cert_hash",
            TestIncarnation {
                admission_cert_hash: vec![1u8; 32],
                ..honest.clone()
            },
        ),
        (
            "an empty admission_cert_hash",
            TestIncarnation {
                admission_cert_hash: Vec::new(),
                ..honest.clone()
            },
        ),
    ];
    for (index, (name, incarnation)) in variants.iter().enumerate() {
        let attempted = identity_from(&new_label("bob", &format!("incarnation-{index}")));
        let commit = raw_update(&mut bob, Some(&attempted), incarnation, Extra::None);
        let err = refused_update(
            &mut w,
            &mut bob,
            &commit,
            "noncanonical_commit",
            Some(&attempted),
        );
        assert!(!err.is_empty(), "{name}");
        assert!(!w.active("bob", "write"), "{name}");
    }

    // The same raw builder with the honest incarnation and a fresh key is canonical.
    let label = new_label("bob", "incarnation-honest");
    let fresh = identity_from(&label);
    let parent = w.frontier();
    let commit = raw_update(&mut bob, Some(&fresh), &honest, Extra::None);
    let response = w.ok("bob", &update_body(&parent, &commit));
    let accepted = accepted_from(&response);
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.kernel_frontier(), accepted.frontier);
    assert_eq!(w.generation("bob", "write"), 1);
    assert!(w.active("bob", "write"));
    assert_eq!(w.verify_ack(&accepted.ack).kind, AckKind::Update);
    for member in [&mut root, &mut carol] {
        assert_eq!(
            member
                .apply_ack(&commit, &accepted.ack)
                .expect("member merges the acked update"),
            accepted.frontier
        );
        let leaf = leaf_of(member, "bob");
        assert_eq!(leaf.signature_key().as_slice(), fresh.public_key());
        assert_eq!(leaf_incarnation(&leaf), honest);
    }
    w.keys.insert("bob".to_owned(), label);
    assert!(w.authenticates("bob", &fresh));
    assert!(!w.authenticates("bob", &identity("bob")));
}

#[test]
fn update_commit_without_offer_is_unauthorized() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("no-offer");

    // R-10 rekey is adapter-only: a worker cannot call the kernel command directly.
    let frontier = w.frontier();
    let direct = json!({
        "command":"rekey", "subject":"bob", "right":"write", "generation":1,
        "parent_branch":frontier.branch, "new_branch":"x", "epoch":frontier.epoch + 1
    });
    rejected(&mut w, ROOT, &direct, "unauthorized");

    // No offer exists at all.
    let rights = w.rights_of("carol");
    let attempted = identity_from(&new_label("carol", "no-offer-1"));
    let staged = carol
        .stage_rekey(identity_from(&new_label("carol", "no-offer-1")), &rights)
        .expect("carol stages a valid-looking update");
    refused_update(
        &mut w,
        &mut carol,
        &staged.commit,
        "unauthorized",
        Some(&attempted),
    );

    // An offer for bob does not authorize carol.
    revoke_and_offer_write(&mut w, "bob");
    let attempted = identity_from(&new_label("carol", "no-offer-2"));
    let staged = carol
        .stage_rekey(identity_from(&new_label("carol", "no-offer-2")), &rights)
        .expect("carol stages a valid-looking update");
    refused_update(
        &mut w,
        &mut carol,
        &staged.commit,
        "unauthorized",
        Some(&attempted),
    );

    // Positive: bob's offered rekey is canonical.
    rekey(
        &mut w,
        &mut bob,
        &new_label("bob", "no-offer"),
        (Right::Write, 1),
        &mut [&mut root, &mut carol],
    );

    // The offer is cleared once used: a second update from bob is unauthorized.
    let bob_rights = w.rights_of("bob");
    let attempted = identity_from(&new_label("bob", "no-offer-again"));
    let staged = bob
        .stage_rekey(
            identity_from(&new_label("bob", "no-offer-again")),
            &bob_rights,
        )
        .expect("bob stages another update");
    refused_update(
        &mut w,
        &mut bob,
        &staged.commit,
        "unauthorized",
        Some(&attempted),
    );

    // Positive for carol once she holds an offer.
    revoke_and_offer_write(&mut w, "carol");
    rekey(
        &mut w,
        &mut carol,
        &new_label("carol", "no-offer-3"),
        (Right::Write, 1),
        &mut [&mut root, &mut bob],
    );
    assert_eq!(w.generation("carol", "write"), 1);
    assert!(w.active("carol", "write"));
}

#[test]
fn update_commit_with_proposals_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("proposals");
    let dave = w.candidate("dave");
    revoke_and_offer_write(&mut w, "bob");
    let honest = honest_incarnation(&mut w, &mut bob, (Right::Write, 1));

    // A GroupContextExtensions proposal that changes nothing.
    let attempted = identity_from(&new_label("bob", "proposals-gce"));
    let commit = raw_update(
        &mut bob,
        Some(&attempted),
        &honest,
        Extra::SameContextExtensions,
    );
    refused_update(
        &mut w,
        &mut bob,
        &commit,
        "noncanonical_commit",
        Some(&attempted),
    );

    // An Add proposal for a certified candidate.
    let attempted = identity_from(&new_label("bob", "proposals-add"));
    let commit = raw_update(
        &mut bob,
        Some(&attempted),
        &honest,
        Extra::Add(dave.key_package().to_vec()),
    );
    refused_update(
        &mut w,
        &mut bob,
        &commit,
        "noncanonical_commit",
        Some(&attempted),
    );
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol"]);

    // The honest rekey, with no proposal, is canonical on the same state.
    rekey(
        &mut w,
        &mut bob,
        &new_label("bob", "proposals"),
        (Right::Write, 1),
        &mut [&mut root, &mut carol],
    );
    assert!(w.active("bob", "write"));
}

#[test]
fn rekey_while_fenced_is_read_fenced() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol,
    } = setup("fenced");
    revoke_and_offer_write(&mut w, "bob");

    // A read revocation of carol fences the group.
    let response = w.revoke("carol", "read");
    assert_eq!(response["read_fenced"], json!(true));
    let rights = rights_with(&w.rights_of("bob"), (Right::Write, 1));
    let attempted = identity_from(&new_label("bob", "fenced-1"));
    let staged = bob
        .stage_rekey(identity_from(&new_label("bob", "fenced-1")), &rights)
        .expect("bob stages the rekey");
    refused_update(
        &mut w,
        &mut bob,
        &staged.commit,
        "read_fenced",
        Some(&attempted),
    );

    // A canonical but unconfirmed repair keeps the group fenced.
    drop(carol);
    let plan = commit_repair(&mut w, &mut root, &mut [&mut bob]);
    assert_eq!(plan.removed, vec!["carol"]);
    let attempted = identity_from(&new_label("bob", "fenced-2"));
    let staged = bob
        .stage_rekey(identity_from(&new_label("bob", "fenced-2")), &rights)
        .expect("bob stages the rekey");
    refused_update(
        &mut w,
        &mut bob,
        &staged.commit,
        "read_fenced",
        Some(&attempted),
    );
    assert!(!w.active("bob", "write"));

    // Once the repair is confirmed, the still-pending offer succeeds with a commit
    // restaged at the new frontier.
    open_fence(&mut w, &mut root, &mut bob);
    rekey(
        &mut w,
        &mut bob,
        &new_label("bob", "fenced-3"),
        (Right::Write, 1),
        &mut [&mut root],
    );
    assert!(w.active("bob", "write"));
    assert_eq!(w.generation("bob", "write"), 1);
    assert_eq!(w.roster(), vec![ROOT, "bob"]);
}

#[test]
fn new_right_for_current_member_via_rekey() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("new-right");
    // frank holds direct root grants (no delegation record), so a new admin grant is
    // effective for him. A delegated member's chain is bounded by its delegation rights,
    // and `delegate` already creates generation-0 grants for every delegated right.
    let mut body = grant_body("frank", "read", 0);
    body["subject_key"] = json!(lower_hex(identity("frank").public_key()));
    w.ok(ROOT, &body);
    w.ok(ROOT, &grant_body("frank", "write", 0));
    w.ok(ROOT, &grant_body("frank", "admit", 0));
    let mut frank = admit(&mut w, &mut root, "frank", &mut [&mut bob, &mut carol]);
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "frank"]);
    assert!(w.grant_record("frank", "admin").is_none());

    // Without admin, frank's Add is refused by the kernel.
    let dave = w.candidate("dave");
    let staged = frank.stage_add(dave.key_package()).expect("stage add");
    rejected(
        &mut w,
        "frank",
        &admit_body(&staged.parent, &staged.commit),
        "unauthorized",
    );
    frank.discard_pending().expect("discard");

    // The offer of a new right at generation 0, then the rekey.
    offer(&mut w, "frank", "admin", 0);
    assert!(w.grant_record("frank", "admin").is_none());
    rekey(
        &mut w,
        &mut frank,
        &new_label("frank", "new-right"),
        (Right::Admin, 0),
        &mut [&mut root, &mut bob, &mut carol],
    );
    assert_eq!(
        w.rights_of("frank"),
        vec![
            (Right::Read, 0),
            (Right::Write, 0),
            (Right::Admin, 0),
            (Right::Admit, 0)
        ]
    );
    let leaf = leaf_of(&mut root, "frank");
    assert_eq!(
        leaf_incarnation(&leaf).rights,
        vec![(1, 0), (2, 0), (3, 0), (4, 0)]
    );

    // frank, now holding admin under his new key, admits dave canonically.
    let mut dave = admit_candidate(
        &mut w,
        &mut frank,
        dave,
        &mut [&mut root, &mut bob, &mut carol],
    );
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "frank", "dave"]);
    assert_eq!(
        dave.frontier().expect("dave frontier"),
        frank.frontier().expect("frank frontier")
    );
    let published = publish(&mut w, &mut root, "op-after-frank-add");
    deliver_to(&mut w, &mut dave, &published);
}
