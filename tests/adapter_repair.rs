//! Phase 4.4a contract tests: read revocation, repair, confirmation, the retained-key
//! adversary and read rejoin (`docs/adapter-contract.md` §4.7, §4.12 C-20 to C-25, §5.4,
//! the read part of §5.5; `docs/authority-contract.md` `revoke`, D-3, R-3).
//!
//! The `acc_context` payload, the confirmation TBS and `epoch_authenticator_hash` are
//! encoded, decoded or recomputed here with `tls_codec` and `sha2`, independently of
//! `src/wire.rs`. Raw OpenMLS state is used through `ClientEndpoint::mls_parts_mut`,
//! which honest code never uses, to build non-canonical repair commits, to read epoch
//! authenticators and to model a removed endpoint that keeps its group secrets.
//!
//! Rejected requests are checked to leave the kernel checkpoint and the adapter
//! frontier unchanged and to add one trace event with the error code. A repair changes
//! the group irreversibly, so in the repair tests the honest repair runs after the
//! rejected variants, in the same test and on the same state; an adapter that rejects
//! everything still fails.

mod common;

use std::collections::HashMap;

use agent_trust::adapter::{Adapter, ClientIdentity};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use agent_trust::wire::{
    epoch_authenticator_hash, AckKind, CanonicalAck, Frontier, ReleaseCertificate,
    RepairConfirmation, Right, SignedStructure, CONFIRM_LABEL,
};
use common::{
    adapter_dir, code, lower_hex, scripted_provider, sign, FixedClock, ScriptedRand, TestProvider,
};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
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
const T_CONFIRM_LABEL: &[u8] = b"agent-trust/confirm/v1";
const ACC_EXT: u16 = 0xf043;
const INC_EXT: u16 = 0xf044;
/// C-9 right code of `read`.
const READ_CODE: u8 = 1;

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

/// §4.2 `AccContext`, as plain test data.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TestAcc {
    version: u8,
    apf_key_id: Vec<u8>,
    group: Vec<u8>,
    policy_revision: u64,
    policy_digest: Vec<u8>,
}

fn decode_acc(bytes: &[u8]) -> TestAcc {
    let mut reader = TlsReader::new(bytes);
    let acc = TestAcc {
        version: reader.u8(),
        apf_key_id: reader.opaque(),
        group: reader.opaque(),
        policy_revision: reader.u64(),
        policy_digest: reader.opaque(),
    };
    reader.finish();
    acc
}

fn encode_acc(acc: &TestAcc) -> Vec<u8> {
    let mut out = vec![acc.version];
    out.extend(vl(&acc.apf_key_id));
    out.extend(vl(&acc.group));
    out.extend(tls_u64(acc.policy_revision));
    out.extend(vl(&acc.policy_digest));
    out
}

/// The `(right code, generation)` list of an `authz_incarnation` payload (§4.3).
fn incarnation_rights(bytes: &[u8]) -> (String, Vec<(u8, u64)>) {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.u8(), 1, "authz_incarnation version");
    let subject = reader.string();
    let rights_bytes = reader.opaque();
    let _cert_hash = reader.opaque();
    reader.finish();
    let mut rights_reader = TlsReader::new(&rights_bytes);
    let mut rights = Vec::new();
    while !rights_reader.rest.is_empty() {
        rights.push((rights_reader.u8(), rights_reader.u64()));
    }
    (subject, rights)
}

/// C-23 `ConfirmationTBS { label, group, uint64 epoch, branch (ASCII hex),
/// epoch_authenticator_hash }`, encoded without `src/wire.rs`.
fn confirmation_tbs(group: &str, frontier: &Frontier, hash: &[u8]) -> Vec<u8> {
    let mut out = vl(T_CONFIRM_LABEL);
    out.extend(vl(group.as_bytes()));
    out.extend(tls_u64(frontier.epoch));
    out.extend(vl(frontier.branch.as_bytes()));
    out.extend(vl(hash));
    out
}

/// A confirmation signed by `signer` over the independent TBS encoding.
fn independent_confirmation(
    signer: &impl Signer,
    group: &str,
    frontier: &Frontier,
    hash: &[u8],
) -> Vec<u8> {
    let mut out = confirmation_tbs(group, frontier, hash);
    let signature = signer.sign(&out).expect("test signature");
    out.extend(vl(&signature));
    out
}

/// Decodes a signed confirmation, checks its signature under `public_key`, and returns
/// `(group, frontier, epoch_authenticator_hash)`, without `src/wire.rs`.
fn decode_confirmation(bytes: &[u8], public_key: &[u8]) -> (String, Frontier, Vec<u8>) {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.opaque(), T_CONFIRM_LABEL, "confirmation label");
    let group = reader.string();
    let epoch = reader.u64();
    let branch = reader.string();
    let hash = reader.opaque();
    let tbs_len = bytes.len() - reader.rest.len();
    let signature = reader.opaque();
    reader.finish();
    assert!(
        RustCrypto::default()
            .verify_signature(
                SignatureScheme::ED25519,
                &bytes[..tbs_len],
                public_key,
                &signature
            )
            .is_ok(),
        "confirmation signature covers the TLS encoding of the TBS"
    );
    (group, Frontier { epoch, branch }, hash)
}

/// C-23 `SHA-256(label ‖ branch (ASCII hex) ‖ epoch_authenticator)`, plain concatenation.
fn independent_authenticator_hash(branch: &str, epoch_authenticator: &[u8]) -> Vec<u8> {
    let mut input = T_CONFIRM_LABEL.to_vec();
    input.extend_from_slice(branch.as_bytes());
    input.extend_from_slice(epoch_authenticator);
    sha256(&input)
}

/// The epoch authenticator hash of a member's current epoch, read with raw OpenMLS.
fn genuine_hash(client: &mut Client) -> Vec<u8> {
    let frontier = client.frontier().expect("member frontier");
    let (group, _, _) = client.mls_parts_mut();
    independent_authenticator_hash(&frontier.branch, group.epoch_authenticator().as_slice())
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

/// `Envelope { opaque certificate<V>; opaque mls_message<V>; }` (C-14).
fn decode_envelope(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut reader = TlsReader::new(bytes);
    let parts = (reader.opaque(), reader.opaque());
    reader.finish();
    parts
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

/// Credential identities of the members in the client's ratchet tree.
fn tree_members(client: &mut Client) -> Vec<String> {
    let (group, _, _) = client.mls_parts_mut();
    let mut names: Vec<String> = group
        .members()
        .map(|member| {
            String::from_utf8(credential_identity(&member.credential)).expect("UTF-8 identity")
        })
        .collect();
    names.sort();
    names
}

fn leaf_index(client: &mut Client, subject: &str) -> LeafNodeIndex {
    let (group, _, _) = client.mls_parts_mut();
    group
        .members()
        .find(|member| credential_identity(&member.credential) == subject.as_bytes())
        .map(|member| member.index)
        .unwrap_or_else(|| panic!("{subject} is in the tree"))
}

/// The client's single `acc_context` payload.
fn current_acc_bytes(client: &mut Client) -> Vec<u8> {
    let (group, _, _) = client.mls_parts_mut();
    let payloads = unknown_payloads(
        group.public_group().group_context().extensions().iter(),
        ACC_EXT,
    );
    assert_eq!(payloads.len(), 1, "exactly one acc_context");
    payloads[0].clone()
}

/// The member's current GroupContext extensions with `acc_context` replaced by `acc`.
fn extensions_with_acc(client: &mut Client, acc: &[u8]) -> Extensions<GroupContext> {
    let (group, _, _) = client.mls_parts_mut();
    let current = group.public_group().group_context().extensions().clone();
    let replaced: Vec<Extension> = current
        .iter()
        .map(|extension| match extension {
            Extension::Unknown(t, _) if *t == ACC_EXT => {
                Extension::Unknown(ACC_EXT, UnknownExtension(acc.to_vec()))
            }
            _ => extension.clone(),
        })
        .collect();
    Extensions::from_vec(replaced).expect("valid GroupContext extensions")
}

/// Builds and stages, without merging, a commit through the raw OpenMLS group: one
/// Remove per name in `removed`, a GroupContextExtensions proposal replacing
/// `acc_context` when `acc` is given, and `force_self_update(force_path)`.
fn raw_repair(
    client: &mut Client,
    removed: &[&str],
    acc: Option<&[u8]>,
    force_path: bool,
) -> Vec<u8> {
    let indices: Vec<LeafNodeIndex> = removed.iter().map(|s| leaf_index(client, s)).collect();
    let extensions = acc.map(|acc| extensions_with_acc(client, acc));
    let (group, provider, signer) = client.mls_parts_mut();
    let mut builder = group.commit_builder().propose_removals(indices);
    if let Some(extensions) = extensions {
        builder = builder
            .propose_group_context_extensions(extensions)
            .expect("propose GroupContextExtensions");
    }
    let bundle = builder
        .force_self_update(force_path)
        .load_psks(provider.storage())
        .expect("load psks")
        .build(provider.rand(), provider.crypto(), signer, |_| true)
        .expect("build commit")
        .stage_commit(provider)
        .expect("stage commit");
    bundle
        .commit()
        .tls_serialize_detached()
        .expect("serialize commit")
}

/// True if the client's own pending (staged, unmerged) commit carries an UpdatePath.
fn pending_has_path(client: &mut Client) -> bool {
    let (group, _, _) = client.mls_parts_mut();
    group
        .pending_commit()
        .expect("a staged pending commit")
        .update_path_leaf_node()
        .is_some()
}

/// An application message built directly with OpenMLS, outside `protect`.
fn raw_application(sender: &mut Client, plaintext: &[u8]) -> Vec<u8> {
    let (group, provider, signer) = sender.mls_parts_mut();
    group
        .create_message(provider, signer, plaintext)
        .expect("raw application message")
        .tls_serialize_detached()
        .expect("MLS message encoding")
}

fn protocol_message(bytes: &[u8]) -> ProtocolMessage {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("MLS message decodes")
        .try_into_protocol_message()
        .expect("protocol message")
}

/// Processes an application message with a raw OpenMLS group; returns
/// `(sender identity, plaintext)` or the OpenMLS error.
fn group_decrypt(
    group: &mut MlsGroup,
    provider: &Prov,
    mls_message: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let processed = group
        .process_message(provider, protocol_message(mls_message))
        .map_err(|err| format!("{err:?}"))?;
    let sender = credential_identity(processed.credential());
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => {
            Ok((sender, application.into_bytes()))
        }
        _ => Err("not an application message".into()),
    }
}

/// Raw OpenMLS processing at a live endpoint, outside `receive`.
fn raw_decrypt(receiver: &mut Client, mls_message: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let (group, provider, _) = receiver.mls_parts_mut();
    group_decrypt(group, provider, mls_message)
}

/// A complete byte copy of the endpoint's storage, reloaded with `MlsGroup::load`
/// outside the adapter and outside `ClientEndpoint`.
fn retained_copy(client: &mut Client, label: &str) -> (MlsGroup, Prov) {
    let (_, provider, _) = client.mls_parts_mut();
    let copy = provider.storage_copy(ScriptedRand::new(label.as_bytes()));
    let group = MlsGroup::load(copy.storage(), &GroupId::from_slice(GROUP.as_bytes()))
        .expect("load from the copied storage")
        .expect("the copied storage holds the group");
    (group, copy)
}

// ---------------------------------------------------------------------------
// Identities, providers and the test world (pattern of `tests/adapter_release.rs`)
// ---------------------------------------------------------------------------

/// Deterministic client identity: the same name always yields the same key.
fn identity(name: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(
        format!("repair-identity/{name}").as_bytes(),
    ))
    .expect("client identity")
}

fn client_provider(label: &str) -> Prov {
    TestProvider::new(ScriptedRand::new(
        format!("repair-provider/{label}").as_bytes(),
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
    policy_revision: u64,
    parent: Frontier,
}

/// A canonical repair: its plan, exact commit bytes and the acked successor.
#[derive(Clone, Debug)]
struct Repaired {
    plan: Plan,
    commit: Vec<u8>,
    frontier: Frontier,
    ack: Vec<u8>,
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
    providers: u64,
}

/// Genesis with the root; bob, carol and dave delegated `read`, `write` and `admit` and
/// admitted by the root; erin delegated `read` only and never admitted.
struct Setup {
    w: World,
    root: Client,
    bob: Client,
    carol: Client,
    dave: Client,
}

/// Full genesis (§5.1).
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(format!("repair-apf/{tag}").as_bytes());
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
    w.delegate("erin", &["read"]);
    let mut bob = admit(&mut w, &mut root, "bob", &mut []);
    let mut carol = admit(&mut w, &mut root, "carol", &mut [&mut bob]);
    let dave = admit(&mut w, &mut root, "dave", &mut [&mut bob, &mut carol]);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["roster"], json!([ROOT, "bob", "carol", "dave"]));
    assert_eq!(checkpoint["epoch"], json!(3));
    assert_eq!(checkpoint["read_fenced"], json!(false));
    Setup {
        w,
        root,
        bob,
        carol,
        dave,
    }
}

fn repair_plan_body() -> Value {
    json!({"command":"repair_plan"})
}

fn repair_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"repair", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn admit_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"admit", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn confirm_body(confirmation: &[u8]) -> Value {
    json!({"command":"confirm_repair", "confirmation":lower_hex(confirmation)})
}

fn consume_body(op: &str) -> Value {
    json!({"command":"consume", "op":op})
}

fn grant_body(subject: &str, right: &str, generation: u64, fresh_keys: bool) -> Value {
    json!({"command":"grant", "subject":subject, "right":right,
           "generation":generation, "fresh_keys":fresh_keys})
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
        let response = self.ok(actor, &repair_plan_body());
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
            policy_revision: response["policy_revision"]
                .as_u64()
                .expect("plan policy_revision"),
            parent: Frontier {
                epoch: response["parent_epoch"].as_u64().expect("parent_epoch"),
                branch: response["parent_branch"]
                    .as_str()
                    .expect("parent_branch")
                    .to_owned(),
            },
        }
    }

    fn submit_repair(
        &mut self,
        actor: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<Accepted, String> {
        let response = self.send(actor, &repair_body(parent, commit))?;
        Ok(accepted_from(&response))
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
        self.ok(&actor, &confirm_body(&confirmation))
    }

    fn verify_ack(&self, ack: &[u8]) -> CanonicalAck {
        CanonicalAck::verify(ack, &self.apf_public, &RustCrypto::default())
            .expect("ack verifies under the APF key")
    }

    fn apf_key_id(&self) -> Vec<u8> {
        sha256(&self.apf_public)
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
        let response = self.ok(actor, &consume_body(op));
        assert_eq!(response["recipient"], json!(actor));
        hex::decode(
            response["receipt"]
                .as_str()
                .expect("consume response carries the receipt in hex"),
        )
        .expect("receipt is hex")
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

/// Submits a staged repair commit as `actor`, expects `expected`, then clears the
/// committer's pending commit and checks that it stayed at its parent frontier.
fn refused_repair(
    w: &mut World,
    actor: &str,
    committer: &mut Client,
    commit: &[u8],
    expected: &str,
) -> String {
    let parent = committer.frontier().expect("committer frontier");
    assert_eq!(w.frontier(), parent, "staged on the canonical frontier");
    let err = rejected(w, actor, &repair_body(&parent, commit), expected);
    committer.discard_pending().expect("discard pending commit");
    assert_eq!(committer.frontier().expect("frontier"), parent);
    assert_eq!(w.frontier(), parent);
    err
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

/// Full honest admission of `subject` from `candidate`, committed by `committer`.
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

/// Repairs with a plan the committer requests: `stage_repair`, `submit_commit {kind:
/// "repair"}`, then `apply_ack` at the committer and at `others`. The fence stays closed.
fn commit_repair(w: &mut World, committer: &mut Client, others: &mut [&mut Client]) -> Repaired {
    let actor = committer.subject().to_owned();
    let plan = w.plan(&actor);
    commit_repair_with(w, committer, plan, others)
}

fn commit_repair_with(
    w: &mut World,
    committer: &mut Client,
    plan: Plan,
    others: &mut [&mut Client],
) -> Repaired {
    let actor = committer.subject().to_owned();
    let staged = committer
        .stage_repair(&plan.removed, &plan.acc_context)
        .unwrap_or_else(|err| panic!("{actor} stages the planned repair, got {err}"));
    assert_eq!(staged.parent, plan.parent, "staged on the planned parent");
    let accepted = w
        .submit_repair(&actor, &staged.parent, &staged.commit)
        .unwrap_or_else(|err| panic!("{actor} repair should be canonical, got {err}"));
    assert_eq!(accepted.frontier.epoch, plan.parent.epoch + 1);
    assert_eq!(w.frontier(), accepted.frontier);
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
    Repaired {
        plan,
        commit: staged.commit,
        frontier: accepted.frontier,
        ack: accepted.ack,
    }
}

/// The committer confirms (not yet open), then another continuing member confirms and
/// the fence opens with `evidence: "pair"`.
fn open_fence(w: &mut World, committer: &mut Client, other: &mut Client) {
    let first = w.confirm(committer);
    assert_eq!(first["opened"], json!(false), "committer alone: {first}");
    assert_eq!(w.checkpoint()["read_fenced"], json!(true));
    let second = w.confirm(other);
    assert_eq!(second["opened"], json!(true), "{second}");
    assert_eq!(second["evidence"], json!("pair"), "{second}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
    assert_eq!(checkpoint["fence_revision"], Value::Null);
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

/// The readers of a release certificate.
fn certificate_readers(w: &World, certificate: &[u8]) -> Vec<(String, u64)> {
    ReleaseCertificate::verify(certificate, &w.apf_public, &RustCrypto::default())
        .expect("certificate verifies")
        .readers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// BROKEN CONTROL. A kernel revocation alone changes no MLS key: the revoked endpoint
/// still holds the epoch secrets and decrypts new traffic. This is why §5.4 requires a
/// cryptographic removal before the fence may open. The unsafe decryption is asserted
/// to succeed.
#[test]
fn api_only_revocation_lets_a_retained_endpoint_decrypt_new_traffic() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        ..
    } = setup("broken-control");

    // Positive: an honest release before the revocation reaches bob.
    let before = publish(&mut w, &mut root, "op-before");
    deliver_to(&mut w, &mut bob, &before);

    // The kernel revocation closes the fence but removes nobody from the MLS group.
    let response = w.revoke("bob", "read");
    assert_eq!(response["read_fenced"], json!(true));
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "dave"]);
    assert_eq!(tree_members(&mut root), vec!["bob", "carol", "dave", ROOT]);

    // The adapter refuses a fresh release.
    w.allocate(ROOT, "op-fenced");
    let body = w.release_body(ROOT, "op-fenced", &payload_for("op-fenced"));
    rejected(&mut w, ROOT, &body, "read_fenced");

    // Unsafe: a raw application message created after the revocation decrypts at bob.
    let secret = b"new traffic after an API-only revocation";
    let raw = raw_application(&mut root, secret);
    let (sender, plaintext) =
        raw_decrypt(&mut bob, &raw).expect("BROKEN CONTROL: the revoked endpoint decrypts");
    assert_eq!(sender, ROOT.as_bytes());
    assert_eq!(plaintext, secret);
}

#[test]
fn read_revocation_fences_release_until_confirmed_repair() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
    } = setup("fence");

    // Positive: release and delivery before the revocation.
    let before = publish(&mut w, &mut root, "op-before");
    deliver_to(&mut w, &mut carol, &before);

    // Read revocation closes the fence at the revoke's policy revision (§5.4 step 1).
    let response = w.revoke("bob", "read");
    assert_eq!(response["read_fenced"], json!(true));
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["fence_revision"], checkpoint["policy_revision"]);
    assert_eq!(checkpoint["repair_pending"], Value::Null);
    let parent = w.kernel_frontier();

    w.allocate(ROOT, "op-fenced");
    let body = w.release_body(ROOT, "op-fenced", &payload_for("op-fenced"));
    rejected(&mut w, ROOT, &body, "read_fenced");

    // C-20 plan, checked independently.
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["bob"]);
    assert_eq!(plan.parent, parent);
    let policy_revision = w.policy_revision();
    assert_eq!(plan.policy_revision, policy_revision);
    let policy_digest = hex::decode(
        w.checkpoint()["policy_digest"]
            .as_str()
            .expect("policy_digest"),
    )
    .expect("policy_digest is hex");
    assert_eq!(
        decode_acc(&plan.acc_context),
        TestAcc {
            version: 1,
            apf_key_id: w.apf_key_id(),
            group: GROUP.as_bytes().to_vec(),
            policy_revision,
            policy_digest,
        }
    );
    assert_eq!(
        w.plan("carol"),
        plan,
        "any roster member gets the same plan"
    );

    // The canonical repair commit.
    let staged = root
        .stage_repair(&plan.removed, &plan.acc_context)
        .expect("stage repair");
    assert_eq!(staged.parent, parent);
    let accepted = w
        .submit_repair(ROOT, &staged.parent, &staged.commit)
        .expect("canonical repair");
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
    let ack = w.verify_ack(&accepted.ack);
    assert_eq!(
        ack,
        CanonicalAck {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            parent: parent.clone(),
            successor: accepted.frontier.clone(),
            commit_hash: sha256(&staged.commit),
            kind: AckKind::Repair,
        }
    );
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["epoch"], json!(accepted.frontier.epoch));
    assert_eq!(checkpoint["branch"], json!(accepted.frontier.branch));
    assert_eq!(checkpoint["roster"], json!([ROOT, "carol", "dave"]));
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(
        checkpoint["repair_pending"],
        json!(accepted.frontier.branch)
    );
    assert_eq!(checkpoint["policy_revision"], json!(policy_revision));
    assert_eq!(w.frontier(), accepted.frontier);

    for member in [&mut root, &mut carol, &mut dave] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("apply repair ack"),
            accepted.frontier
        );
        assert_eq!(tree_members(member), vec!["carol", "dave", ROOT]);
        assert_eq!(current_acc_bytes(member), plan.acc_context);
    }

    // Canonical but unconfirmed: still fenced.
    w.allocate(ROOT, "op-after");
    let body = w.release_body(ROOT, "op-after", &payload_for("op-after"));
    rejected(&mut w, ROOT, &body, "read_fenced");

    // Confirmation by the committer and another continuing member opens the fence.
    open_fence(&mut w, &mut root, &mut carol);
    let released = w.release(ROOT, "op-after", &payload_for("op-after"));
    assert_eq!(
        certificate_readers(&w, &released.certificate),
        vec![
            ("carol".to_owned(), 0),
            ("dave".to_owned(), 0),
            (ROOT.to_owned(), 0)
        ]
    );
    let after = finish(&mut w, &mut root, released);
    deliver_to(&mut w, &mut carol, &after);
    deliver_to(&mut w, &mut dave, &after);
    code_in(
        "removed bob",
        bob.receive(&after.envelope),
        &["undecryptable", "binding_mismatch"],
    );
}

#[test]
fn repair_missing_one_revoked_reader_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut dave,
        ..
    } = setup("missing-one");
    w.revoke("bob", "read");
    w.revoke("carol", "read");
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["bob", "carol"]);

    // Only bob removed.
    let commit = raw_repair(&mut root, &["bob"], Some(&plan.acc_context), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["roster"], json!([ROOT, "bob", "carol", "dave"]));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
    assert_eq!(w.plan(ROOT), plan, "the plan is unchanged");

    // The exact repair is canonical.
    let repaired = commit_repair_with(&mut w, &mut root, plan, &mut [&mut dave]);
    assert_eq!(w.roster(), vec![ROOT, "dave"]);
    assert_eq!(tree_members(&mut dave), vec!["dave", ROOT]);
    open_fence(&mut w, &mut root, &mut dave);
    assert_eq!(w.kernel_frontier(), repaired.frontier);
}

#[test]
fn repair_removing_a_continuing_reader_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        ..
    } = setup("extra-removal");
    w.revoke("bob", "read");
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["bob"]);

    let commit = raw_repair(&mut root, &["bob", "dave"], Some(&plan.acc_context), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "dave"]);

    commit_repair_with(&mut w, &mut root, plan, &mut [&mut carol, &mut dave]);
    assert_eq!(w.roster(), vec![ROOT, "carol", "dave"]);
    open_fence(&mut w, &mut root, &mut dave);
}

#[test]
fn repair_without_acc_context_update_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        ..
    } = setup("no-acc");
    w.revoke("bob", "read");
    let plan = w.plan(ROOT);
    let parent_acc = current_acc_bytes(&mut root);
    assert_ne!(parent_acc, plan.acc_context, "the plan changes acc_context");

    // Remove-only commit: no GroupContextExtensions proposal.
    let commit = raw_repair(&mut root, &["bob"], None, true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");

    // A GroupContextExtensions proposal that keeps the parent acc_context.
    let commit = raw_repair(&mut root, &["bob"], Some(&parent_acc), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");

    // The planned revision with a stale policy digest (the parent group's).
    let mut stale = decode_acc(&plan.acc_context);
    stale.policy_digest = decode_acc(&parent_acc).policy_digest;
    let stale = encode_acc(&stale);
    assert_ne!(stale, plan.acc_context);
    let commit = raw_repair(&mut root, &["bob"], Some(&stale), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");

    // The planned bytes are canonical.
    commit_repair_with(
        &mut w,
        &mut root,
        plan.clone(),
        &mut [&mut carol, &mut dave],
    );
    assert_eq!(current_acc_bytes(&mut carol), plan.acc_context);
    open_fence(&mut w, &mut root, &mut dave);
}

#[test]
fn repair_with_policy_revision_older_than_fence_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        ..
    } = setup("old-revision");
    w.revoke("bob", "read");
    let fence_revision = w.checkpoint()["fence_revision"]
        .as_u64()
        .expect("fence_revision after a fencing revoke");
    let plan = w.plan(ROOT);
    assert_eq!(plan.policy_revision, fence_revision);

    // A forged plan below the fence revision.
    let mut forged = decode_acc(&plan.acc_context);
    forged.policy_revision = fence_revision - 1;
    let forged = encode_acc(&forged);
    let commit = raw_repair(&mut root, &["bob"], Some(&forged), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");

    // A further grant (to a subject that is not a roster member) changes the policy.
    let mut body = grant_body("frank", "read", 0, true);
    body["subject_key"] = json!(lower_hex(identity("frank").public_key()));
    w.ok(ROOT, &body);
    let checkpoint = w.checkpoint();
    assert_eq!(
        checkpoint["policy_revision"],
        json!(plan.policy_revision + 1)
    );
    assert_eq!(checkpoint["fence_revision"], json!(fence_revision));

    // The old plan's acc_context no longer matches.
    let commit = raw_repair(&mut root, &["bob"], Some(&plan.acc_context), true);
    refused_repair(&mut w, ROOT, &mut root, &commit, "noncanonical_commit");

    // A fresh plan succeeds.
    let fresh = w.plan(ROOT);
    assert_eq!(fresh.removed, plan.removed);
    assert_eq!(fresh.policy_revision, plan.policy_revision + 1);
    assert_ne!(fresh.acc_context, plan.acc_context);
    assert_eq!(
        decode_acc(&fresh.acc_context).policy_revision,
        fresh.policy_revision
    );
    commit_repair_with(
        &mut w,
        &mut root,
        fresh.clone(),
        &mut [&mut carol, &mut dave],
    );
    assert_eq!(current_acc_bytes(&mut dave), fresh.acc_context);
    open_fence(&mut w, &mut root, &mut dave);
}

/// RFC 9420 §12.4.2 requires a path for any commit that covers a Remove or a
/// GroupContextExtensions proposal, and the pinned OpenMLS adds one even when
/// `force_self_update` is false. An honest client therefore cannot build a pathless
/// repair, and the sequencer's UpdatePath check (C-22 step 4) is defense in depth.
#[test]
fn repair_without_update_path_is_noncanonical() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
    } = setup("path");
    w.revoke("bob", "read");
    let plan = w.plan(ROOT);

    // OpenMLS adds a path without `force_self_update`.
    raw_repair(&mut root, &["bob"], Some(&plan.acc_context), false);
    assert!(
        pending_has_path(&mut root),
        "Remove + GroupContextExtensions commit carries an UpdatePath"
    );
    root.discard_pending().expect("discard");
    raw_repair(&mut root, &["bob"], None, false);
    assert!(
        pending_has_path(&mut root),
        "Remove-only commit carries an UpdatePath"
    );
    root.discard_pending().expect("discard");

    // A repair from the removed member itself (it cannot remove its own leaf).
    let commit = raw_repair(&mut bob, &[], Some(&plan.acc_context), true);
    refused_repair(&mut w, "bob", &mut bob, &commit, "noncanonical_commit");

    // The honest commit bytes submitted by a non-member and by another member.
    let staged = root
        .stage_repair(&plan.removed, &plan.acc_context)
        .expect("stage repair");
    assert!(pending_has_path(&mut root));
    rejected(
        &mut w,
        "erin",
        &repair_body(&staged.parent, &staged.commit),
        "noncanonical_commit",
    );
    rejected(
        &mut w,
        "carol",
        &repair_body(&staged.parent, &staged.commit),
        "noncanonical_commit",
    );

    // The committer's own submission of the same bytes is canonical.
    let accepted = w
        .submit_repair(ROOT, &staged.parent, &staged.commit)
        .expect("canonical repair");
    for member in [&mut root, &mut carol, &mut dave] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("apply repair ack"),
            accepted.frontier
        );
    }
    open_fence(&mut w, &mut root, &mut dave);
}

#[test]
fn canonical_repair_stays_fenced_until_confirmation() {
    let Setup {
        mut w,
        mut root,
        bob,
        mut carol,
        mut dave,
    } = setup("pending");

    // Positive: a persisted operation, consumed once before the revocation.
    let old = publish(&mut w, &mut root, "op-old");
    deliver_to(&mut w, &mut dave, &old);

    w.revoke("bob", "read");
    // Carol applies the ack only later.
    let repaired = commit_repair(&mut w, &mut root, &mut [&mut dave]);

    // Repair pending: no new plan, no consumption.
    rejected(&mut w, ROOT, &repair_plan_body(), "invalid_repair");
    rejected(&mut w, "carol", &consume_body("op-old"), "read_fenced");

    // The committer alone does not open while another continuing member exists.
    let response = w.confirm(&mut root);
    assert_eq!(response["opened"], json!(false), "{response}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(
        checkpoint["repair_pending"],
        json!(repaired.frontier.branch)
    );

    // Carol's honest confirmation of her stale parent frontier.
    let stale = carol.confirmation().expect("carol confirmation");
    let (_, stale_frontier, _) = decode_confirmation(&stale, identity("carol").public_key());
    assert_eq!(stale_frontier, repaired.plan.parent);
    rejected(&mut w, "carol", &confirm_body(&stale), "invalid_repair");

    // The removed member: its own honest confirmation, and one for the current frontier.
    let bob_stale = bob.confirmation().expect("bob confirmation");
    rejected(&mut w, "bob", &confirm_body(&bob_stale), "invalid_repair");
    let bob_current = RepairConfirmation {
        group: GROUP.to_owned(),
        frontier: repaired.frontier.clone(),
        epoch_authenticator_hash: genuine_hash(&mut root),
    }
    .sign(identity("bob").signer())
    .expect("sign");
    rejected(&mut w, "bob", &confirm_body(&bob_current), "invalid_repair");

    // Dave's genuine fields, signed by another member's key.
    let dave_fields = RepairConfirmation {
        group: GROUP.to_owned(),
        frontier: dave.frontier().expect("dave frontier"),
        epoch_authenticator_hash: genuine_hash(&mut dave),
    };
    let wrong_key = dave_fields.sign(identity("carol").signer()).expect("sign");
    rejected(&mut w, "dave", &confirm_body(&wrong_key), "unauthenticated");

    // Dave's genuine confirmation opens the fence.
    let response = w.confirm(&mut dave);
    assert_eq!(response["opened"], json!(true), "{response}");
    assert_eq!(response["evidence"], json!("pair"), "{response}");
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));

    // Carol catches up and receives new traffic.
    carol
        .apply_ack(&repaired.commit, &repaired.ack)
        .expect("carol applies the repair ack");
    let next = publish(&mut w, &mut root, "op-next");
    deliver_to(&mut w, &mut carol, &next);
}

#[test]
fn inconsistent_confirmation_hash_keeps_fence_closed() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        ..
    } = setup("confirm-hash");
    w.revoke("bob", "read");
    let repaired = commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave]);

    // C-23 encoding, checked independently.
    let genuine = genuine_hash(&mut root);
    assert_eq!(genuine_hash(&mut carol), genuine);
    assert_eq!(genuine_hash(&mut dave), genuine);
    {
        let (group, _, _) = root.mls_parts_mut();
        assert_eq!(
            epoch_authenticator_hash(
                &repaired.frontier.branch,
                group.epoch_authenticator().as_slice()
            ),
            genuine
        );
    }
    assert_eq!(CONFIRM_LABEL, T_CONFIRM_LABEL);
    let confirmation = root.confirmation().expect("root confirmation");
    assert_eq!(
        decode_confirmation(&confirmation, identity(ROOT).public_key()),
        (GROUP.to_owned(), repaired.frontier.clone(), genuine.clone())
    );
    let fields = RepairConfirmation {
        group: GROUP.to_owned(),
        frontier: repaired.frontier.clone(),
        epoch_authenticator_hash: genuine.clone(),
    };
    assert_eq!(
        RepairConfirmation::verify(
            &confirmation,
            identity(ROOT).public_key(),
            &RustCrypto::default()
        )
        .expect("confirmation verifies under the root key"),
        fields
    );
    assert_eq!(
        fields.sign(identity(ROOT).signer()).expect("sign"),
        confirmation,
        "Ed25519 is deterministic"
    );
    assert_eq!(
        independent_confirmation(identity(ROOT).signer(), GROUP, &repaired.frontier, &genuine),
        confirmation
    );

    let response = w.ok(ROOT, &confirm_body(&confirmation));
    assert_eq!(response["opened"], json!(false), "{response}");

    // Validly signed by a continuing member over a wrong hash.
    let forged = RepairConfirmation {
        group: GROUP.to_owned(),
        frontier: repaired.frontier.clone(),
        epoch_authenticator_hash: sha256(b"not the epoch authenticator"),
    }
    .sign(identity("dave").signer())
    .expect("sign");
    rejected(&mut w, "dave", &confirm_body(&forged), "binding_mismatch");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(
        checkpoint["repair_pending"],
        json!(repaired.frontier.branch)
    );

    // The genuine confirmation opens the fence.
    let response = w.confirm(&mut dave);
    assert_eq!(response["opened"], json!(true), "{response}");
    assert_eq!(response["evidence"], json!("pair"), "{response}");
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));

    // Single continuing member: the committer's own confirmation suffices.
    let (mut w, mut root) = genesis("confirm-single");
    w.delegate("bob", &["read", "write", "admit"]);
    let _bob = admit(&mut w, &mut root, "bob", &mut []);
    w.revoke("bob", "read");
    let repaired = commit_repair(&mut w, &mut root, &mut []);
    assert_eq!(w.roster(), vec![ROOT]);
    let response = w.confirm(&mut root);
    assert_eq!(response["opened"], json!(true), "{response}");
    assert_eq!(response["evidence"], json!("single"), "{response}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["branch"], json!(repaired.frontier.branch));
    w.allocate(ROOT, "op-single");
    w.release(ROOT, "op-single", &payload_for("op-single"));
}

#[test]
fn removed_endpoint_storage_copy_cannot_decrypt_successor_traffic() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
    } = setup("retained");
    let before = publish(&mut w, &mut root, "op-before");
    deliver_to(&mut w, &mut bob, &before);

    w.revoke("bob", "read");
    // Complete copies of bob's storage, taken before the repair.
    let (mut retained, retained_provider) = retained_copy(&mut bob, "retained/a");
    let (mut processed, processed_provider) = retained_copy(&mut bob, "retained/b");
    let bob_frontier = bob.frontier().expect("bob frontier");
    for group in [&retained, &processed] {
        assert_eq!(group.epoch().as_u64(), bob_frontier.epoch);
    }

    // Positive control: the copy decrypts pre-removal traffic.
    let pre = raw_application(&mut root, b"pre-removal traffic");
    let (sender, plaintext) = group_decrypt(&mut retained, &retained_provider, &pre)
        .expect("the retained copy decrypts pre-removal traffic");
    assert_eq!(sender, ROOT.as_bytes());
    assert_eq!(plaintext, b"pre-removal traffic");

    // Repair and confirmation.
    let repaired = commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave]);
    open_fence(&mut w, &mut root, &mut dave);

    // A real release, protected by the root and delivered to carol.
    let after = publish(&mut w, &mut root, "op-after");
    deliver_to(&mut w, &mut carol, &after);
    let (_, successor) = decode_envelope(&after.envelope);

    // The retained copy, still at the parent epoch.
    assert!(
        group_decrypt(&mut retained, &retained_provider, &successor).is_err(),
        "the retained copy must not decrypt successor traffic"
    );
    // The retained copy that first processes the repair commit learns only its removal.
    let message = processed
        .process_message(&processed_provider, protocol_message(&repaired.commit))
        .expect("the public repair commit processes at the retained copy");
    let ProcessedMessageContent::StagedCommitMessage(staged) = message.into_content() else {
        panic!("the repair is a commit");
    };
    assert!(staged.self_removed(), "the copy sees its own removal");
    processed
        .merge_staged_commit(&processed_provider, *staged)
        .expect("merge");
    assert!(!processed.is_active(), "the copy is evicted");
    assert!(
        group_decrypt(&mut processed, &processed_provider, &successor).is_err(),
        "the retained copy must not decrypt successor traffic after the repair commit"
    );

    // Bob's live endpoint, before and after applying the repair ack (C-24).
    code_in(
        "bob before the ack",
        bob.receive(&after.envelope),
        &["undecryptable", "binding_mismatch"],
    );
    bob.apply_ack(&repaired.commit, &repaired.ack)
        .expect("a removed member may apply the repair ack");
    {
        let (group, _, _) = bob.mls_parts_mut();
        assert!(!group.is_active(), "the removed member becomes inactive");
    }
    let later = publish(&mut w, &mut root, "op-later");
    deliver_to(&mut w, &mut dave, &later);
    code_in(
        "bob after the ack",
        bob.receive(&later.envelope),
        &["undecryptable", "binding_mismatch"],
    );
}

#[test]
fn continuing_members_send_and_deliver_after_repair() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
    } = setup("continuing");
    w.revoke("bob", "read");
    // C-21: any continuing member may commit; dave holds no admin right.
    assert!(!w.active("dave", "admin") && w.grant_record("dave", "admin").is_none());
    commit_repair(&mut w, &mut dave, &mut [&mut root, &mut carol]);
    open_fence(&mut w, &mut dave, &mut root);
    assert_eq!(w.roster(), vec![ROOT, "carol", "dave"]);

    let expected_readers = vec![
        ("carol".to_owned(), 0),
        ("dave".to_owned(), 0),
        (ROOT.to_owned(), 0),
    ];
    let mut members = [root, carol, dave];
    for sender in 0..members.len() {
        let name = members[sender].subject().to_owned();
        let op = format!("op-from-{name}");
        let published = publish(&mut w, &mut members[sender], &op);
        assert_eq!(
            certificate_readers(&w, &published.released.certificate),
            expected_readers,
            "the cover omits bob"
        );
        for (receiver, member) in members.iter_mut().enumerate() {
            if receiver != sender {
                deliver_to(&mut w, member, &published);
            }
        }
        code_in(
            "removed bob",
            bob.receive(&published.envelope),
            &["undecryptable", "binding_mismatch"],
        );
    }

    // A cover that still names bob is unsound.
    w.allocate(ROOT, "op-with-bob");
    let mut body = w.release_body(ROOT, "op-with-bob", &payload_for("op-with-bob"));
    body["cover"]
        .as_array_mut()
        .expect("cover")
        .push(json!([{"subject":"bob", "right":"read", "generation":0}]));
    rejected(&mut w, ROOT, &body, "unsound_cover");
    w.release(ROOT, "op-with-bob", &payload_for("op-with-bob"));
}

#[test]
fn offline_client_stays_locally_fenced_without_blocking_others() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        ..
    } = setup("offline");
    w.revoke("bob", "read");
    // Carol is offline: she does not apply the repair ack.
    let repaired = commit_repair(&mut w, &mut root, &mut [&mut dave]);
    assert_eq!(carol.frontier().expect("carol"), repaired.plan.parent);
    open_fence(&mut w, &mut root, &mut dave);

    // Traffic at the new frontier reaches dave.
    let first = publish(&mut w, &mut root, "op-new-1");
    deliver_to(&mut w, &mut dave, &first);

    // Carol stays locally fenced.
    code_in(
        "offline carol receives",
        carol.receive(&first.envelope),
        &["binding_mismatch", "undecryptable"],
    );
    w.allocate("carol", "op-carol");
    let released = w.release("carol", "op-carol", &payload_for("op-carol"));
    code(
        carol.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );

    // After applying the ack she receives and sends again.
    assert_eq!(
        carol
            .apply_ack(&repaired.commit, &repaired.ack)
            .expect("carol applies the repair ack"),
        repaired.frontier
    );
    let second = publish(&mut w, &mut root, "op-new-2");
    deliver_to(&mut w, &mut carol, &second);
    let from_carol = finish(&mut w, &mut carol, released);
    deliver_to(&mut w, &mut dave, &from_carol);
}

#[test]
fn write_revocation_does_not_remove_an_authorized_reader() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        ..
    } = setup("write-revoke");

    // Positive: bob sends and receives.
    let from_bob = publish(&mut w, &mut bob, "op-bob-before");
    deliver_to(&mut w, &mut root, &from_bob);

    let frontier = w.kernel_frontier();
    let response = w.revoke("bob", "write");
    assert_eq!(response["read_fenced"], json!(false));
    assert_eq!(w.kernel_frontier(), frontier);
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "dave"]);
    rejected(&mut w, "bob", &repair_plan_body(), "invalid_repair");
    rejected(&mut w, ROOT, &repair_plan_body(), "invalid_repair");

    // Bob still receives.
    let to_bob = publish(&mut w, &mut root, "op-to-bob");
    deliver_to(&mut w, &mut bob, &to_bob);

    // Bob can no longer release.
    w.allocate("bob", "op-bob-after");
    let body = w.release_body("bob", "op-bob-after", &payload_for("op-bob-after"));
    rejected(&mut w, "bob", &body, "unauthorized");

    // A later read revocation plans to remove only the read-revoked member.
    w.revoke("carol", "read");
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["carol"]);
}

#[test]
fn reallowed_reader_rejoins_only_with_new_generation_key_package() {
    let Setup {
        mut w,
        mut root,
        bob,
        mut carol,
        mut dave,
    } = setup("rejoin");
    // A generation-0 KeyPackage, certified while bob still held read.
    let old_candidate = w.candidate("bob");
    drop(bob);

    w.revoke("bob", "read");
    commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave]);
    open_fence(&mut w, &mut root, &mut dave);
    assert!(!w.roster().contains(&"bob".to_owned()));

    // C-25: the adapter sets fresh_keys itself, so a worker's false still re-grants.
    let policy_revision = w.policy_revision();
    w.ok(ROOT, &grant_body("bob", "read", 1, false));
    assert!(w.active("bob", "read"));
    assert_eq!(w.generation("bob", "read"), 1);
    assert_eq!(w.policy_revision(), policy_revision + 1);
    assert_eq!(w.checkpoint()["read_fenced"], json!(false));

    // The old generation-0 KeyPackage is not canonical.
    let staged = root
        .stage_add(old_candidate.key_package())
        .expect("stage add");
    rejected(
        &mut w,
        ROOT,
        &admit_body(&staged.parent, &staged.commit),
        "noncanonical_commit",
    );
    root.discard_pending().expect("discard");

    // A fresh certificate over a KeyPackage whose incarnation still says read 0.
    let relabelled = w.prepare_with(
        "bob",
        &[(Right::Read, 0), (Right::Write, 0), (Right::Admit, 0)],
    );
    let relabelled = w.certify("bob", relabelled);
    let staged = root.stage_add(relabelled.key_package()).expect("stage add");
    rejected(
        &mut w,
        ROOT,
        &admit_body(&staged.parent, &staged.commit),
        "noncanonical_commit",
    );
    root.discard_pending().expect("discard");

    // A new KeyPackage at read generation 1 with a fresh certificate admits bob.
    assert_eq!(
        w.rights_of("bob"),
        vec![(Right::Read, 1), (Right::Write, 0), (Right::Admit, 0)]
    );
    let candidate = w.candidate("bob");
    let mut bob = admit_candidate(&mut w, &mut root, candidate, &mut [&mut carol, &mut dave]);
    assert_eq!(w.roster(), vec![ROOT, "carol", "dave", "bob"]);
    let bob_index = leaf_index(&mut root, "bob");
    let leaf = {
        let (group, _, _) = root.mls_parts_mut();
        group
            .public_group()
            .leaf(bob_index)
            .expect("bob leaf")
            .clone()
    };
    let incarnations = unknown_payloads(leaf.extensions().iter(), INC_EXT);
    assert_eq!(incarnations.len(), 1);
    let (subject, rights) = incarnation_rights(&incarnations[0]);
    assert_eq!(subject, "bob");
    assert!(rights.contains(&(READ_CODE, 1)), "{rights:?}");

    // Bob receives a new release at his new generation.
    let published = publish(&mut w, &mut root, "op-rejoined");
    assert!(
        certificate_readers(&w, &published.released.certificate).contains(&("bob".to_owned(), 1))
    );
    deliver_to(&mut w, &mut bob, &published);
    deliver_to(&mut w, &mut carol, &published);
}

#[test]
fn grant_to_a_current_member_requires_rekey() {
    let Setup { mut w, .. } = setup("rekey-guard");

    // Positive: a grant to a subject that is not a roster member.
    let mut body = grant_body("frank", "read", 0, true);
    body["subject_key"] = json!(lower_hex(identity("frank").public_key()));
    w.ok(ROOT, &body);
    assert!(w.active("frank", "read"));

    // A new right for a current member. Amendment A-3 (C-28): the grant is a pending
    // offer, `{pending: true}`, and the kernel is unchanged.
    assert!(w.grant_record("bob", "admin").is_none());
    let before = w.checkpoint();
    let response = w.ok(ROOT, &grant_body("bob", "admin", 0, true));
    assert_eq!(response, json!({"pending": true}));
    assert_eq!(
        w.checkpoint(),
        before,
        "an offer leaves the kernel unchanged"
    );
    assert!(w.grant_record("bob", "admin").is_none());

    // A revoked non-read right re-granted to a current member.
    let response = w.revoke("bob", "write");
    assert_eq!(response["read_fenced"], json!(false));
    // Amendment A-3 (C-28): a pending offer; the kernel is unchanged.
    let before = w.checkpoint();
    let response = w.ok(ROOT, &grant_body("bob", "write", 1, true));
    assert_eq!(response, json!({"pending": true}));
    assert_eq!(
        w.checkpoint(),
        before,
        "an offer leaves the kernel unchanged"
    );
    assert!(!w.active("bob", "write"));
    // Amendment A-3 (C-28): read is never offered to a current member.
    rejected(
        &mut w,
        ROOT,
        &grant_body("bob", "read", 1, true),
        "malformed",
    );

    // Non-members keep the grant path, and the adapter sets fresh_keys itself.
    w.ok(ROOT, &grant_body("erin", "write", 0, false));
    assert!(w.active("erin", "write"));
    w.revoke("erin", "read");
    w.ok(ROOT, &grant_body("erin", "read", 1, false));
    assert_eq!(w.generation("erin", "read"), 1);
    assert!(w.active("erin", "read"));
}
