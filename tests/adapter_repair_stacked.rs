//! D-10 contract tests: stacked repair (`docs/adapter-contract.md` §4.12 C-27, which
//! amends C-20, C-22 and C-23; §5.4; §13 D-10; `docs/authority-contract.md` D-3).
//!
//! A read revocation of a continuing member while a repair is pending must not leave the
//! fence unable to reopen. A new plan and a new repair commit stack on the pending repair,
//! and only the latest pending repair can be confirmed.
//!
//! The confirmation TBS is decoded here with `tls_codec`
//! and `sha2`, independently of `src/wire.rs`. Raw OpenMLS state is used through
//! `ClientEndpoint::mls_parts_mut`, which honest code never uses, to model removed
//! endpoints that keep their group secrets.
//!
//! A repair changes the group irreversibly, so where the order is forced the rejected
//! requests are checked to leave the kernel checkpoint and the adapter frontier unchanged
//! and to add one trace event with the error code, and the honest path then runs on the
//! same state in the same test.

mod common;

use std::collections::HashMap;

use agent_trust::adapter::{Adapter, ClientIdentity};
use agent_trust::client::{ClientEndpoint, JoinCandidate};
use agent_trust::wire::{
    AckKind, CanonicalAck, Frontier, ReleaseCertificate, Right, SignedStructure,
};
use common::{
    adapter_dir, code, lower_hex, scripted_provider, sign, FixedClock, ScriptedRand, TestProvider,
};
use openmls::prelude::*;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
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

/// Decodes a signed C-23 confirmation, checks its signature under `public_key`, and
/// returns `(group, frontier, epoch_authenticator_hash)`, without `src/wire.rs`.
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
// Identities, providers and the test world (pattern of `tests/adapter_repair.rs`)
// ---------------------------------------------------------------------------

/// Deterministic client identity: the same name always yields the same key.
fn identity(name: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(
        format!("stacked-identity/{name}").as_bytes(),
    ))
    .expect("client identity")
}

fn client_provider(label: &str) -> Prov {
    TestProvider::new(ScriptedRand::new(
        format!("stacked-provider/{label}").as_bytes(),
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

/// Genesis with the root; bob, carol, dave and erin delegated `read`, `write` and
/// `admit` and admitted by the root.
struct Setup {
    w: World,
    root: Client,
    bob: Client,
    carol: Client,
    dave: Client,
    erin: Client,
}

/// Full genesis (§5.1).
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(format!("stacked-apf/{tag}").as_bytes());
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
    for subject in ["bob", "carol", "dave", "erin"] {
        w.delegate(subject, &["read", "write", "admit"]);
    }
    let mut bob = admit(&mut w, &mut root, "bob", &mut []);
    let mut carol = admit(&mut w, &mut root, "carol", &mut [&mut bob]);
    let mut dave = admit(&mut w, &mut root, "dave", &mut [&mut bob, &mut carol]);
    let erin = admit(
        &mut w,
        &mut root,
        "erin",
        &mut [&mut bob, &mut carol, &mut dave],
    );
    let checkpoint = w.checkpoint();
    assert_eq!(
        checkpoint["roster"],
        json!([ROOT, "bob", "carol", "dave", "erin"])
    );
    assert_eq!(checkpoint["epoch"], json!(4));
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
    Setup {
        w,
        root,
        bob,
        carol,
        dave,
        erin,
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

    fn fence_revision(&mut self) -> u64 {
        self.checkpoint()["fence_revision"]
            .as_u64()
            .expect("fence_revision while fenced")
    }

    fn policy_digest(&mut self) -> Vec<u8> {
        hex::decode(
            self.checkpoint()["policy_digest"]
                .as_str()
                .expect("policy_digest"),
        )
        .expect("policy_digest is hex")
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

    /// Honest candidate: prepare at the current generations, certify, finalize.
    fn candidate(&mut self, subject: &str) -> JoinCandidate<Prov> {
        let rights = self.rights_of(subject);
        let provider = self.provider(subject);
        let prepared = agent_trust::client::PreparedJoin::prepare(
            GROUP,
            subject,
            &rights,
            identity(subject),
            provider,
            &self.apf_public,
        )
        .expect("prepare KeyPackage");
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
    /// each at its latest generation.
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

/// Full honest admission of `subject`, committed by `committer` and merged at `others`.
fn admit(
    w: &mut World,
    committer: &mut Client,
    subject: &str,
    others: &mut [&mut Client],
) -> Client {
    let candidate = w.candidate(subject);
    let actor = committer.subject().to_owned();
    let staged = committer
        .stage_add(candidate.key_package())
        .expect("stage add");
    let parent = w.frontier();
    assert_eq!(staged.parent, parent, "staged on the canonical frontier");
    let accepted = w.submit_admit(&actor, &staged.parent, &staged.commit);
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
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
    let joined = candidate
        .join(&staged.welcome, &accepted.ack)
        .unwrap_or_else(|err| panic!("candidate joins, got {err}"));
    assert_eq!(
        joined.frontier().expect("joined frontier"),
        accepted.frontier
    );
    joined
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
        .stage_repair(&plan.removed)
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
    assert_eq!(first["evidence"], Value::Null, "{first}");
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

/// The readers `[(dave, 0), (erin, 0), (root, 0)]` left after both repairs.
fn survivors() -> Vec<(String, u64)> {
    vec![
        ("dave".to_owned(), 0),
        ("erin".to_owned(), 0),
        (ROOT.to_owned(), 0),
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn stacked_repair_after_revocation_during_pending_repair_reopens_after_latest_confirmation() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
        mut erin,
    } = setup("stacked");

    // First repair: remove bob. It becomes canonical and pending.
    w.revoke("bob", "read");
    let first_fence = w.fence_revision();
    let first = commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave, &mut erin]);
    assert_eq!(first.plan.removed, vec!["bob"]);
    assert_eq!(w.roster(), vec![ROOT, "carol", "dave", "erin"]);

    // Before the stacked repair, the committer alone does not open the first repair.
    let response = w.confirm(&mut root);
    assert_eq!(response["opened"], json!(false), "{response}");
    assert_eq!(response["evidence"], Value::Null, "{response}");
    assert_eq!(
        w.checkpoint()["repair_pending"],
        json!(first.frontier.branch)
    );

    // A read revocation of a continuing member while the repair is pending (C-27).
    let response = w.revoke("carol", "read");
    assert_eq!(response["read_fenced"], json!(true));
    let policy_revision = w.policy_revision();
    assert_eq!(
        w.fence_revision(),
        policy_revision,
        "a second fencing revoke moves fence_revision to the newer revision (D-3)"
    );
    assert!(policy_revision > first_fence);
    assert_eq!(w.kernel_frontier(), first.frontier);

    // C-27 amends C-20: a new plan at the pending repair's successor frontier.
    let plan = w.plan("dave");
    assert_eq!(plan.removed, vec!["carol"], "only the newly revoked reader");
    assert_eq!(
        plan.parent, first.frontier,
        "built on the pending successor"
    );
    assert_eq!(plan.policy_revision, policy_revision);
    let policy_digest = w.policy_digest();
    assert_eq!(w.plan(ROOT), plan, "any roster member gets the same plan");
    assert_eq!(w.plan("erin"), plan, "any roster member gets the same plan");

    // C-27 amends C-22 step 1: the stacked repair commit is canonical.
    let stacked = commit_repair_with(&mut w, &mut dave, plan, &mut [&mut root, &mut erin]);
    assert_eq!(stacked.frontier.epoch, first.frontier.epoch + 1);
    assert_eq!(
        w.verify_ack(&stacked.ack),
        CanonicalAck {
            apf_key_id: w.apf_key_id(),
            group: GROUP.to_owned(),
            parent: first.frontier.clone(),
            successor: stacked.frontier.clone(),
            commit_hash: sha256(&stacked.commit),
            kind: AckKind::Repair,
            // R-11 (c): the stacked ack carries the newer fence revision and its digest.
            policy_revision,
            policy_digest,
        }
    );
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["roster"], json!([ROOT, "dave", "erin"]));
    assert_eq!(checkpoint["repair_pending"], json!(stacked.frontier.branch));
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["policy_revision"], json!(policy_revision));
    for member in [&mut root, &mut dave, &mut erin] {
        assert_eq!(member.frontier().expect("frontier"), stacked.frontier);
        assert_eq!(tree_members(member), vec!["dave", "erin", ROOT]);
    }

    // Canonical but unconfirmed: still fenced.
    w.allocate(ROOT, "op-after");
    let body = w.release_body(ROOT, "op-after", &payload_for("op-after"));
    rejected(&mut w, ROOT, &body, "read_fenced");

    // The latest repair's committer and another continuing member open the fence.
    open_fence(&mut w, &mut dave, &mut root);
    assert_eq!(w.kernel_frontier(), stacked.frontier);

    // A release by the root reaches dave and erin, and neither removed member.
    let released = w.release(ROOT, "op-after", &payload_for("op-after"));
    assert_eq!(certificate_readers(&w, &released.certificate), survivors());
    let after = finish(&mut w, &mut root, released);
    deliver_to(&mut w, &mut dave, &after);
    deliver_to(&mut w, &mut erin, &after);
    for (name, removed) in [("bob", &mut bob), ("carol", &mut carol)] {
        code_in(
            name,
            removed.receive(&after.envelope),
            &["undecryptable", "binding_mismatch"],
        );
    }
}

#[test]
fn confirmation_of_superseded_repair_does_not_open_the_fence() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        mut erin,
        ..
    } = setup("superseded");

    // First repair by the root; every continuing member applies its ack.
    w.revoke("bob", "read");
    let first = commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave, &mut erin]);

    // The committer's confirmation of the first repair is stored but does not open.
    let root_first = root.confirmation().expect("root confirmation");
    let response = w.ok(ROOT, &confirm_body(&root_first));
    assert_eq!(response["opened"], json!(false), "{response}");
    assert_eq!(response["evidence"], Value::Null, "{response}");
    // Honest confirmations at the first repair's frontier, not yet sent.
    let dave_first = dave.confirmation().expect("dave confirmation");
    let (_, frontier, first_hash) = decode_confirmation(&dave_first, identity("dave").public_key());
    assert_eq!(frontier, first.frontier);

    // A stacked repair by the same committer supersedes the first.
    w.revoke("carol", "read");
    let stacked = commit_repair(&mut w, &mut root, &mut []);
    assert_eq!(stacked.plan.removed, vec!["carol"]);
    assert_eq!(stacked.plan.parent, first.frontier);
    assert_eq!(w.roster(), vec![ROOT, "dave", "erin"]);

    // Confirmations of the superseded frontier are invalid_repair (C-27 amends C-23).
    rejected(&mut w, ROOT, &confirm_body(&root_first), "invalid_repair");
    rejected(&mut w, "dave", &confirm_body(&dave_first), "invalid_repair");
    let erin_first = erin.confirmation().expect("erin confirmation");
    let (_, frontier, hash) = decode_confirmation(&erin_first, identity("erin").public_key());
    assert_eq!(frontier, first.frontier, "erin applied only the first ack");
    assert_eq!(hash, first_hash);
    rejected(&mut w, "erin", &confirm_body(&erin_first), "invalid_repair");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["repair_pending"], json!(stacked.frontier.branch));

    // The root's stored confirmation of the first repair does not count: one confirmation
    // of the latest from a member other than its committer does not open.
    assert_eq!(
        erin.apply_ack(&stacked.commit, &stacked.ack)
            .expect("erin applies the stacked ack"),
        stacked.frontier
    );
    let erin_latest = erin.confirmation().expect("erin confirmation");
    let (_, frontier, latest_hash) =
        decode_confirmation(&erin_latest, identity("erin").public_key());
    assert_eq!(frontier, stacked.frontier);
    assert_ne!(latest_hash, first_hash);
    let response = w.ok("erin", &confirm_body(&erin_latest));
    assert_eq!(response["opened"], json!(false), "{response}");
    assert_eq!(response["evidence"], Value::Null, "{response}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["repair_pending"], json!(stacked.frontier.branch));

    // Positive: the latest committer's confirmation pairs with erin's and opens.
    assert_eq!(
        dave.apply_ack(&stacked.commit, &stacked.ack)
            .expect("dave applies the stacked ack"),
        stacked.frontier
    );
    let response = w.confirm(&mut root);
    assert_eq!(response["opened"], json!(true), "{response}");
    assert_eq!(response["evidence"], json!("pair"), "{response}");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
    assert_eq!(checkpoint["fence_revision"], Value::Null);

    let published = publish(&mut w, &mut root, "op-open");
    assert_eq!(
        certificate_readers(&w, &published.released.certificate),
        survivors()
    );
    deliver_to(&mut w, &mut dave, &published);
    deliver_to(&mut w, &mut erin, &published);
}

#[test]
fn members_removed_by_both_repairs_cannot_decrypt_successor_traffic() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
        mut dave,
        mut erin,
    } = setup("retained");

    // Bob's complete storage, copied before the first repair.
    w.revoke("bob", "read");
    let (mut bob_copy, bob_provider) = retained_copy(&mut bob, "retained/bob");
    assert_eq!(
        bob_copy.epoch().as_u64(),
        bob.frontier().expect("bob").epoch
    );
    // Positive control: bob's copy decrypts traffic created before his removal.
    let pre_bob = raw_application(&mut root, b"before bob's removal");
    let (sender, plaintext) = group_decrypt(&mut bob_copy, &bob_provider, &pre_bob)
        .expect("bob's copy decrypts pre-removal traffic");
    assert_eq!(sender, ROOT.as_bytes());
    assert_eq!(plaintext, b"before bob's removal");

    let first = commit_repair(&mut w, &mut root, &mut [&mut carol, &mut dave, &mut erin]);

    // Carol's complete storage, copied after the first repair and before the stacked one.
    w.revoke("carol", "read");
    let (mut carol_copy, carol_provider) = retained_copy(&mut carol, "retained/carol");
    assert_eq!(carol_copy.epoch().as_u64(), first.frontier.epoch);
    // Positive control: carol's copy decrypts traffic created before her removal.
    let pre_carol = raw_application(&mut root, b"before carol's removal");
    let (sender, plaintext) = group_decrypt(&mut carol_copy, &carol_provider, &pre_carol)
        .expect("carol's copy decrypts pre-removal traffic");
    assert_eq!(sender, ROOT.as_bytes());
    assert_eq!(plaintext, b"before carol's removal");

    // The stacked repair, committed by dave, and the fence reopens.
    let stacked = commit_repair(&mut w, &mut dave, &mut [&mut root, &mut erin]);
    assert_eq!(stacked.plan.removed, vec!["carol"]);
    open_fence(&mut w, &mut dave, &mut erin);

    // A real release after the fence reopens, delivered to the continuing members.
    let after = publish(&mut w, &mut root, "op-after");
    deliver_to(&mut w, &mut dave, &after);
    deliver_to(&mut w, &mut erin, &after);
    let (_, successor) = decode_envelope(&after.envelope);

    // Neither retained copy decrypts it.
    assert!(
        group_decrypt(&mut bob_copy, &bob_provider, &successor).is_err(),
        "bob's retained copy must not decrypt successor traffic"
    );
    assert!(
        group_decrypt(&mut carol_copy, &carol_provider, &successor).is_err(),
        "carol's retained copy must not decrypt successor traffic"
    );
    // Nor do the live endpoints of the removed members.
    for (name, removed) in [("bob", &mut bob), ("carol", &mut carol)] {
        code_in(
            name,
            removed.receive(&after.envelope),
            &["undecryptable", "binding_mismatch"],
        );
    }
}

#[test]
fn revocation_is_never_refused_while_a_repair_is_pending() {
    let Setup {
        mut w,
        mut root,
        mut carol,
        mut dave,
        mut erin,
        ..
    } = setup("revoke-pending");

    // Positive: a plan exists while fenced with a reader to remove.
    w.revoke("bob", "read");
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["bob"]);
    let first = commit_repair_with(
        &mut w,
        &mut root,
        plan,
        &mut [&mut carol, &mut dave, &mut erin],
    );

    // C-26 guard: a pending repair with nothing more to remove has no plan.
    rejected(&mut w, ROOT, &repair_plan_body(), "invalid_repair");
    rejected(&mut w, "dave", &repair_plan_body(), "invalid_repair");

    // A non-read revoke of a continuing member succeeds and moves no fence.
    let before = w.checkpoint();
    let fence = w.fence_revision();
    let response = w.revoke("dave", "write");
    assert_eq!(response["read_fenced"], json!(true));
    assert!(!w.active("dave", "write"));
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["repair_pending"], json!(first.frontier.branch));
    assert_eq!(checkpoint["fence_revision"], json!(fence));
    assert_eq!(
        checkpoint["policy_revision"],
        json!(before["policy_revision"].as_u64().expect("revision") + 1)
    );
    assert_eq!(checkpoint["roster"], before["roster"]);
    assert_eq!(w.kernel_frontier(), first.frontier);
    assert_eq!(w.frontier(), first.frontier);
    // Still nothing more to remove.
    rejected(&mut w, ROOT, &repair_plan_body(), "invalid_repair");

    // A read revoke of a continuing member succeeds and advances fence_revision.
    let before = w.checkpoint();
    let response = w.revoke("erin", "read");
    assert_eq!(response["read_fenced"], json!(true));
    assert!(!w.active("erin", "read"));
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true));
    assert_eq!(checkpoint["repair_pending"], json!(first.frontier.branch));
    let policy_revision = checkpoint["policy_revision"].as_u64().expect("revision");
    assert_eq!(
        policy_revision,
        before["policy_revision"].as_u64().expect("revision") + 1
    );
    assert_eq!(checkpoint["fence_revision"], json!(policy_revision));
    assert!(policy_revision > fence);
    assert_eq!(checkpoint["roster"], before["roster"]);
    assert_eq!(w.kernel_frontier(), first.frontier);
    assert_eq!(w.frontier(), first.frontier);
}
