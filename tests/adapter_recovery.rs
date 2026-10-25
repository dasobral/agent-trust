//! Phase 4.5 contract tests: durability and crash recovery
//! (`docs/adapter-contract.md` §6 barriers B1 to B8, §6.1 C-31 to C-34).
//!
//! Every client stores its OpenMLS state in its own SQLite file (`common::FileProvider`),
//! so a client restart is a drop followed by `ClientEndpoint::load` over the same file. An
//! adapter crash is armed with `Adapter::crash_after`; the crashed adapter value is
//! dropped before `Adapter::open` reopens the directory.
//!
//! A request that crashes after the kernel call returns no certificate, receipt or ack.
//! Ed25519 is deterministic, so the tests rebuild the expected bytes independently of
//! `src/wire.rs` and sign them with the test-only APF seed from the temporary directory.
//! Every normal release and every normal ack is checked byte for byte against that
//! rebuild first, so the rebuild is validated on the positive path. A rebuilt release
//! certificate is accepted by `persist` only if it is byte-identical to the certificate
//! the adapter stored (C-16); a rebuilt ack is the ack the recovered adapter re-signs
//! (C-32).
//!
//! `Adapter::frontier` reads the kernel. `Adapter::open` refuses a sequencer that is not
//! at the kernel frontier (`binding_mismatch: sequencer frontier`), so a successful
//! `open` followed by a further canonical commit shows that the two agree.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use agent_trust::adapter::{
    Adapter, ClientIdentity, CrashPoint, SignedRequest, ADAPTER_FILE, APF_KEY_FILE,
};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use agent_trust::wire::{AckKind, CanonicalAck, Frontier, Right, SignedStructure};
use common::{
    adapter_dir, code, lower_hex, scripted_provider, sign, DalekSigner, FileProvider, FixedClock,
    ScriptedRand, TestProvider,
};
use openmls_rust_crypto::RustCrypto;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Serialize as TlsSerialize, VLBytes};

const GROUP: &str = "g";
const ROOT: &str = "root";
/// Trusted adapter time for every test.
const NOW: u64 = 1_000;
/// Default delegation expiry.
const EXPIRES: u64 = 1_000_000;
/// Content type used by every honest release.
const CONTENT_TYPE: &[u8] = b"text/plain";

/// C-33 error code of a request stopped at an armed crash point.
const CRASHED: &str = "crashed";
/// C-32 trace outcome of an intent that the kernel applied.
const RECOVERED: &str = "recovered";
/// C-34 interrupted-genesis marker.
const GENESIS_MARKER: &str = "genesis.incomplete";

// Spelled out here independently of `src/wire.rs`.
const T_OPERATION_LABEL: &[u8] = b"agent-trust/operation/v1";
const T_RELEASE_LABEL: &[u8] = b"agent-trust/release/v1";
const T_CANONICAL_LABEL: &[u8] = b"agent-trust/canonical/v1";
/// C-9 right code of `write`.
const WRITE_CODE: u8 = 2;
/// §4.6 ack kinds.
const KIND_ADMIT: u8 = 1;
const KIND_REPAIR: u8 = 2;
const KIND_UPDATE: u8 = 3;

type AdapterProv = TestProvider<ScriptedRand>;
type TestAdapter = Adapter<AdapterProv, FixedClock>;
type Prov = FileProvider<ScriptedRand>;
type Client = ClientEndpoint<Prov>;

const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];

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

/// C-14 operation digest, recomputed without `src/wire.rs`.
fn independent_digest(
    op: &str,
    payload: &[u8],
    frontier: &Frontier,
    policy_revision: u64,
) -> String {
    let mut input = Vec::new();
    input.extend(vl(T_OPERATION_LABEL));
    input.extend(vl(op.as_bytes()));
    input.extend(vl(GROUP.as_bytes()));
    input.extend(vl(CONTENT_TYPE));
    input.extend(vl(&sha256(payload)));
    input.extend(tls_u64(frontier.epoch));
    input.extend(vl(frontier.branch.as_bytes()));
    input.extend(tls_u64(policy_revision));
    lower_hex(&sha256(&input))
}

/// §4.5 `ReleaseCertificateTBS` with the C-14 encodings, for a `write` release on the
/// group resource without an invocation. `writer_generation` and `readers` come from the
/// release body's `cover`; `readers` is sorted by subject.
fn release_tbs(
    apf_key_id: &[u8],
    actor: &str,
    op: &str,
    body: &Value,
    event_hash: &str,
) -> Vec<u8> {
    let cover = body["cover"].as_array().expect("cover");
    let writer_generation = cover[0][0]["generation"]
        .as_u64()
        .expect("writer generation");
    let mut readers: Vec<(String, u64)> = cover[1..]
        .iter()
        .map(|support| {
            (
                support[0]["subject"]
                    .as_str()
                    .expect("reader subject")
                    .to_owned(),
                support[0]["generation"]
                    .as_u64()
                    .expect("reader generation"),
            )
        })
        .collect();
    readers.sort();
    let mut readers_bytes = Vec::new();
    for (subject, generation) in &readers {
        readers_bytes.extend(vl(subject.as_bytes()));
        readers_bytes.extend(tls_u64(*generation));
    }
    let mut out = Vec::new();
    out.extend(vl(T_RELEASE_LABEL));
    out.extend(vl(apf_key_id));
    out.extend(vl(GROUP.as_bytes()));
    out.extend(vl(op.as_bytes()));
    out.extend(vl(actor.as_bytes()));
    out.push(WRITE_CODE);
    out.extend(vl(GROUP.as_bytes()));
    out.extend(vl(b""));
    out.extend(tls_u64(body["epoch"].as_u64().expect("release epoch")));
    out.extend(vl(body["branch"]
        .as_str()
        .expect("release branch")
        .as_bytes()));
    out.extend(tls_u64(
        body["policy_revision"]
            .as_u64()
            .expect("release policy_revision"),
    ));
    out.extend(vl(body["digest"]
        .as_str()
        .expect("release digest")
        .as_bytes()));
    out.extend(tls_u64(writer_generation));
    out.extend(vl(&readers_bytes));
    out.extend(vl(event_hash.as_bytes()));
    out
}

/// §4.6 `CanonicalAckTBS` with the C-13 branch encoding and the R-11 policy fields.
#[allow(clippy::too_many_arguments)]
fn ack_tbs(
    apf_key_id: &[u8],
    parent: &Frontier,
    successor: &Frontier,
    commit: &[u8],
    kind: u8,
    policy_revision: u64,
    policy_digest: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(vl(T_CANONICAL_LABEL));
    out.extend(vl(apf_key_id));
    out.extend(vl(GROUP.as_bytes()));
    out.extend(tls_u64(parent.epoch));
    out.extend(vl(parent.branch.as_bytes()));
    out.extend(tls_u64(successor.epoch));
    out.extend(vl(successor.branch.as_bytes()));
    out.extend(vl(&sha256(commit)));
    out.push(kind);
    out.extend(tls_u64(policy_revision));
    out.extend(vl(policy_digest));
    out
}

/// `struct { TBS tbs; opaque signature<V>; }` signed by `signer` (C-9).
fn signed(signer: &DalekSigner, tbs: Vec<u8>) -> Vec<u8> {
    use openmls_traits::signatures::Signer;
    let signature = signer.sign(&tbs).expect("test signature");
    let mut out = tbs;
    out.extend(vl(&signature));
    out
}

// ---------------------------------------------------------------------------
// Kernel checkpoint and adapter store readers
// ---------------------------------------------------------------------------

fn revision(checkpoint: &Value) -> u64 {
    checkpoint["revision"].as_u64().expect("kernel revision")
}

fn last_event(checkpoint: &Value) -> &Value {
    checkpoint["history"]
        .as_array()
        .expect("kernel history")
        .last()
        .expect("non-empty kernel history")
}

/// The `kind` of the last kernel history event (C-32).
fn last_kind(checkpoint: &Value) -> String {
    last_event(checkpoint)["event"]["kind"]
        .as_str()
        .expect("event kind")
        .to_owned()
}

/// The hash of the last kernel history event.
fn last_hash(checkpoint: &Value) -> String {
    last_event(checkpoint)["hash"]
        .as_str()
        .expect("event hash")
        .to_owned()
}

/// The kernel operation record of `op` in the latest snapshot.
fn kernel_operation(checkpoint: &Value, op: &str) -> Option<Value> {
    last_event(checkpoint)["event"]["snapshot"]["operations"]
        .as_array()
        .expect("snapshot operations")
        .iter()
        .find(|operation| operation["op"] == json!(op))
        .cloned()
}

/// How often the kernel recorded `recipient` consuming `op`.
fn consumptions(checkpoint: &Value, op: &str, recipient: &str) -> usize {
    last_event(checkpoint)["event"]["snapshot"]["consumed"]
        .as_array()
        .expect("snapshot consumed")
        .iter()
        .filter(|entry| entry["op"] == json!(op) && entry["recipient"] == json!(recipient))
        .count()
}

/// Every row of every table in `adapter.sqlite`, rendered as text, read through a
/// separate connection. Used only to compare the store before and after a clean restart.
fn store_rows(dir: &Path) -> BTreeMap<String, Vec<String>> {
    let connection =
        rusqlite::Connection::open(dir.join(ADAPTER_FILE)).expect("open adapter store");
    let names: Vec<String> = connection
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .expect("list tables")
        .query_map([], |row| row.get(0))
        .expect("query tables")
        .collect::<Result<_, _>>()
        .expect("table names");
    let mut out = BTreeMap::new();
    for name in names {
        let mut statement = connection
            .prepare(&format!("SELECT * FROM \"{name}\" ORDER BY rowid"))
            .expect("select table");
        let columns = statement.column_count();
        let rows: Vec<String> = statement
            .query_map([], |row| {
                let mut cells = Vec::with_capacity(columns);
                for index in 0..columns {
                    cells.push(format!("{:?}", row.get_ref(index)?));
                }
                Ok(cells.join("|"))
            })
            .expect("query rows")
            .collect::<Result<_, _>>()
            .expect("rows");
        out.insert(name, rows);
    }
    out
}

/// The confirmation evidence the adapter store holds for the repair at `branch`
/// (`adapter_repairs.evidence`, C-23).
fn stored_evidence(dir: &Path, branch: &str) -> Option<String> {
    let connection =
        rusqlite::Connection::open(dir.join(ADAPTER_FILE)).expect("open adapter store");
    connection
        .query_row(
            "SELECT evidence FROM adapter_repairs WHERE branch = ?1",
            [branch],
            |row| row.get(0),
        )
        .expect("repair record present")
}

// ---------------------------------------------------------------------------
// Identities, bodies and the test world
// ---------------------------------------------------------------------------

/// The deterministic identity derived from `label`: one label, one key.
fn identity_from(label: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(label.as_bytes())).expect("client identity")
}

fn original_label(name: &str) -> String {
    format!("recovery-identity/{name}")
}

/// A subject's original identity.
fn identity(name: &str) -> ClientIdentity {
    identity_from(&original_label(name))
}

/// The label of a new identity for a rekey of `name`.
fn new_label(name: &str, tag: &str) -> String {
    format!("recovery-identity/{name}/new/{tag}")
}

fn payload_for(op: &str) -> Vec<u8> {
    format!("frozen payload of {op}").into_bytes()
}

fn allocate_body(op: &str) -> Value {
    json!({"command":"allocate", "op":op})
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

fn delegate_body(subject: &str, key: &ClientIdentity) -> Value {
    json!({
        "command":"delegate", "subject":subject, "rights":["read", "write", "admit"],
        "resources":[GROUP], "expires_at":EXPIRES, "not_before":0, "depth":4,
        "subject_key":lower_hex(key.public_key())
    })
}

fn submit_body(kind: &str, parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":kind, "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn grant_body(subject: &str, right: &str, generation: u64) -> Value {
    json!({"command":"grant", "subject":subject, "right":right,
           "generation":generation, "fresh_keys":true})
}

fn confirm_body(confirmation: &[u8]) -> Value {
    json!({"command":"confirm_repair", "confirmation":lower_hex(confirmation)})
}

/// A read-only probe: `repair_plan` never mutates anything.
fn probe_body() -> Value {
    json!({"command":"repair_plan"})
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

/// Outcome of an accepted `submit_commit`.
#[derive(Clone, Debug)]
struct Accepted {
    frontier: Frontier,
    ack: Vec<u8>,
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

/// A C-20 repair plan.
#[derive(Clone, Debug)]
struct Plan {
    removed: Vec<String>,
    parent: Frontier,
}

/// A kernel release accepted by the adapter, with its certificate.
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

/// A request stopped at an armed crash point, with the state just before it.
struct Crashed {
    request: SignedRequest,
    command: String,
    checkpoint: Value,
    trace: Vec<Value>,
}

struct World {
    tag: String,
    /// The adapter directory.
    dir: tempfile::TempDir,
    /// The client storage files.
    clients: tempfile::TempDir,
    /// `None` between a crash (or a clean drop) and the next `open`.
    adapter: Option<TestAdapter>,
    clock: FixedClock,
    apf_public: Vec<u8>,
    seqs: HashMap<String, u64>,
    /// The label of each actor's currently registered identity, when it is not the
    /// original one.
    keys: HashMap<String, String>,
    /// Counter for distinct provider rand streams, storage files and adapter opens.
    counter: u64,
}

/// Genesis with the root; bob, carol, dave and erin delegated `read`, `write` and
/// `admit`; bob and carol admitted by the root.
struct Setup {
    w: World,
    root: Client,
    bob: Client,
    carol: Client,
}

impl World {
    fn next(&mut self) -> u64 {
        self.counter += 1;
        self.counter
    }

    fn a(&mut self) -> &mut TestAdapter {
        self.adapter.as_mut().expect("the adapter is open")
    }

    /// A fresh storage file path for `name`.
    fn client_file(&mut self, name: &str) -> PathBuf {
        let n = self.next();
        self.clients.path().join(format!("{name}-{n}.sqlite"))
    }

    /// A provider over the storage file at `path`, with its own rand stream.
    fn provider_at(&mut self, path: &Path) -> Prov {
        let n = self.next();
        FileProvider::open(
            path,
            ScriptedRand::new(format!("recovery-provider/{}/{n}", self.tag).as_bytes()),
        )
    }

    /// A provider over a new storage file for `name`.
    fn provider(&mut self, name: &str) -> Prov {
        let path = self.client_file(name);
        self.provider_at(&path)
    }

    /// The actor's currently registered identity, as far as the test knows.
    fn current_identity(&self, actor: &str) -> ClientIdentity {
        match self.keys.get(actor) {
            Some(label) => identity_from(label),
            None => identity(actor),
        }
    }

    /// Reloads `subject` from the storage file at `path` (C-33).
    fn load_at(
        &mut self,
        path: &Path,
        subject: &str,
        pending_commit: Option<&[u8]>,
        pending_identity: Option<&str>,
    ) -> Client {
        let provider = self.provider_at(path);
        let identity = self.current_identity(subject);
        ClientEndpoint::load(
            GROUP,
            subject,
            identity,
            provider,
            &self.apf_public,
            pending_commit,
            pending_identity.map(identity_from),
        )
        .unwrap_or_else(|err| panic!("{subject} reloads from its storage, got {err}"))
    }

    /// Restarts `client`: drops it, then reloads it from the same storage file.
    fn reload(
        &mut self,
        mut client: Client,
        pending_commit: Option<&[u8]>,
        pending_identity: Option<&str>,
    ) -> Client {
        let subject = client.subject().to_owned();
        let path = client.mls_parts_mut().1.path().to_path_buf();
        drop(client);
        self.load_at(&path, &subject, pending_commit, pending_identity)
    }

    /// `body` signed by `signer_identity` as `actor` at the actor's next sequence.
    fn request_with(
        &mut self,
        actor: &str,
        signer_identity: &ClientIdentity,
        body: &Value,
    ) -> SignedRequest {
        let sequence = self.seqs.entry(actor.to_owned()).or_insert(0);
        *sequence += 1;
        sign(signer_identity.signer(), GROUP, actor, *sequence, body)
    }

    /// `body` signed by the actor's current identity at its next sequence.
    fn request(&mut self, actor: &str, body: &Value) -> SignedRequest {
        let signer_identity = self.current_identity(actor);
        self.request_with(actor, &signer_identity, body)
    }

    fn send_with(
        &mut self,
        actor: &str,
        signer_identity: &ClientIdentity,
        body: &Value,
    ) -> Result<Value, String> {
        let request = self.request_with(actor, signer_identity, body);
        self.a().handle(&request)
    }

    fn send(&mut self, actor: &str, body: &Value) -> Result<Value, String> {
        let request = self.request(actor, body);
        self.a().handle(&request)
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
        self.a().checkpoint().expect("checkpoint")
    }

    fn frontier(&mut self) -> Frontier {
        self.a().frontier().expect("adapter frontier")
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

    fn delegate(&mut self, subject: &str) {
        let body = delegate_body(subject, &identity(subject));
        self.ok(ROOT, &body);
    }

    fn revoke(&mut self, subject: &str, right: &str) -> Value {
        self.ok(
            ROOT,
            &json!({"command":"revoke", "subject":subject, "right":right}),
        )
    }

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

    /// Honest candidate on a new storage file: prepare at the current generations,
    /// certify, finalize.
    fn candidate(&mut self, subject: &str) -> JoinCandidate<Prov> {
        let rights = self.rights_of(subject);
        let provider = self.provider(subject);
        let prepared = PreparedJoin::prepare(
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
        let response = self.ok(actor, &probe_body());
        Plan {
            removed: response["removed"]
                .as_array()
                .expect("removed list")
                .iter()
                .map(|name| name.as_str().expect("removed name").to_owned())
                .collect(),
            parent: Frontier {
                epoch: response["parent_epoch"].as_u64().expect("parent_epoch"),
                branch: response["parent_branch"]
                    .as_str()
                    .expect("parent_branch")
                    .to_owned(),
            },
        }
    }

    /// `confirm_repair` with the member's own honest confirmation.
    fn confirm(&mut self, member: &mut Client) -> Value {
        let actor = member.subject().to_owned();
        let confirmation = member
            .confirmation()
            .unwrap_or_else(|err| panic!("{actor} builds its confirmation, got {err}"));
        self.ok(&actor, &confirm_body(&confirmation))
    }

    /// The APF signer, rebuilt from the test-only seed file in the temporary directory.
    /// Used only to rebuild bytes the adapter signs deterministically.
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

    /// The release certificate the APF signs for `body` and the kernel release event
    /// `event_hash` (§4.5, C-14), rebuilt independently.
    fn rebuild_certificate(
        &self,
        actor: &str,
        op: &str,
        body: &Value,
        event_hash: &str,
    ) -> Vec<u8> {
        signed(
            &self.apf_signer(),
            release_tbs(&self.apf_key_id(), actor, op, body, event_hash),
        )
    }

    /// The canonical ack the APF signs for `commit` (§4.6), rebuilt independently. Its
    /// policy fields are the kernel's now (R-11), so it is called right after the commit's
    /// kernel step, before any other.
    fn rebuild_ack(
        &mut self,
        parent: &Frontier,
        successor: &Frontier,
        commit: &[u8],
        kind: u8,
    ) -> Vec<u8> {
        let checkpoint = self.checkpoint();
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .expect("policy_revision");
        let policy_digest =
            hex::decode(checkpoint["policy_digest"].as_str().expect("policy_digest"))
                .expect("policy_digest is hex");
        signed(
            &self.apf_signer(),
            ack_tbs(
                &self.apf_key_id(),
                parent,
                successor,
                commit,
                kind,
                policy_revision,
                &policy_digest,
            ),
        )
    }

    fn verify_ack(&self, ack: &[u8]) -> CanonicalAck {
        CanonicalAck::verify(ack, &self.apf_public, &RustCrypto::default())
            .expect("ack verifies under the APF key")
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
        let response = self.ok(actor, &allocate_body(op));
        assert_eq!(response["op"], json!(op));
    }

    /// A C-16 release body at the current kernel frontier and policy revision.
    fn release_body(&mut self, actor: &str, op: &str, payload: &[u8]) -> Value {
        let frontier = self.frontier();
        let policy_revision = self.policy_revision();
        let digest = independent_digest(op, payload, &frontier, policy_revision);
        json!({
            "command":"release", "op":op, "right":"write", "digest":digest,
            "cover":self.cover(actor), "policy_revision":policy_revision,
            "epoch":frontier.epoch, "branch":frontier.branch
        })
    }

    /// An honest release. The returned certificate must equal the independent rebuild
    /// over the kernel release event, which validates `rebuild_certificate`.
    fn release(&mut self, actor: &str, op: &str, payload: &[u8]) -> Released {
        let body = self.release_body(actor, op, payload);
        let response = self.ok(actor, &body);
        let certificate = hex::decode(
            response["certificate"]
                .as_str()
                .expect("release response carries the certificate in hex"),
        )
        .expect("certificate is hex");
        let event_hash = response["event_hash"]
            .as_str()
            .expect("release event hash")
            .to_owned();
        let checkpoint = self.checkpoint();
        assert_eq!(last_kind(&checkpoint), "release");
        assert_eq!(
            last_hash(&checkpoint),
            event_hash,
            "the release event is the last kernel event"
        );
        assert_eq!(
            certificate,
            self.rebuild_certificate(actor, op, &body, &event_hash),
            "the independent certificate rebuild matches an issued certificate"
        );
        Released {
            op: op.to_owned(),
            actor: actor.to_owned(),
            payload: payload.to_vec(),
            certificate,
        }
    }

    fn persist(&mut self, actor: &str, op: &str, envelope: &[u8]) {
        let response = self.ok(actor, &persist_body(op, envelope));
        assert_eq!(response["op"], json!(op));
    }

    fn emit(&mut self, actor: &str, op: &str, envelope: &[u8]) {
        let response = self.ok(actor, &emit_body(op, envelope));
        assert_eq!(response["op"], json!(op));
        assert_eq!(response["envelope"], json!(lower_hex(envelope)));
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

    // -- crashes and restarts --------------------------------------------------------

    /// Arms `point`, sends `body` as `actor` and requires `crashed`. Every later call on
    /// the crashed adapter value is also `crashed` (C-33); the value is then dropped.
    fn crash(&mut self, point: CrashPoint, actor: &str, body: &Value) -> Crashed {
        let checkpoint = self.checkpoint();
        let trace = self.a().trace();
        let request = self.request(actor, body);
        self.a().crash_after(point);
        code(self.a().handle(&request), CRASHED);
        code(self.a().checkpoint(), CRASHED);
        drop(self.adapter.take());
        Crashed {
            request,
            command: body["command"].as_str().expect("command").to_owned(),
            checkpoint,
            trace,
        }
    }

    /// `Adapter::open` on the directory; it must succeed.
    fn reopen(&mut self) {
        assert!(self.adapter.is_none(), "the old adapter value was dropped");
        let n = self.next();
        let (provider, _) =
            scripted_provider(format!("recovery-apf/{}/open/{n}", self.tag).as_bytes());
        let adapter = Adapter::open(self.dir.path(), provider, self.clock.clone())
            .unwrap_or_else(|err| panic!("open after restart, got {err}"));
        self.adapter = Some(adapter);
    }
}

/// Full genesis (§5.1) with a file-backed root.
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let clients = tempfile::tempdir().expect("client storage directory");
    let clock = FixedClock::new(NOW);
    let (provider, _) = scripted_provider(format!("recovery-apf/{tag}").as_bytes());
    let root_identity = identity(ROOT);
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity.public_key(),
        provider,
        clock.clone(),
    )
    .expect("begin_genesis");
    let apf_public = pending.apf_public_key().to_vec();
    let mut w = World {
        tag: tag.to_owned(),
        dir,
        clients,
        adapter: None,
        clock,
        apf_public,
        seqs: HashMap::new(),
        keys: HashMap::new(),
        counter: 0,
    };
    let root_provider = w.provider(ROOT);
    let root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        root_provider,
        pending.founder_certificate(),
        pending.apf_anchor(),
        &w.apf_public,
    )
    .expect("root founds the group");
    let group_info = root.export_group_info().expect("export GroupInfo");
    let ratchet_tree = root.export_ratchet_tree().expect("export ratchet tree");
    w.adapter = Some(
        pending
            .complete(&group_info, &ratchet_tree)
            .expect("genesis completes"),
    );
    (w, root)
}

fn setup(tag: &str) -> Setup {
    let (mut w, mut root) = genesis(tag);
    for subject in ["bob", "carol", "dave", "erin"] {
        w.delegate(subject);
    }
    let mut bob = admit(&mut w, &mut root, "bob", &mut []);
    let carol = admit(&mut w, &mut root, "carol", &mut [&mut bob]);
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

// ---------------------------------------------------------------------------
// Checks and flows
// ---------------------------------------------------------------------------

/// Handles the exact `request` and asserts the error code, an unchanged kernel and
/// exactly one trace event whose outcome is that code.
fn rejected_request(w: &mut World, request: &SignedRequest, expected: &str) -> String {
    let before = w.checkpoint();
    let trace_len = w.a().trace().len();
    let err = code(w.a().handle(request), expected);
    assert_eq!(
        w.checkpoint(),
        before,
        "rejected request ({err}) must leave the kernel unchanged"
    );
    let trace = w.a().trace();
    assert_eq!(trace.len(), trace_len + 1, "one trace event per request");
    assert_eq!(trace[trace_len]["outcome"], json!(expected), "{err}");
    err
}

fn rejected_with(
    w: &mut World,
    actor: &str,
    signer_identity: &ClientIdentity,
    body: &Value,
    expected: &str,
) -> String {
    let request = w.request_with(actor, signer_identity, body);
    rejected_request(w, &request, expected)
}

fn rejected(w: &mut World, actor: &str, body: &Value, expected: &str) -> String {
    let request = w.request(actor, body);
    rejected_request(w, &request, expected)
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

/// After `open`, the trace is the trace before the crash plus exactly one event for the
/// crashed request, `{actor, sequence, command, outcome}` (C-5, C-32).
fn assert_recovery_event(w: &mut World, crashed: &Crashed, outcome: &str) {
    let trace = w.a().trace();
    assert_eq!(
        trace.len(),
        crashed.trace.len() + 1,
        "exactly one trace event for the crashed request: {trace:?}"
    );
    assert_eq!(&trace[..crashed.trace.len()], crashed.trace.as_slice());
    assert_eq!(
        trace[crashed.trace.len()],
        json!({
            "actor": crashed.request.actor,
            "sequence": crashed.request.sequence,
            "command": crashed.command,
            "outcome": outcome,
        })
    );
}

/// C-32 applied branch: the kernel applied the crashed request exactly once (revision
/// plus one, last event `kind`), the trace records `recovered`, and the request's
/// sequence stays consumed.
fn assert_recovered(w: &mut World, crashed: &Crashed, kind: &str) {
    let checkpoint = w.checkpoint();
    assert_eq!(
        revision(&checkpoint),
        revision(&crashed.checkpoint) + 1,
        "the kernel applied the crashed request exactly once"
    );
    assert_eq!(last_kind(&checkpoint), kind);
    assert_recovery_event(w, crashed, RECOVERED);
    rejected_request(w, &crashed.request, "unauthenticated");
}

/// C-32 not-applied branch: the kernel is unchanged, the trace records `crashed`, and
/// the request's sequence stays consumed (C-31, C-4).
fn assert_discarded(w: &mut World, crashed: &Crashed) {
    assert_eq!(
        w.checkpoint(),
        crashed.checkpoint,
        "a crash before the kernel call leaves the kernel unchanged"
    );
    assert_recovery_event(w, crashed, CRASHED);
    rejected_request(w, &crashed.request, "unauthenticated");
}

/// Submits an honest staged Add and merges it at the committer and `others`. The ack
/// must equal the independent rebuild.
fn canonical_add(
    w: &mut World,
    committer: &mut Client,
    staged: &StagedAdd,
    others: &mut [&mut Client],
) -> Accepted {
    let actor = committer.subject().to_owned();
    let parent = w.frontier();
    assert_eq!(staged.parent, parent, "staged on the canonical frontier");
    let accepted = accepted_from(&w.ok(&actor, &submit_body("admit", &parent, &staged.commit)));
    assert_eq!(accepted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.frontier(), accepted.frontier);
    assert_eq!(
        accepted.ack,
        w.rebuild_ack(&parent, &accepted.frontier, &staged.commit, KIND_ADMIT),
        "the independent ack rebuild matches an issued ack"
    );
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

/// Full honest admission of `subject`; returns the joined client, the staged commit and
/// the accepted ack.
fn admit_full(
    w: &mut World,
    committer: &mut Client,
    subject: &str,
    others: &mut [&mut Client],
) -> (Client, StagedAdd, Accepted) {
    let candidate = w.candidate(subject);
    let staged = committer
        .stage_add(candidate.key_package())
        .expect("stage add");
    let accepted = canonical_add(w, committer, &staged, others);
    let joined = candidate
        .join(&staged.welcome, &accepted.ack)
        .unwrap_or_else(|err| panic!("{subject} joins, got {err}"));
    assert_eq!(
        joined.frontier().expect("joined frontier"),
        accepted.frontier
    );
    (joined, staged, accepted)
}

fn admit(
    w: &mut World,
    committer: &mut Client,
    subject: &str,
    others: &mut [&mut Client],
) -> Client {
    admit_full(w, committer, subject, others).0
}

/// The committer confirms, then another continuing member confirms and the fence opens
/// with `pair` evidence.
fn open_fence(w: &mut World, committer: &mut Client, other: &mut Client) {
    let first = w.confirm(committer);
    assert_eq!(first["opened"], json!(false), "committer alone: {first}");
    let second = w.confirm(other);
    assert_eq!(second, json!({"opened": true, "evidence": "pair"}));
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(false));
    assert_eq!(checkpoint["repair_pending"], Value::Null);
}

/// C-28 offer: root grants `right` at `generation` to a current member.
fn offer(w: &mut World, subject: &str, right: &str, generation: u64) {
    let before = w.checkpoint();
    let response = w.ok(ROOT, &grant_body(subject, right, generation));
    assert_eq!(response, json!({"pending": true}));
    assert_eq!(
        w.checkpoint(),
        before,
        "an offer leaves the kernel unchanged"
    );
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

/// Protects `released` at `sender`, then persists and emits the envelope as its actor.
fn finish(w: &mut World, sender: &mut Client, released: Released) -> Published {
    let envelope = sender
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .unwrap_or_else(|err| panic!("{} protects {}, got {err}", released.actor, released.op));
    w.persist(&released.actor, &released.op, &envelope);
    w.emit(&released.actor, &released.op, &envelope);
    Published { released, envelope }
}

/// Allocate, release, protect, persist and emit one operation of `sender`.
fn publish(w: &mut World, sender: &mut Client, op: &str) -> Published {
    let actor = sender.subject().to_owned();
    w.allocate(&actor, op);
    let released = w.release(&actor, op, &payload_for(op));
    finish(w, sender, released)
}

/// Receives, consumes and delivers `published` at `receiver`; returns the receipt.
fn deliver_to(w: &mut World, receiver: &mut Client, published: &Published) -> Vec<u8> {
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
    receipt
}

/// Releases `op` for `actor` through an adapter crash at `point` after the kernel
/// release, reopens, and returns the certificate rebuilt from the kernel release event.
/// The caller proves it is the stored certificate by persisting an envelope built from it.
fn crashed_release(w: &mut World, point: CrashPoint, actor: &str, op: &str) -> Released {
    w.allocate(actor, op);
    let payload = payload_for(op);
    let body = w.release_body(actor, op, &payload);
    let crashed = w.crash(point, actor, &body);
    w.reopen();
    assert_recovered(w, &crashed, "release");
    // Recovery appended no kernel event (revision plus one exactly), so the last event
    // is the crashed release.
    let checkpoint = w.checkpoint();
    assert_eq!(revision(&checkpoint), revision(&crashed.checkpoint) + 1);
    let operation = kernel_operation(&checkpoint, op).expect("released operation");
    assert_eq!(operation["status"], json!("released"));
    let event_hash = last_hash(&checkpoint);
    Released {
        op: op.to_owned(),
        actor: actor.to_owned(),
        payload,
        certificate: w.rebuild_certificate(actor, op, &body, &event_hash),
    }
}

/// A repair of carol's revoked read, committed by the root, through an adapter crash at
/// `point`. Returns the rebuilt repair ack, already applied by the root and bob.
fn crashed_repair(
    w: &mut World,
    point: CrashPoint,
    root: &mut Client,
    bob: &mut Client,
) -> Accepted {
    let response = w.revoke("carol", "read");
    assert_eq!(response["read_fenced"], json!(true));
    let plan = w.plan(ROOT);
    assert_eq!(plan.removed, vec!["carol".to_owned()]);
    let staged = root
        .stage_repair(&plan.removed)
        .expect("stage the planned repair");
    assert_eq!(staged.parent, plan.parent);
    let crashed = w.crash(
        point,
        ROOT,
        &submit_body("repair", &staged.parent, &staged.commit),
    );
    w.reopen();
    assert_recovered(w, &crashed, "repair_stage");

    let successor = w.frontier();
    assert_eq!(successor.epoch, staged.parent.epoch + 1);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["read_fenced"], json!(true), "fence stays closed");
    assert_eq!(checkpoint["repair_pending"], json!(successor.branch));
    let ack = w.rebuild_ack(&staged.parent, &successor, &staged.commit, KIND_REPAIR);
    for member in [root, bob] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &ack)
                .expect("continuing member merges the recovered repair"),
            successor
        );
    }
    Accepted {
        frontier: successor,
        ack,
    }
}

/// A rekey of bob's write through an adapter crash at `point` after the kernel `rekey`.
/// Afterwards the old key no longer authenticates, the new one does, the offer is gone,
/// and every member applies the rebuilt update ack.
fn crashed_rekey(
    w: &mut World,
    point: CrashPoint,
    root: &mut Client,
    bob: &mut Client,
    carol: &mut Client,
) {
    let old = identity("bob");
    assert!(w.authenticates("bob", &old), "positive: the original key");
    let generation = revoke_and_offer_write(w, "bob");
    let label = new_label("bob", &format!("{point:?}"));
    let new_identity = identity_from(&label);
    assert!(!w.authenticates("bob", &new_identity));
    let rights = rights_with(&w.rights_of("bob"), (Right::Write, generation));
    let staged = bob
        .stage_rekey(identity_from(&label), &rights)
        .expect("stage the rekey");
    let policy_revision = w.policy_revision();
    let crashed = w.crash(
        point,
        "bob",
        &submit_body("update", &staged.parent, &staged.commit),
    );
    w.reopen();
    assert_recovered(w, &crashed, "rekey");

    let successor = w.frontier();
    assert_eq!(successor.epoch, staged.parent.epoch + 1);
    assert_eq!(w.policy_revision(), policy_revision + 1);
    assert_eq!(w.rights_of("bob"), rights, "the kernel applied the offer");

    // The key rotation was recovered.
    rejected_with(w, "bob", &old, &probe_body(), "unauthenticated");
    assert!(
        w.authenticates("bob", &new_identity),
        "the new key authenticates after recovery"
    );
    w.keys.insert("bob".to_owned(), label.clone());

    // Every member applies the re-signed update ack; bob's identity is the new one.
    let ack = w.rebuild_ack(&staged.parent, &successor, &staged.commit, KIND_UPDATE);
    assert_eq!(
        bob.apply_ack(&staged.commit, &ack)
            .expect("bob merges his recovered update"),
        successor
    );
    assert_eq!(bob.identity().public_key(), new_identity.public_key());
    for member in [&mut *root, &mut *carol] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &ack)
                .expect("member merges the recovered update"),
            successor
        );
    }

    // The offer is gone: another update commit has no offer to apply.
    let again = bob
        .stage_rekey(
            identity_from(&format!("{label}/again")),
            &w.rights_of("bob"),
        )
        .expect("stage a second rekey");
    rejected(
        w,
        "bob",
        &submit_body("update", &again.parent, &again.commit),
        "unauthorized",
    );
    bob.discard_pending().expect("discard the refused rekey");
    assert_eq!(bob.frontier().expect("bob frontier"), successor);

    // The new leaf signer sends, and readers deliver.
    let published = publish(w, bob, &format!("op-after-rekey-{point:?}"));
    deliver_to(w, root, &published);
    deliver_to(w, carol, &published);
}

// ---------------------------------------------------------------------------
// Tests: barriers B1 to B8 (§6)
// ---------------------------------------------------------------------------

#[test]
fn b1_crash_after_allocate_allows_release_after_restart() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("b1");

    // Positive: an allocation without a crash is released by its owner and delivered.
    let control = publish(&mut w, &mut bob, "op-b1-control");
    deliver_to(&mut w, &mut root, &control);

    // B1: the adapter crashes after the kernel allocate, before its store write.
    let crashed = w.crash(CrashPoint::AfterKernel, "bob", &allocate_body("op-b1"));
    w.reopen();
    assert_recovered(&mut w, &crashed, "allocate");
    let checkpoint = w.checkpoint();
    let operation = kernel_operation(&checkpoint, "op-b1").expect("allocated operation");
    assert_eq!(operation["status"], json!("allocated"));
    assert_eq!(operation["actor"], json!("bob"));

    // The recovered owner (C-17) releases it.
    let released = w.release("bob", "op-b1", &payload_for("op-b1"));
    let envelope = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("bob protects the recovered operation");
    // Any other actor is still unauthorized on it.
    for intruder in ["carol", ROOT] {
        rejected(
            &mut w,
            intruder,
            &persist_body("op-b1", &envelope),
            "unauthorized",
        );
        rejected(&mut w, intruder, &abandon_body("op-b1"), "unauthorized");
        rejected(
            &mut w,
            intruder,
            &emit_body("op-b1", &envelope),
            "unauthorized",
        );
    }
    w.persist("bob", "op-b1", &envelope);
    w.emit("bob", "op-b1", &envelope);
    deliver_to(&mut w, &mut root, &Published { released, envelope });
    // The recovered allocation keeps its operation id.
    rejected(
        &mut w,
        "bob",
        &allocate_body("op-b1"),
        "duplicate_operation",
    );
}

#[test]
fn b2_crash_after_release_before_persist_abandons_permanently() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("b2");

    // Positive: a release without a crash; `release` checks the certificate rebuild.
    let control = publish(&mut w, &mut bob, "op-b2-control");
    deliver_to(&mut w, &mut root, &control);

    // (a) The adapter crashes after the kernel release. Recovery re-signs the
    // certificate from kernel state; it is byte-identical to the rebuild, because
    // `persist` accepts only the exact stored certificate (C-16).
    let released = crashed_release(&mut w, CrashPoint::AfterKernel, "bob", "op-b2a");
    let published = finish(&mut w, &mut bob, released);
    let receipt = deliver_to(&mut w, &mut root, &published);
    assert!(!receipt.is_empty());

    // (b) The client crashes after it received the certificate, before persist. The
    // restarted owner abandons the operation at the APF.
    w.allocate("bob", "op-b2b");
    let released = w.release("bob", "op-b2b", &payload_for("op-b2b"));
    let mut bob = w.reload(bob, None, None);
    assert_eq!(bob.frontier().expect("reloaded frontier"), w.frontier());
    let response = w.ok("bob", &abandon_body("op-b2b"));
    assert_eq!(response["op"], json!("op-b2b"));
    let checkpoint = w.checkpoint();
    assert_eq!(
        kernel_operation(&checkpoint, "op-b2b").expect("operation")["status"],
        json!("abandoned")
    );

    // The abandoned operation can never be persisted, emitted, consumed, released or
    // reused, even with a validly protected envelope for its certificate.
    let envelope = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("the client can still build an envelope");
    rejected(
        &mut w,
        "bob",
        &persist_body("op-b2b", &envelope),
        "invalid_transition",
    );
    rejected(
        &mut w,
        "bob",
        &emit_body("op-b2b", &envelope),
        "not_persisted",
    );
    rejected(&mut w, ROOT, &consume_body("op-b2b"), "not_persisted");
    let body = w.release_body("bob", "op-b2b", &payload_for("op-b2b"));
    rejected(&mut w, "bob", &body, "invalid_transition");
    rejected(
        &mut w,
        "bob",
        &allocate_body("op-b2b"),
        "duplicate_operation",
    );
    // Abandon is terminal and idempotent.
    let response = w.ok("bob", &abandon_body("op-b2b"));
    assert_eq!(response["op"], json!("op-b2b"));

    // The restarted client keeps working.
    let after = publish(&mut w, &mut bob, "op-b2-after");
    deliver_to(&mut w, &mut root, &after);
}

#[test]
fn b3_crash_after_persist_reemits_identical_bytes() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b3");

    // Positive: persisted bytes are re-emitted without a crash.
    let control = publish(&mut w, &mut bob, "op-b3-control");
    w.emit("bob", "op-b3-control", &control.envelope);
    deliver_to(&mut w, &mut root, &control);

    // B3: the adapter crashes after the kernel persist, before its store write.
    w.allocate("bob", "op-b3");
    let released = w.release("bob", "op-b3", &payload_for("op-b3"));
    let envelope = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("bob protects");
    let crashed = w.crash(
        CrashPoint::AfterKernel,
        "bob",
        &persist_body("op-b3", &envelope),
    );
    w.reopen();
    assert_recovered(&mut w, &crashed, "persist");
    let checkpoint = w.checkpoint();
    assert_eq!(
        kernel_operation(&checkpoint, "op-b3").expect("operation")["status"],
        json!("persisted")
    );

    // The exact persisted bytes are emitted, repeatedly, without a kernel change.
    let before = w.checkpoint();
    for _ in 0..2 {
        w.emit("bob", "op-b3", &envelope);
    }
    w.persist("bob", "op-b3", &envelope);
    assert_eq!(
        w.checkpoint(),
        before,
        "re-emission is not a kernel transition"
    );

    // A different, validly protected envelope for the same certificate is refused.
    let other = bob
        .protect(&released.certificate, CONTENT_TYPE, &released.payload)
        .expect("second protect");
    assert_ne!(other, envelope);
    rejected(
        &mut w,
        "bob",
        &emit_body("op-b3", &other),
        "binding_mismatch",
    );
    rejected(
        &mut w,
        "bob",
        &persist_body("op-b3", &other),
        "binding_mismatch",
    );

    let published = Published { released, envelope };
    deliver_to(&mut w, &mut root, &published);
    deliver_to(&mut w, &mut carol, &published);
}

#[test]
fn b4_crash_after_decrypt_before_consume_never_delivers() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b4");

    // Positive: the durable receiver receives, consumes and delivers.
    let control = publish(&mut w, &mut bob, "op-b4-control");
    deliver_to(&mut w, &mut root, &control);

    // B4: the root decrypts, then restarts before it consumes.
    let published = publish(&mut w, &mut bob, "op-b4");
    let before = w.checkpoint();
    let pending = root
        .receive(&published.envelope)
        .expect("root decrypts and holds the plaintext");
    assert_eq!(pending.op(), "op-b4");
    drop(pending);
    let mut root = w.reload(root, None, None);
    assert_eq!(root.frontier().expect("reloaded frontier"), w.frontier());

    // The ratchet advanced durably: the same envelope never decrypts again.
    code(root.receive(&published.envelope), "undecryptable");
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint, before, "nothing was consumed");
    assert_eq!(consumptions(&checkpoint, "op-b4", ROOT), 0);

    // The message itself is intact: carol delivers it once.
    deliver_to(&mut w, &mut carol, &published);
    // The reloaded root receives and delivers later traffic.
    let later = publish(&mut w, &mut bob, "op-b4-later");
    deliver_to(&mut w, &mut root, &later);
}

#[test]
fn b5_crash_after_consume_rejects_replay() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b5");

    // Positive: consume once, then replay.
    let control = publish(&mut w, &mut bob, "op-b5-control");
    deliver_to(&mut w, &mut root, &control);
    rejected(&mut w, ROOT, &consume_body("op-b5-control"), "replay");

    // B5: the adapter crashes after the kernel consume, before its store write.
    let published = publish(&mut w, &mut bob, "op-b5");
    let pending = root.receive(&published.envelope).expect("root receives");
    let crashed = w.crash(CrashPoint::AfterKernel, ROOT, &consume_body("op-b5"));
    w.reopen();
    assert_recovered(&mut w, &crashed, "consume");
    let checkpoint = w.checkpoint();
    assert_eq!(consumptions(&checkpoint, "op-b5", ROOT), 1);

    // A retried consume is a replay; the kernel records one consumption only.
    rejected(&mut w, ROOT, &consume_body("op-b5"), "replay");
    assert_eq!(consumptions(&w.checkpoint(), "op-b5", ROOT), 1);

    // Another reader consumes and delivers once, then replays.
    let carol_receipt = deliver_to(&mut w, &mut carol, &published);
    rejected(&mut w, "carol", &consume_body("op-b5"), "replay");
    // The root lost its delivery: it has no receipt of its own, and another reader's
    // receipt does not deliver.
    code(pending.deliver(&carol_receipt), "binding_mismatch");
}

#[test]
fn b6_crash_after_stage_before_ack_never_merges() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b6");
    let parent = w.frontier();

    // B6: the adapter crashes after the intent, before the kernel admit.
    let candidate = w.candidate("dave");
    let staged = root.stage_add(candidate.key_package()).expect("stage add");
    assert_eq!(staged.parent, parent);
    let crashed = w.crash(
        CrashPoint::AfterIntent,
        ROOT,
        &submit_body("admit", &staged.parent, &staged.commit),
    );
    w.reopen();
    assert_discarded(&mut w, &crashed);
    assert_eq!(
        w.frontier(),
        parent,
        "kernel and sequencer stay at the parent"
    );

    // No client merges: nobody holds an ack.
    assert_eq!(bob.frontier().expect("bob frontier"), parent);
    assert_eq!(carol.frontier().expect("carol frontier"), parent);

    // The committer restarts with its submitted commit and discards it.
    let mut root = w.reload(root, Some(&staged.commit), None);
    assert_eq!(root.frontier().expect("root frontier"), parent);
    root.discard_pending()
        .expect("discard the never-acked commit");
    assert_eq!(root.frontier().expect("root frontier"), parent);

    // It restages; the new commit is canonical and every member merges it.
    let restaged = root
        .stage_add(candidate.key_package())
        .expect("restage add");
    assert_ne!(restaged.commit, staged.commit);
    let accepted = canonical_add(&mut w, &mut root, &restaged, &mut [&mut bob, &mut carol]);
    let mut dave = candidate
        .join(&restaged.welcome, &accepted.ack)
        .expect("dave joins from the new Welcome");
    assert_eq!(dave.frontier().expect("dave frontier"), accepted.frontier);
    assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "dave"]);

    // The crashed commit can never become canonical.
    rejected(
        &mut w,
        ROOT,
        &submit_body("admit", &staged.parent, &staged.commit),
        "stale_frontier",
    );
    let published = publish(&mut w, &mut root, "op-b6");
    deliver_to(&mut w, &mut dave, &published);
}

#[test]
fn b7_crash_after_ack_before_merge_stays_locally_fenced_until_exact_merge() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b7");

    // Positive: bob is current and delivers.
    let control = publish(&mut w, &mut root, "op-b7-control");
    deliver_to(&mut w, &mut bob, &control);

    // B7, member: dave's admission is canonical; bob restarts before he applies the ack.
    let candidate = w.candidate("dave");
    let staged = root.stage_add(candidate.key_package()).expect("stage add");
    let parent = staged.parent.clone();
    let accepted = accepted_from(&w.ok(ROOT, &submit_body("admit", &parent, &staged.commit)));
    for member in [&mut root, &mut carol] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges"),
            accepted.frontier
        );
    }
    let mut dave = candidate
        .join(&staged.welcome, &accepted.ack)
        .expect("dave joins");
    let mut bob = w.reload(bob, None, None);
    assert_eq!(bob.frontier().expect("bob frontier"), parent);

    // While behind, bob's protect and receive fail on the frontier.
    w.allocate("bob", "op-b7-bob");
    let released = w.release("bob", "op-b7-bob", &payload_for("op-b7-bob"));
    code(
        bob.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );
    let from_root = publish(&mut w, &mut root, "op-b7-root");
    code_in(
        "bob receives while behind",
        bob.receive(&from_root.envelope),
        &["binding_mismatch", "undecryptable"],
    );
    // A commit other than the exact acked bytes does not merge.
    code(
        bob.apply_ack(&flip_last(&staged.commit), &accepted.ack),
        "binding_mismatch",
    );
    assert_eq!(bob.frontier().expect("bob frontier"), parent);

    // The exact acked commit makes him current.
    assert_eq!(
        bob.apply_ack(&staged.commit, &accepted.ack)
            .expect("bob merges the exact acked commit"),
        accepted.frontier
    );
    let published = finish(&mut w, &mut bob, released);
    deliver_to(&mut w, &mut root, &published);
    deliver_to(&mut w, &mut dave, &published);
    deliver_to(&mut w, &mut bob, &from_root);

    // B7, committer: the root restarts after the ack, with its submitted commit pending.
    let candidate = w.candidate("erin");
    let staged = root.stage_add(candidate.key_package()).expect("stage add");
    let parent = staged.parent.clone();
    let accepted = accepted_from(&w.ok(ROOT, &submit_body("admit", &parent, &staged.commit)));
    for member in [&mut bob, &mut carol, &mut dave] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges"),
            accepted.frontier
        );
    }
    let mut erin = candidate
        .join(&staged.welcome, &accepted.ack)
        .expect("erin joins");
    let mut root = w.reload(root, Some(&staged.commit), None);
    assert_eq!(root.frontier().expect("root frontier"), parent);

    w.allocate(ROOT, "op-b7-root-behind");
    let released = w.release(ROOT, "op-b7-root-behind", &payload_for("op-b7-root-behind"));
    code(
        root.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );
    let from_bob = publish(&mut w, &mut bob, "op-b7-bob-2");
    code_in(
        "root receives while behind",
        root.receive(&from_bob.envelope),
        &["binding_mismatch", "undecryptable"],
    );

    // The committer merges its own commit under the ack.
    assert_eq!(
        root.apply_ack(&staged.commit, &accepted.ack)
            .expect("the committer merges its own acked commit"),
        accepted.frontier
    );
    let published = finish(&mut w, &mut root, released);
    deliver_to(&mut w, &mut erin, &published);
    deliver_to(&mut w, &mut root, &from_bob);
}

#[test]
fn b8_client_storage_rollback_is_unready_until_exact_frontier() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("b8");

    // An older snapshot of bob's storage, at epoch 2.
    let old_frontier = bob.frontier().expect("bob frontier");
    let snapshot = w.client_file("bob-snapshot");
    bob.mls_parts_mut().1.snapshot(&snapshot);

    // Positive: bob applies two acks in order and is current.
    let (mut dave, staged3, accepted3) =
        admit_full(&mut w, &mut root, "dave", &mut [&mut bob, &mut carol]);
    let (mut erin, staged4, accepted4) = admit_full(
        &mut w,
        &mut root,
        "erin",
        &mut [&mut bob, &mut carol, &mut dave],
    );
    let current = w.frontier();
    assert_eq!(current, accepted4.frontier);
    assert_eq!(bob.frontier().expect("bob frontier"), current);
    let control = publish(&mut w, &mut root, "op-b8-control");
    deliver_to(&mut w, &mut bob, &control);

    // B8: bob restarts from the older snapshot.
    drop(bob);
    let mut bob = w.load_at(&snapshot, "bob", None, None);
    assert_eq!(bob.frontier().expect("rolled-back frontier"), old_frontier);
    assert_ne!(old_frontier, current);

    // He is unready: protect and receive fail on the frontier.
    w.allocate("bob", "op-b8-bob");
    let released = w.release("bob", "op-b8-bob", &payload_for("op-b8-bob"));
    code(
        bob.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );
    let from_root = publish(&mut w, &mut root, "op-b8-root");
    code_in(
        "rolled-back bob receives",
        bob.receive(&from_root.envelope),
        &["binding_mismatch", "undecryptable"],
    );

    // Out of order: the later ack does not apply to the older frontier.
    code(
        bob.apply_ack(&staged4.commit, &accepted4.ack),
        "binding_mismatch",
    );
    assert_eq!(bob.frontier().expect("frontier"), old_frontier);

    // In order: the first missing ack, then the second.
    assert_eq!(
        bob.apply_ack(&staged3.commit, &accepted3.ack)
            .expect("the first missing ack applies"),
        accepted3.frontier
    );
    code(
        bob.protect(&released.certificate, CONTENT_TYPE, &released.payload),
        "binding_mismatch",
    );
    code(
        bob.apply_ack(&staged3.commit, &accepted3.ack),
        "binding_mismatch",
    );
    assert_eq!(
        bob.apply_ack(&staged4.commit, &accepted4.ack)
            .expect("the second missing ack applies"),
        current
    );

    // At the exact current frontier he is ready again.
    let published = finish(&mut w, &mut bob, released);
    deliver_to(&mut w, &mut root, &published);
    deliver_to(&mut w, &mut erin, &published);
    deliver_to(&mut w, &mut bob, &from_root);
}

// ---------------------------------------------------------------------------
// Tests: restart and recovery on `open` (C-31 to C-34)
// ---------------------------------------------------------------------------

#[test]
fn adapter_restart_reloads_sequencer_certificates_and_request_sequences() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("restart");

    // State to survive: a released operation, an allocated operation, an accepted
    // request, a pending offer, and the admission certificates of bob and carol.
    w.allocate("bob", "op-r-released");
    let released = w.release("bob", "op-r-released", &payload_for("op-r-released"));
    w.allocate("bob", "op-r-allocated");
    let accepted_request = w.request("bob", &allocate_body("op-r-replayed"));
    w.a()
        .handle(&accepted_request)
        .expect("the request is accepted before the restart");
    let generation = revoke_and_offer_write(&mut w, "carol");

    let checkpoint = w.checkpoint();
    let frontier = w.frontier();
    let trace = w.a().trace();

    // A clean restart.
    drop(w.adapter.take());
    let stored = store_rows(w.dir.path());
    w.reopen();
    assert_eq!(w.checkpoint(), checkpoint);
    assert_eq!(w.frontier(), frontier);
    assert_eq!(w.a().trace(), trace, "a clean restart adds no trace event");
    let reloaded = store_rows(w.dir.path());
    for (table, rows) in &stored {
        assert_eq!(
            reloaded.get(table),
            Some(rows),
            "adapter store table {table} survives the restart unchanged"
        );
    }

    // Request sequences: the accepted request cannot be replayed.
    rejected_request(&mut w, &accepted_request, "unauthenticated");

    // Operation owners: another actor is unauthorized; the owner proceeds.
    let body = w.release_body("carol", "op-r-allocated", &payload_for("op-r-allocated"));
    rejected(&mut w, "carol", &body, "unauthorized");
    let late = w.release("bob", "op-r-allocated", &payload_for("op-r-allocated"));

    // Certificates: envelopes built from the certificates issued before and after the
    // restart persist, and readers deliver them.
    let published = finish(&mut w, &mut bob, released);
    deliver_to(&mut w, &mut root, &published);
    let published = finish(&mut w, &mut bob, late);
    deliver_to(&mut w, &mut carol, &published);

    // Pending offer: carol's rekey still finds it. Sequencer: the update is canonical.
    let label = new_label("carol", "restart");
    let rights = rights_with(&w.rights_of("carol"), (Right::Write, generation));
    let staged = carol
        .stage_rekey(identity_from(&label), &rights)
        .expect("stage the rekey");
    let parent = w.frontier();
    let accepted = accepted_from(&w.ok(
        "carol",
        &submit_body("update", &staged.parent, &staged.commit),
    ));
    assert_eq!(
        accepted.ack,
        w.rebuild_ack(&parent, &accepted.frontier, &staged.commit, KIND_UPDATE)
    );
    assert_eq!(w.verify_ack(&accepted.ack).kind, AckKind::Update);
    for member in [&mut carol, &mut root, &mut bob] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges the update"),
            accepted.frontier
        );
    }
    w.keys.insert("carol".to_owned(), label);
    let mut dave = admit(&mut w, &mut root, "dave", &mut [&mut bob, &mut carol]);
    let published = publish(&mut w, &mut carol, "op-r-after");
    deliver_to(&mut w, &mut dave, &published);
}

#[test]
fn kernel_ahead_of_sequencer_recovers_on_open() {
    // Admission: the kernel admitted, the sequencer did not merge.
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            mut carol,
        } = setup("seq-admit");
        let candidate = w.candidate("dave");
        let staged = root.stage_add(candidate.key_package()).expect("stage add");
        let parent = staged.parent.clone();
        let crashed = w.crash(
            CrashPoint::AfterKernel,
            ROOT,
            &submit_body("admit", &parent, &staged.commit),
        );
        w.reopen();
        assert_recovered(&mut w, &crashed, "admit");
        let successor = w.frontier();
        assert_eq!(successor.epoch, parent.epoch + 1);
        assert_eq!(w.roster(), vec![ROOT, "bob", "carol", "dave"]);

        let ack = w.rebuild_ack(&parent, &successor, &staged.commit, KIND_ADMIT);
        for member in [&mut root, &mut bob, &mut carol] {
            assert_eq!(
                member
                    .apply_ack(&staged.commit, &ack)
                    .expect("member merges the recovered admission"),
                successor
            );
        }
        let mut dave = candidate
            .join(&staged.welcome, &ack)
            .expect("dave joins under the recovered ack");
        // The recovered sequencer sequences the next commit.
        let mut erin = admit(
            &mut w,
            &mut root,
            "erin",
            &mut [&mut bob, &mut carol, &mut dave],
        );
        let published = publish(&mut w, &mut root, "op-seq-admit");
        deliver_to(&mut w, &mut dave, &published);
        deliver_to(&mut w, &mut erin, &published);
    }

    // Repair: the kernel staged the repair, the sequencer did not merge.
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            carol: _,
        } = setup("seq-repair");
        let accepted = crashed_repair(&mut w, CrashPoint::AfterKernel, &mut root, &mut bob);
        // The recovered repair record lets the fence open on confirmation.
        open_fence(&mut w, &mut root, &mut bob);
        assert_eq!(
            stored_evidence(w.dir.path(), &accepted.frontier.branch).as_deref(),
            Some("pair")
        );
        let published = publish(&mut w, &mut bob, "op-seq-repair");
        deliver_to(&mut w, &mut root, &published);
    }

    // Rekey: the kernel applied the rekey, the sequencer did not merge.
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            mut carol,
        } = setup("seq-rekey");
        crashed_rekey(
            &mut w,
            CrashPoint::AfterKernel,
            &mut root,
            &mut bob,
            &mut carol,
        );
    }
}

#[test]
fn kernel_ahead_of_store_recovers_on_open() {
    // Delegate (key registration) and release (certificate).
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            mut carol,
        } = setup("store-delegate");
        let frank = identity("frank");
        let crashed = w.crash(
            CrashPoint::AfterSequencer,
            ROOT,
            &delegate_body("frank", &frank),
        );
        w.reopen();
        assert_recovered(&mut w, &crashed, "delegate");
        assert!(w.active("frank", "read"));
        // The key registration was recovered: frank authenticates, and his key cannot be
        // registered again (C-1).
        let response = w.ok("frank", &allocate_body("op-frank"));
        assert_eq!(response["op"], json!("op-frank"));
        rejected(
            &mut w,
            ROOT,
            &delegate_body("gina", &frank),
            "binding_mismatch",
        );
        let mut frank = admit(&mut w, &mut root, "frank", &mut [&mut bob, &mut carol]);

        let released = crashed_release(&mut w, CrashPoint::AfterSequencer, "bob", "op-store");
        let published = finish(&mut w, &mut bob, released);
        deliver_to(&mut w, &mut frank, &published);
        deliver_to(&mut w, &mut root, &published);
    }

    // Repair (repair record), then the confirmation that opens the fence (evidence).
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            carol: _,
        } = setup("store-repair");
        let accepted = crashed_repair(&mut w, CrashPoint::AfterSequencer, &mut root, &mut bob);

        // The recovered repair record accepts the committer's confirmation.
        let first = w.confirm(&mut root);
        assert_eq!(first, json!({"opened": false, "evidence": null}));
        // The adapter crashes after kernel `repair_open`, before its store write.
        let confirmation = bob.confirmation().expect("bob's confirmation");
        let crashed = w.crash(
            CrashPoint::AfterSequencer,
            "bob",
            &confirm_body(&confirmation),
        );
        w.reopen();
        assert_recovered(&mut w, &crashed, "repair_open");
        let checkpoint = w.checkpoint();
        assert_eq!(checkpoint["read_fenced"], json!(false), "the fence is open");
        assert_eq!(checkpoint["repair_pending"], Value::Null);
        drop(w.adapter.take());
        assert_eq!(
            stored_evidence(w.dir.path(), &accepted.frontier.branch).as_deref(),
            Some("pair"),
            "the confirmation evidence was recovered"
        );
        w.reopen();
        let published = publish(&mut w, &mut bob, "op-store-repair");
        deliver_to(&mut w, &mut root, &published);
    }

    // Rekey (key rotation, offer deletion).
    {
        let Setup {
            mut w,
            mut root,
            mut bob,
            mut carol,
        } = setup("store-rekey");
        crashed_rekey(
            &mut w,
            CrashPoint::AfterSequencer,
            &mut root,
            &mut bob,
            &mut carol,
        );
    }
}

#[test]
fn crash_before_kernel_discards_intent() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        carol: _,
    } = setup("intent");

    // allocate
    let crashed = w.crash(CrashPoint::AfterIntent, "bob", &allocate_body("op-i"));
    w.reopen();
    assert_discarded(&mut w, &crashed);
    assert!(kernel_operation(&w.checkpoint(), "op-i").is_none());
    w.allocate("bob", "op-i");

    // release
    let body = w.release_body("bob", "op-i", &payload_for("op-i"));
    let crashed = w.crash(CrashPoint::AfterIntent, "bob", &body);
    w.reopen();
    assert_discarded(&mut w, &crashed);
    assert_eq!(
        kernel_operation(&w.checkpoint(), "op-i").expect("operation")["status"],
        json!("allocated")
    );
    let released = w.release("bob", "op-i", &payload_for("op-i"));
    let published = finish(&mut w, &mut bob, released);

    // consume
    let pending = root.receive(&published.envelope).expect("root receives");
    let crashed = w.crash(CrashPoint::AfterIntent, ROOT, &consume_body("op-i"));
    w.reopen();
    assert_discarded(&mut w, &crashed);
    assert_eq!(consumptions(&w.checkpoint(), "op-i", ROOT), 0);
    let receipt = w.consumed(ROOT, "op-i");
    assert_eq!(
        pending.deliver(&receipt).expect("root delivers"),
        (CONTENT_TYPE.to_vec(), payload_for("op-i"))
    );

    // delegate: no key is registered by a discarded intent.
    let frank = identity("frank");
    let body = delegate_body("frank", &frank);
    let crashed = w.crash(CrashPoint::AfterIntent, ROOT, &body);
    w.reopen();
    assert_discarded(&mut w, &crashed);
    assert!(w.grant_record("frank", "read").is_none());
    rejected(
        &mut w,
        "frank",
        &allocate_body("op-frank"),
        "unauthenticated",
    );
    w.ok(ROOT, &body);
    let response = w.ok("frank", &allocate_body("op-frank"));
    assert_eq!(response["op"], json!("op-frank"));
}

#[test]
fn interrupted_genesis_can_restart() {
    // Positive: an uninterrupted genesis leaves no marker and reopens.
    {
        let (mut w, _root) = genesis("genesis-control");
        assert!(!w.dir.path().join(GENESIS_MARKER).exists());
        drop(w.adapter.take());
        w.reopen();
        assert_eq!(w.checkpoint()["roster"], json!([ROOT]));
    }

    let dir = adapter_dir();
    let clients = tempfile::tempdir().expect("client storage directory");
    let clock = FixedClock::new(NOW);
    let root_identity = || identity(ROOT);

    // The first genesis crashes inside `complete`, after kernel `init`.
    let (provider, _) = scripted_provider(b"recovery-apf/interrupted/first");
    let mut pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity().public_key(),
        provider,
        clock.clone(),
    )
    .expect("begin_genesis");
    let first_root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity(),
        FileProvider::open(
            &clients.path().join("root-first.sqlite"),
            ScriptedRand::new(b"recovery-provider/interrupted/first"),
        ),
        pending.founder_certificate(),
        pending.apf_anchor(),
        pending.apf_public_key(),
    )
    .expect("root founds the first group");
    let group_info = first_root.export_group_info().expect("GroupInfo");
    let ratchet_tree = first_root.export_ratchet_tree().expect("ratchet tree");
    pending.crash_after(CrashPoint::GenesisAfterKernel);
    code(pending.complete(&group_info, &ratchet_tree), CRASHED);
    drop(first_root);
    assert!(
        dir.path().join(GENESIS_MARKER).exists(),
        "the interrupted genesis leaves its marker (C-34)"
    );

    // `open` refuses the interrupted directory.
    let (provider, _) = scripted_provider(b"recovery-apf/interrupted/open");
    let err = code(
        Adapter::open(dir.path(), provider, clock.clone()),
        "uninitialized",
    );
    assert!(
        err.contains("interrupted genesis"),
        "open names the interrupted genesis, got {err}"
    );

    // `begin_genesis` on the same directory proceeds and completes.
    let (provider, _) = scripted_provider(b"recovery-apf/interrupted/second");
    let pending = Adapter::begin_genesis(
        dir.path(),
        GROUP,
        ROOT,
        root_identity().public_key(),
        provider,
        clock.clone(),
    )
    .expect("begin_genesis after an interrupted genesis");
    let apf_public = pending.apf_public_key().to_vec();
    let mut w = World {
        tag: "interrupted".to_owned(),
        dir,
        clients,
        adapter: None,
        clock,
        apf_public,
        seqs: HashMap::new(),
        keys: HashMap::new(),
        counter: 0,
    };
    let root_provider = w.provider(ROOT);
    let mut root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity(),
        root_provider,
        pending.founder_certificate(),
        pending.apf_anchor(),
        &w.apf_public,
    )
    .expect("root founds the group again");
    let group_info = root.export_group_info().expect("GroupInfo");
    let ratchet_tree = root.export_ratchet_tree().expect("ratchet tree");
    w.adapter = Some(
        pending
            .complete(&group_info, &ratchet_tree)
            .expect("genesis completes after an interrupted one"),
    );
    assert!(!w.dir.path().join(GENESIS_MARKER).exists());
    assert_eq!(w.frontier(), root.frontier().expect("root frontier"));

    // The new adapter works and survives a clean restart.
    w.delegate("bob");
    let mut bob = admit(&mut w, &mut root, "bob", &mut []);
    drop(w.adapter.take());
    w.reopen();
    let published = publish(&mut w, &mut root, "op-genesis");
    deliver_to(&mut w, &mut bob, &published);
}

#[test]
fn rekey_identity_survives_client_restart() {
    let Setup {
        mut w,
        mut root,
        mut bob,
        mut carol,
    } = setup("rekey-restart");
    let old = identity("bob");
    assert!(w.authenticates("bob", &old), "positive: the original key");

    // bob stages a rekey and submits it; it is canonical.
    let generation = revoke_and_offer_write(&mut w, "bob");
    let label = new_label("bob", "restart");
    let new_identity = identity_from(&label);
    let rights = rights_with(&w.rights_of("bob"), (Right::Write, generation));
    let staged = bob
        .stage_rekey(identity_from(&label), &rights)
        .expect("stage the rekey");
    let accepted = accepted_from(&w.ok(
        "bob",
        &submit_body("update", &staged.parent, &staged.commit),
    ));
    assert_eq!(
        accepted.ack,
        w.rebuild_ack(
            &staged.parent,
            &accepted.frontier,
            &staged.commit,
            KIND_UPDATE
        )
    );
    rejected_with(&mut w, "bob", &old, &probe_body(), "unauthenticated");

    // bob restarts before he applies the ack, with his pending commit and new identity.
    let mut bob = w.reload(bob, Some(&staged.commit), Some(&label));
    assert_eq!(bob.frontier().expect("bob frontier"), staged.parent);
    assert_eq!(
        bob.identity().public_key(),
        old.public_key(),
        "until the ack, bob's identity is the old one"
    );
    assert_eq!(
        bob.apply_ack(&staged.commit, &accepted.ack)
            .expect("bob merges his own acked update"),
        accepted.frontier
    );
    assert_eq!(
        bob.identity().public_key(),
        new_identity.public_key(),
        "after the ack, bob's identity is the new one"
    );
    for member in [&mut root, &mut carol] {
        assert_eq!(
            member
                .apply_ack(&staged.commit, &accepted.ack)
                .expect("member merges the update"),
            accepted.frontier
        );
    }
    w.keys.insert("bob".to_owned(), label);

    // The new key authenticates; the old one does not.
    let response = w
        .send_with("bob", &new_identity, &allocate_body("op-rekey-new-key"))
        .expect("the new key authenticates");
    assert_eq!(response["op"], json!("op-rekey-new-key"));
    rejected_with(
        &mut w,
        "bob",
        &old,
        &allocate_body("op-rekey-old-key"),
        "unauthenticated",
    );

    // bob's new leaf signer sends, and readers deliver.
    let published = publish(&mut w, &mut bob, "op-rekey-restart");
    deliver_to(&mut w, &mut root, &published);
    deliver_to(&mut w, &mut carol, &published);
}

/// R-12 (D-16): a kernel step whose `now` is past a delegation's expiry records an
/// `expire` event before its own event, in the same kernel transaction. A crash after
/// that kernel call must still be recovered as applied: the kernel advanced by the expiry
/// and the step, and the last event is the step's own (C-32, C-45).
#[test]
fn crash_after_a_kernel_step_that_recorded_an_expiry_is_recovered() {
    let Setup { mut w, .. } = setup("expiry-crash");
    // frank holds a short delegation and is not admitted, so his expiry does not fence.
    let frank = identity("frank");
    w.ok(
        ROOT,
        &json!({
            "command":"delegate", "subject":"frank", "rights":["read"], "resources":[GROUP],
            "expires_at":NOW + 10, "not_before":0, "depth":4,
            "subject_key":lower_hex(frank.public_key())
        }),
    );
    w.clock.set(NOW + 11);

    let gina = identity("gina");
    let crashed = w.crash(CrashPoint::AfterKernel, ROOT, &delegate_body("gina", &gina));
    w.reopen();
    let checkpoint = w.checkpoint();
    assert_eq!(
        revision(&checkpoint),
        revision(&crashed.checkpoint) + 2,
        "the expiry and the crashed request each advanced the kernel once"
    );
    let history = checkpoint["history"].as_array().expect("history");
    let kinds: Vec<&str> = history[history.len() - 2..]
        .iter()
        .map(|entry| entry["event"]["kind"].as_str().expect("kind"))
        .collect();
    assert_eq!(kinds, ["expire", "delegate"]);
    assert_eq!(last_kind(&checkpoint), "delegate");
    assert_recovery_event(&mut w, &crashed, RECOVERED);
    rejected_request(&mut w, &crashed.request, "unauthenticated");
    assert_eq!(
        w.grant_record("frank", "read").expect("frank read")["active"],
        json!(false)
    );
    assert!(w.active("gina", "read"));
    assert_eq!(checkpoint["read_fenced"], json!(false));
    // gina's key registration was recovered with the request: she authenticates.
    let response = w.ok("gina", &allocate_body("op-gina"));
    assert_eq!(response["op"], json!("op-gina"));
}
