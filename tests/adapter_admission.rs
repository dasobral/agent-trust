//! Phase 4.2 contract tests: canonical frontier, public sequencer, genesis and admission
//! (`docs/adapter-contract.md` §4.1–§4.6, §4.10 C-7 to C-12, §5.1, §5.2).
//!
//! The frontier, `apf_anchor`, `authz_incarnation` and the founder and admission
//! certificate layouts are decoded or recomputed here with `tls_codec` and `sha2`,
//! independently of `src/wire.rs`. Raw OpenMLS state is read through
//! `ClientEndpoint::mls_parts_mut`, which honest code never uses.
//!
//! Every negative case runs after the matching positive path in the same test, so an
//! adapter or client that rejects everything cannot pass. No application messages are
//! sent: they belong to phase 4.3.

mod common;

use std::collections::HashMap;
use std::path::Path;

use agent_trust::adapter::{Adapter, ClientIdentity, ADAPTER_FILE, APF_KEY_FILE, AUTHORITY_FILE};
use agent_trust::client::{ClientEndpoint, JoinCandidate, PreparedJoin, StagedAdd};
use agent_trust::wire::{
    AckKind, AdmissionCertificate, CanonicalAck, FounderCertificate, Frontier, Right,
    SignedStructure,
};
use common::{
    adapter_dir, code, dalek_public, files_in, lower_hex, scripted_provider, sign, DalekSigner,
    FixedClock, ScriptedRand, TestProvider,
};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::{Ciphersuite, SignatureScheme};
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
/// C-8: the sequencer's OpenMLS storage file.
const SEQUENCER_FILE: &str = "sequencer.sqlite";

// Spelled out here independently of `src/wire.rs`.
const T_FRONTIER_LABEL: &[u8] = b"agent-trust/frontier/v1";
const T_FOUNDER_LABEL: &[u8] = b"agent-trust/founder/v1";
const T_ADMISSION_MAGIC: &[u8] = b"AT-APF-KP";
const CERT_EXT: u16 = 0xf042;
const ANCHOR_EXT: u16 = 0xf043;
const INC_EXT: u16 = 0xf044;
const ZERO_HASH: [u8; 32] = [0; 32];

const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];

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

/// §4.1 `FrontierInput`, hashed and hex-encoded, computed without `src/wire.rs`.
fn independent_frontier(
    group_id: &[u8],
    epoch: u64,
    tree_hash: &[u8],
    confirmed_transcript_hash: &[u8],
) -> Frontier {
    let mut input = Vec::new();
    input.extend(vl(T_FRONTIER_LABEL));
    input.extend(vl(group_id));
    input.extend(tls_u64(epoch));
    input.extend(vl(tree_hash));
    input.extend(vl(confirmed_transcript_hash));
    Frontier {
        epoch,
        branch: lower_hex(&sha256(&input)),
    }
}

fn context_frontier(context: &GroupContext) -> Frontier {
    independent_frontier(
        context.group_id().as_slice(),
        context.epoch().as_u64(),
        context.tree_hash(),
        context.confirmed_transcript_hash(),
    )
}

/// Frontier recomputed from the member's raw OpenMLS group context.
fn raw_frontier(client: &mut Client) -> Frontier {
    let (group, _, _) = client.mls_parts_mut();
    context_frontier(group.public_group().group_context())
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

/// `RightGeneration rights<V>`: a `VLBytes` of `uint8 right ‖ uint64 generation` records.
fn decode_rights(bytes: &[u8]) -> Vec<(u8, u64)> {
    let mut reader = TlsReader::new(bytes);
    let mut out = Vec::new();
    while !reader.rest.is_empty() {
        let right = reader.u8();
        let generation = reader.u64();
        out.push((right, generation));
    }
    out
}

fn encode_rights(rights: &[(u8, u64)]) -> Vec<u8> {
    let mut body = Vec::new();
    for (right, generation) in rights {
        body.push(*right);
        body.extend(tls_u64(*generation));
    }
    vl(&body)
}

fn codes(rights: &[(Right, u64)]) -> Vec<(u8, u64)> {
    rights.iter().map(|(r, g)| (*r as u8, *g)).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// §4.2 `ApfAnchor` after R-11: static, without policy.
struct TestAnchor {
    version: u8,
    apf_key_id: Vec<u8>,
    group: Vec<u8>,
}

fn decode_anchor(bytes: &[u8]) -> TestAnchor {
    let mut reader = TlsReader::new(bytes);
    let anchor = TestAnchor {
        version: reader.u8(),
        apf_key_id: reader.opaque(),
        group: reader.opaque(),
    };
    reader.finish();
    anchor
}

fn encode_anchor(anchor: &TestAnchor) -> Vec<u8> {
    let mut out = vec![anchor.version];
    out.extend(vl(&anchor.apf_key_id));
    out.extend(vl(&anchor.group));
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TestIncarnation {
    version: u8,
    subject: Vec<u8>,
    rights: Vec<(u8, u64)>,
    admission_cert_hash: Vec<u8>,
}

fn decode_incarnation(bytes: &[u8]) -> TestIncarnation {
    let mut reader = TlsReader::new(bytes);
    let incarnation = TestIncarnation {
        version: reader.u8(),
        subject: reader.opaque(),
        rights: decode_rights(&reader.opaque()),
        admission_cert_hash: reader.opaque(),
    };
    reader.finish();
    incarnation
}

fn encode_incarnation(subject: &str, rights: &[(u8, u64)], cert_hash: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend(vl(subject.as_bytes()));
    out.extend(encode_rights(rights));
    out.extend(vl(cert_hash));
    out
}

fn ed25519_verifies(public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    RustCrypto::default()
        .verify_signature(SignatureScheme::ED25519, data, public_key, signature)
        .is_ok()
}

#[derive(Debug)]
struct TestFounder {
    apf_key_id: Vec<u8>,
    group: Vec<u8>,
    subject: Vec<u8>,
    rights: Vec<(u8, u64)>,
    signature_key: Vec<u8>,
}

/// C-9 founder certificate, decoded and signature-checked without `src/wire.rs`.
fn decode_founder(bytes: &[u8], apf_public: &[u8]) -> TestFounder {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.opaque(), T_FOUNDER_LABEL, "founder label");
    let founder = TestFounder {
        apf_key_id: reader.opaque(),
        group: reader.opaque(),
        subject: reader.opaque(),
        rights: decode_rights(&reader.opaque()),
        signature_key: reader.opaque(),
    };
    let tbs_len = bytes.len() - reader.rest.len();
    let signature = reader.opaque();
    reader.finish();
    assert!(
        ed25519_verifies(apf_public, &bytes[..tbs_len], &signature),
        "founder signature covers the TLS encoding of the TBS"
    );
    founder
}

#[derive(Debug, PartialEq, Eq)]
struct TestAdmission {
    version: u8,
    apf_key_id: Vec<u8>,
    group: Vec<u8>,
    subject: Vec<u8>,
    read_generation: u64,
    admit_generation: u64,
    policy_revision: u64,
    not_after: u64,
    key_package_preimage_hash: Vec<u8>,
}

/// §4.4 admission certificate v2, decoded and signature-checked without `src/wire.rs`.
fn decode_admission(bytes: &[u8], apf_public: &[u8]) -> TestAdmission {
    let mut reader = TlsReader::new(bytes);
    assert_eq!(reader.opaque(), T_ADMISSION_MAGIC, "admission magic");
    let admission = TestAdmission {
        version: reader.u8(),
        apf_key_id: reader.opaque(),
        group: reader.opaque(),
        subject: reader.opaque(),
        read_generation: reader.u64(),
        admit_generation: reader.u64(),
        policy_revision: reader.u64(),
        not_after: reader.u64(),
        key_package_preimage_hash: reader.opaque(),
    };
    let tbs_len = bytes.len() - reader.rest.len();
    let signature = reader.opaque();
    reader.finish();
    assert!(
        ed25519_verifies(apf_public, &bytes[..tbs_len], &signature),
        "admission signature covers the TLS encoding of the TBS"
    );
    admission
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

fn credential_identity(credential: &Credential) -> Vec<u8> {
    BasicCredential::try_from(credential.clone())
        .expect("basic credential")
        .identity()
        .to_vec()
}

fn parse_key_package(bytes: &[u8]) -> KeyPackage {
    KeyPackageIn::tls_deserialize_exact(bytes)
        .expect("KeyPackage decodes")
        .validate(&RustCrypto::default(), ProtocolVersion::Mls10)
        .expect("KeyPackage validates")
}

fn wire_format(bytes: &[u8]) -> WireFormat {
    MlsMessageIn::tls_deserialize_exact(bytes)
        .expect("MLS message decodes")
        .wire_format()
}

fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let last = out.len() - 1;
    out[last] ^= 0x01;
    out
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read directory")
        .map(|entry| {
            entry
                .expect("directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// Identities, providers and the test world
// ---------------------------------------------------------------------------

/// Deterministic client identity: the same name always yields the same key.
fn identity(name: &str) -> ClientIdentity {
    ClientIdentity::generate(&ScriptedRand::new(
        format!("admission-identity/{name}").as_bytes(),
    ))
    .expect("client identity")
}

fn client_provider(label: &str) -> Prov {
    TestProvider::new(ScriptedRand::new(
        format!("admission-provider/{label}").as_bytes(),
    ))
}

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
    clock: FixedClock,
    apf_public: Vec<u8>,
    founder_certificate: Vec<u8>,
    apf_anchor: Vec<u8>,
    seqs: HashMap<String, u64>,
    providers: u64,
}

/// Full genesis (§5.1): the root founds the group from the pending founder certificate
/// and `apf_anchor`; the adapter completes from the root's GroupInfo and tree.
fn genesis(tag: &str) -> (World, Client) {
    let dir = adapter_dir();
    let (provider, _) = scripted_provider(format!("admission-apf/{tag}").as_bytes());
    let clock = FixedClock::new(NOW);
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
            clock,
            apf_public,
            founder_certificate,
            apf_anchor,
            seqs: HashMap::new(),
            providers: 0,
        },
        root,
    )
}

fn submit_body(parent: &Frontier, commit: &[u8]) -> Value {
    json!({
        "command":"submit_commit", "kind":"admit", "parent_epoch":parent.epoch,
        "parent_branch":parent.branch, "commit":lower_hex(commit)
    })
}

fn certificate_body(preimage: &[u8]) -> Value {
    json!({"command":"admission_certificate", "key_package_preimage":lower_hex(preimage)})
}

impl World {
    fn provider(&mut self, name: &str) -> Prov {
        self.providers += 1;
        client_provider(&format!("{}/{}/{}", self.tag, name, self.providers))
    }

    /// Signs `body` as `actor` with `key` at the actor's next sequence and handles it.
    fn send_with(
        &mut self,
        actor: &str,
        key: &ClientIdentity,
        body: &Value,
    ) -> Result<Value, String> {
        let sequence = self.seqs.entry(actor.to_owned()).or_insert(0);
        *sequence += 1;
        let request = sign(key.signer(), GROUP, actor, *sequence, body);
        self.adapter.handle(&request)
    }

    fn send(&mut self, actor: &str, body: &Value) -> Result<Value, String> {
        self.send_with(actor, &identity(actor), body)
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

    fn delegate(&mut self, subject: &str, rights: &[&str]) {
        self.delegate_until(subject, rights, EXPIRES);
    }

    fn delegate_until(&mut self, subject: &str, rights: &[&str], expires_at: u64) {
        let body = json!({
            "command":"delegate", "subject":subject, "rights":rights, "resources":[GROUP],
            "expires_at":expires_at, "not_before":0, "depth":4,
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

    fn regrant(&mut self, subject: &str, right: &str, generation: u64) {
        self.ok(
            ROOT,
            &json!({"command":"grant", "subject":subject, "right":right,
                    "generation":generation, "fresh_keys":true}),
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

    fn generation(&mut self, subject: &str, right: &str) -> u64 {
        let checkpoint = self.checkpoint();
        checkpoint["grants"]
            .as_array()
            .expect("grants")
            .iter()
            .find(|g| g["subject"] == json!(subject) && g["right"] == json!(right))
            .and_then(|g| g["generation"].as_u64())
            .expect("grant generation")
    }

    fn prepare(&mut self, subject: &str) -> PreparedJoin<Prov> {
        let rights = self.rights_of(subject);
        self.prepare_with(subject, &rights)
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

    /// `admission_certificate` request signed by `actor` over `preimage`.
    fn certificate(&mut self, actor: &str, preimage: &[u8]) -> Result<Vec<u8>, String> {
        let response = self.send(actor, &certificate_body(preimage))?;
        Ok(hex::decode(
            response["certificate"]
                .as_str()
                .expect("certificate hex string"),
        )
        .expect("certificate is hex"))
    }

    /// Honest candidate: prepare at the current generations, certify, finalize.
    fn candidate(&mut self, subject: &str) -> JoinCandidate<Prov> {
        let prepared = self.prepare(subject);
        let preimage = prepared.preimage().to_vec();
        let certificate = self
            .certificate(subject, &preimage)
            .unwrap_or_else(|err| panic!("{subject} certificate: {err}"));
        prepared
            .finalize(&certificate)
            .expect("finalize KeyPackage")
    }

    fn submit(
        &mut self,
        actor: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<Admitted, String> {
        let response = self.send(actor, &submit_body(parent, commit))?;
        Ok(Admitted {
            frontier: Frontier {
                epoch: response["epoch"].as_u64().expect("response epoch"),
                branch: response["branch"]
                    .as_str()
                    .expect("response branch")
                    .to_owned(),
            },
            ack: hex::decode(response["ack"].as_str().expect("ack hex string")).expect("ack hex"),
        })
    }

    fn verify_ack(&self, ack: &[u8]) -> CanonicalAck {
        CanonicalAck::verify(ack, &self.apf_public, &RustCrypto::default())
            .expect("ack verifies under the APF key")
    }

    /// The APF signer, rebuilt from the test-only seed file in the temporary directory.
    /// Used only to forge structurally wrong but validly signed acks and certificates.
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
}

/// Asserts the error code, an unchanged kernel and adapter frontier, and exactly one
/// trace event whose outcome is that code.
fn rejected(w: &mut World, actor: &str, body: &Value, expected: &str) -> String {
    rejected_with(w, actor, &identity(actor), body, expected)
}

fn rejected_with(
    w: &mut World,
    actor: &str,
    key: &ClientIdentity,
    body: &Value,
    expected: &str,
) -> String {
    let before = w.checkpoint();
    let frontier = w.frontier();
    let trace_len = w.adapter.trace().len();
    let err = code(w.send_with(actor, key, body), expected);
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

/// Submits `staged` as `actor`, expects `expected`, then clears the committer's pending
/// commit and checks that the committer stayed at its parent frontier.
fn refused_commit(
    w: &mut World,
    actor: &str,
    committer: &mut Client,
    staged: &StagedAdd,
    expected: &str,
) -> String {
    let parent = committer.frontier().expect("committer frontier");
    assert_eq!(staged.parent, parent, "staged on the committer's frontier");
    let err = rejected(
        w,
        actor,
        &submit_body(&staged.parent, &staged.commit),
        expected,
    );
    committer.discard_pending().expect("discard pending commit");
    assert_eq!(committer.frontier().expect("frontier"), parent);
    assert_eq!(w.frontier(), parent);
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
    let admitted = w
        .submit(committer_name, &staged.parent, &staged.commit)
        .unwrap_or_else(|err| panic!("{committer_name} commit should be canonical, got {err}"));
    assert_eq!(admitted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.frontier(), admitted.frontier);
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
    assert_eq!(joined.subject(), subject);
    (joined, admitted)
}

fn leaf_capabilities() -> Capabilities {
    Capabilities::builder()
        .ciphersuites(vec![
            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        ])
        .credentials(vec![CredentialType::Basic])
        .extensions(vec![
            ExtensionType::Unknown(CERT_EXT),
            ExtensionType::Unknown(ANCHOR_EXT),
            ExtensionType::Unknown(INC_EXT),
        ])
        .build()
}

fn group_ciphersuite(client: &mut Client) -> Ciphersuite {
    let (group, _, _) = client.mls_parts_mut();
    group.ciphersuite()
}

/// A KeyPackage prepared directly with OpenMLS, outside `PreparedJoin`, so a test can
/// choose the credential, the signature key and the exact leaf `authz_incarnation`.
fn forged_prepared(
    ciphersuite: Ciphersuite,
    provider: &Prov,
    signer: &SignatureKeyPair,
    credential: &str,
    incarnation: Option<Vec<u8>>,
) -> PreparedKeyPackage {
    let mut builder = KeyPackage::builder().leaf_node_capabilities(leaf_capabilities());
    if let Some(bytes) = incarnation {
        builder = builder.leaf_node_extensions(
            Extensions::single(Extension::Unknown(INC_EXT, UnknownExtension(bytes)))
                .expect("leaf extension"),
        );
    }
    builder
        .prepare(
            ciphersuite,
            provider,
            signer,
            CredentialWithKey {
                credential: BasicCredential::new(credential.as_bytes().to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
            CERT_EXT,
        )
        .expect("prepare forged KeyPackage")
}

fn forged_finalize(
    prepared: PreparedKeyPackage,
    certificate: Vec<u8>,
    provider: &Prov,
    signer: &SignatureKeyPair,
) -> Vec<u8> {
    prepared
        .with_external_binding(certificate)
        .expect("embed certificate")
        .finalize(provider, signer)
        .expect("finalize forged KeyPackage")
        .key_package()
        .tls_serialize_detached()
        .expect("serialize KeyPackage")
}

/// A forged KeyPackage whose certificate is genuinely issued by the APF to `requester`
/// over the forged preimage.
#[allow(clippy::too_many_arguments)]
fn certified_forgery(
    w: &mut World,
    ciphersuite: Ciphersuite,
    requester: &str,
    signer: &ClientIdentity,
    credential: &str,
    incarnation: Option<Vec<u8>>,
) -> Vec<u8> {
    let provider = w.provider(credential);
    let prepared = forged_prepared(
        ciphersuite,
        &provider,
        signer.signer(),
        credential,
        incarnation,
    );
    let certificate = w
        .certificate(requester, prepared.canonical_binding_bytes())
        .unwrap_or_else(|err| panic!("APF certifies the presented preimage, got {err}"));
    forged_finalize(prepared, certificate, &provider, signer.signer())
}

/// Builds and stages, without merging, a commit with arbitrary proposals through the
/// raw OpenMLS group. Returns the commit `MlsMessage` bytes.
fn raw_commit(
    client: &mut Client,
    adds: Vec<KeyPackage>,
    extensions: Option<Extensions<GroupContext>>,
) -> Vec<u8> {
    let (group, provider, signer) = client.mls_parts_mut();
    let mut builder = group.commit_builder().propose_adds(adds);
    if let Some(extensions) = extensions {
        builder = builder
            .propose_group_context_extensions(extensions)
            .expect("propose GroupContextExtensions");
    }
    let bundle = builder
        .force_self_update(true)
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

/// The member's current GroupContext extensions with `apf_anchor` replaced by `anchor`.
fn extensions_with_anchor(
    client: &mut Client,
    anchor: Option<&TestAnchor>,
) -> Extensions<GroupContext> {
    let (group, _, _) = client.mls_parts_mut();
    let current = group.public_group().group_context().extensions().clone();
    let replaced: Vec<Extension> = current
        .iter()
        .map(|extension| match (extension, anchor) {
            (Extension::Unknown(t, _), Some(anchor)) if *t == ANCHOR_EXT => {
                Extension::Unknown(ANCHOR_EXT, UnknownExtension(encode_anchor(anchor)))
            }
            _ => extension.clone(),
        })
        .collect();
    Extensions::from_vec(replaced).expect("valid GroupContext extensions")
}

fn current_anchor(client: &mut Client) -> TestAnchor {
    let (group, _, _) = client.mls_parts_mut();
    let payloads = unknown_payloads(
        group.public_group().group_context().extensions().iter(),
        ANCHOR_EXT,
    );
    assert_eq!(payloads.len(), 1, "exactly one apf_anchor");
    decode_anchor(&payloads[0])
}

/// The leaf of the member whose credential identity is `subject`, as `viewer` sees it.
fn leaf_of(viewer: &mut Client, subject: &str) -> LeafNode {
    let (group, _, _) = viewer.mls_parts_mut();
    let index = group
        .members()
        .find(|member| credential_identity(&member.credential) == subject.as_bytes())
        .map(|member| member.index)
        .unwrap_or_else(|| panic!("{subject} is in the tree"));
    group.public_group().leaf(index).expect("leaf node").clone()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn genesis_kernel_branch_is_hash_of_real_group_context() {
    // Positive path.
    let dir = adapter_dir();
    let clock = FixedClock::new(NOW);
    let (provider, _) = scripted_provider(b"genesis-frontier/apf");
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
    assert!(
        dir_entries(dir.path()).is_empty(),
        "begin_genesis writes no file"
    );
    let apf_public = pending.apf_public_key().to_vec();
    assert_eq!(apf_public.len(), 32);
    let mut root = ClientEndpoint::found(
        GROUP,
        ROOT,
        &ROOT_RIGHTS,
        root_identity,
        client_provider("genesis-frontier/root"),
        pending.founder_certificate(),
        pending.apf_anchor(),
        &apf_public,
    )
    .expect("root founds the group");
    assert!(dir_entries(dir.path()).is_empty());
    let group_info = root.export_group_info().expect("GroupInfo");
    let ratchet_tree = root.export_ratchet_tree().expect("ratchet tree");
    let mut adapter = pending
        .complete(&group_info, &ratchet_tree)
        .expect("genesis completes");

    let names = dir_entries(dir.path());
    for file in [AUTHORITY_FILE, ADAPTER_FILE, APF_KEY_FILE, SEQUENCER_FILE] {
        assert!(names.iter().any(|n| n == file), "{file} in {names:?}");
    }
    let seed = std::fs::read(dir.path().join(APF_KEY_FILE)).expect("APF key file");
    assert_eq!(seed.len(), 32);
    assert_eq!(
        dalek_public(&seed),
        apf_public,
        "the APF key is the stored seed's"
    );
    assert_eq!(adapter.apf_public_key(), apf_public.as_slice());

    // The frontier, recomputed from the root's raw OpenMLS GroupContext.
    let (expected, parts) = {
        let (group, _, _) = root.mls_parts_mut();
        let context = group.public_group().group_context();
        assert_eq!(context.group_id().as_slice(), GROUP.as_bytes(), "group id");
        assert_eq!(context.epoch().as_u64(), 0);
        assert!(!context.tree_hash().is_empty());
        (
            context_frontier(context),
            (
                context.group_id().as_slice().to_vec(),
                context.tree_hash().to_vec(),
                context.confirmed_transcript_hash().to_vec(),
            ),
        )
    };
    assert_eq!(expected.epoch, 0);
    assert_eq!(expected.branch.len(), 64);
    assert!(expected
        .branch
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    assert_eq!(
        Frontier::compute(&parts.0, 0, &parts.1, &parts.2).expect("Frontier::compute"),
        expected,
        "wire encoding equals the independent FrontierInput"
    );

    let checkpoint = adapter.checkpoint().expect("checkpoint");
    assert_eq!(checkpoint["group"], json!(GROUP));
    assert_eq!(checkpoint["epoch"], json!(0));
    assert_eq!(checkpoint["branch"], json!(expected.branch));
    assert_ne!(checkpoint["branch"], json!("genesis"));
    assert_eq!(checkpoint["roster"], json!([ROOT]));
    assert_eq!(adapter.frontier().expect("adapter frontier"), expected);
    assert_eq!(root.frontier().expect("root frontier"), expected);

    // `Adapter::open` reloads the full adapter at the same frontier.
    drop(adapter);
    let (provider, _) = scripted_provider(b"genesis-frontier/reopen");
    let mut reopened =
        Adapter::open(dir.path(), provider, clock.clone()).expect("reopen full adapter");
    assert_eq!(reopened.frontier().expect("reopened frontier"), expected);
    assert_eq!(reopened.checkpoint().expect("checkpoint"), checkpoint);
    assert_eq!(reopened.apf_public_key(), apf_public.as_slice());
    drop(reopened);

    // `begin_genesis` refuses an existing adapter directory and changes nothing.
    let before = files_in(dir.path());
    let (provider, _) = scripted_provider(b"genesis-frontier/again");
    code(
        Adapter::begin_genesis(
            dir.path(),
            GROUP,
            ROOT,
            identity(ROOT).public_key(),
            provider,
            clock.clone(),
        ),
        "already_initialized",
    );
    assert_eq!(files_in(dir.path()), before);

    // `complete` with another group's state, or tampered state, fails and leaves nothing.
    /// Picks the GroupInfo and ratchet tree to complete with, from the new root.
    type Choose<'a> = &'a dyn Fn(&Client, &[u8]) -> (Vec<u8>, Vec<u8>);
    let attempt = |tag: &str, choose: Choose<'_>, anchor: &dyn Fn(&[u8]) -> Vec<u8>| {
        let dir = adapter_dir();
        let root_name = format!("root@{tag}");
        let root_identity = identity(&root_name);
        let (provider, _) = scripted_provider(format!("genesis-frontier/{tag}").as_bytes());
        let pending = Adapter::begin_genesis(
            dir.path(),
            GROUP,
            ROOT,
            root_identity.public_key(),
            provider,
            FixedClock::new(NOW),
        )
        .expect("begin_genesis");
        let apf = pending.apf_public_key().to_vec();
        let apf_anchor = anchor(pending.apf_anchor());
        let founded = ClientEndpoint::found(
            GROUP,
            ROOT,
            &ROOT_RIGHTS,
            root_identity,
            client_provider(&format!("genesis-frontier/{tag}/root")),
            pending.founder_certificate(),
            &apf_anchor,
            &apf,
        );
        if let Ok(other_root) = founded {
            let own_info = other_root.export_group_info().expect("GroupInfo");
            let (info, tree) = choose(&other_root, &own_info);
            let result = pending.complete(&info, &tree);
            assert!(result.is_err(), "{tag}: complete must fail");
        }
        assert!(
            dir_entries(dir.path()).is_empty(),
            "{tag}: a failed genesis leaves no file"
        );
    };
    let identity_anchor = |anchor: &[u8]| anchor.to_vec();
    // Another group's GroupInfo and tree (other APF key, other root key).
    attempt(
        "other-group",
        &|_, _| (group_info.clone(), ratchet_tree.clone()),
        &identity_anchor,
    );
    // The right GroupInfo with another group's ratchet tree.
    attempt(
        "other-tree",
        &|_, own_info| (own_info.to_vec(), ratchet_tree.clone()),
        &identity_anchor,
    );
    // Tampered GroupInfo signature.
    attempt(
        "tampered-info",
        &|root, own_info| {
            (
                flip_last(own_info),
                root.export_ratchet_tree().expect("tree"),
            )
        },
        &identity_anchor,
    );
    // Tampered ratchet tree.
    attempt(
        "tampered-tree",
        &|root, own_info| {
            let mut tree = root.export_ratchet_tree().expect("tree");
            let middle = tree.len() / 2;
            tree[middle] ^= 0x01;
            (own_info.to_vec(), tree)
        },
        &identity_anchor,
    );
    // A group created with an `apf_anchor` other than the pending one.
    attempt(
        "wrong-anchor",
        &|root, own_info| (own_info.to_vec(), root.export_ratchet_tree().expect("tree")),
        // R-11: no second well-formed anchor exists for this key and group, so the case
        // uses the pre-R-11 version-1 payload, which `found` already refuses.
        &|anchor: &[u8]| {
            let decoded = decode_anchor(anchor);
            let mut out = vec![1];
            out.extend(vl(&decoded.apf_key_id));
            out.extend(vl(&decoded.group));
            out.extend(tls_u64(7));
            out.extend(vl(&[0u8; 32]));
            out
        },
    );
}

#[test]
fn genesis_group_carries_apf_anchor_and_required_capabilities() {
    let (mut w, mut root) = genesis("gc-extensions");
    let checkpoint = w.checkpoint();
    let apf_key_id = w.apf_key_id();
    assert_eq!(w.adapter.apf_key_id(), apf_key_id);
    let root_key = identity(ROOT).public_key().to_vec();

    {
        let (group, _, signer) = root.mls_parts_mut();
        let context = group.public_group().group_context();

        // Exactly one apf_anchor, equal to the pending payload.
        let anchors = unknown_payloads(context.extensions().iter(), ANCHOR_EXT);
        assert_eq!(anchors.len(), 1, "exactly one apf_anchor");
        assert_eq!(anchors[0], w.apf_anchor);
        // R-11 (a): exactly `{version = 2, apf_key_id, group}`, with no policy.
        let anchor = decode_anchor(&anchors[0]);
        assert_eq!(anchor.version, 2);
        assert_eq!(
            anchor.apf_key_id, apf_key_id,
            "apf_key_id = SHA-256(APF key)"
        );
        assert_eq!(anchor.group, GROUP.as_bytes());
        assert_eq!(checkpoint["policy_revision"], json!(0));

        // Required capabilities.
        let required = context
            .required_capabilities()
            .expect("required capabilities")
            .extension_types();
        for extension_type in [CERT_EXT, ANCHOR_EXT, INC_EXT] {
            assert!(
                required.contains(&ExtensionType::Unknown(extension_type)),
                "required capabilities include {extension_type:#x}: {required:?}"
            );
        }

        // The root leaf carries one authz_incarnation bound to the founder certificate.
        let leaf = group.own_leaf_node().expect("root leaf");
        let incarnations = unknown_payloads(leaf.extensions().iter(), INC_EXT);
        assert_eq!(incarnations.len(), 1, "exactly one authz_incarnation");
        assert_eq!(
            decode_incarnation(&incarnations[0]),
            TestIncarnation {
                version: 1,
                subject: ROOT.as_bytes().to_vec(),
                rights: vec![(1, 0), (2, 0), (3, 0), (4, 0)],
                admission_cert_hash: sha256(&w.founder_certificate),
            }
        );
        for extension_type in [CERT_EXT, ANCHOR_EXT, INC_EXT] {
            assert!(leaf
                .capabilities()
                .extensions()
                .contains(&ExtensionType::Unknown(extension_type)));
        }
        assert_eq!(credential_identity(leaf.credential()), ROOT.as_bytes());
        assert_eq!(leaf.signature_key().as_slice(), root_key.as_slice());
        assert_eq!(signer.public(), root_key.as_slice());
    }

    // The founder certificate verifies under the APF key and binds the root's key.
    let founder = FounderCertificate::verify(
        &w.founder_certificate,
        &w.apf_public,
        &RustCrypto::default(),
    )
    .expect("founder certificate verifies");
    assert_eq!(founder.apf_key_id, apf_key_id);
    assert_eq!(founder.group, GROUP);
    assert_eq!(founder.subject, ROOT);
    assert_eq!(founder.rights, ROOT_RIGHTS.to_vec());
    assert_eq!(founder.signature_key, root_key);
    let independent = decode_founder(&w.founder_certificate, &w.apf_public);
    assert_eq!(independent.apf_key_id, apf_key_id);
    assert_eq!(independent.group, GROUP.as_bytes());
    assert_eq!(independent.subject, ROOT.as_bytes());
    assert_eq!(independent.rights, vec![(1, 0), (2, 0), (3, 0), (4, 0)]);
    assert_eq!(independent.signature_key, root_key);
    // Negative: another key, or a tampered certificate, does not verify.
    let stranger = DalekSigner::from_seed([0x5c; 32]);
    code(
        FounderCertificate::verify(
            &w.founder_certificate,
            &stranger.public_key(),
            &RustCrypto::default(),
        ),
        "unauthenticated",
    );
    code(
        FounderCertificate::verify(
            &flip_last(&w.founder_certificate),
            &w.apf_public,
            &RustCrypto::default(),
        ),
        "unauthenticated",
    );

    // Genesis refuses a root leaf that does not match the founder certificate. The
    // refusal may come from `found` or from `complete`; either way nothing is written.
    type Mutation = fn(&[u8]) -> Vec<u8>;
    type Case<'a> = (&'a str, &'a [(Right, u64)], &'a str, Mutation);
    let cases: [Case<'_>; 4] = [
        ("fewer-rights", &ROOT_RIGHTS[..2], ROOT, |c| c.to_vec()),
        (
            "raised-generation",
            &[
                (Right::Read, 1),
                (Right::Write, 0),
                (Right::Admin, 0),
                (Right::Admit, 0),
            ],
            ROOT,
            |c| c.to_vec(),
        ),
        ("garbage-founder", &ROOT_RIGHTS, ROOT, |_| {
            b"not a founder certificate".to_vec()
        }),
        ("other-signature-key", &ROOT_RIGHTS, "root@impostor", |c| {
            c.to_vec()
        }),
    ];
    for (tag, rights, key_name, founder_bytes) in cases {
        let dir = adapter_dir();
        let (provider, _) = scripted_provider(format!("gc-extensions/{tag}").as_bytes());
        let pending = Adapter::begin_genesis(
            dir.path(),
            GROUP,
            ROOT,
            identity(ROOT).public_key(),
            provider,
            FixedClock::new(NOW),
        )
        .expect("begin_genesis");
        let apf = pending.apf_public_key().to_vec();
        let founded = ClientEndpoint::found(
            GROUP,
            ROOT,
            rights,
            identity(key_name),
            client_provider(&format!("gc-extensions/{tag}/root")),
            &founder_bytes(pending.founder_certificate()),
            pending.apf_anchor(),
            &apf,
        );
        if let Ok(bad_root) = founded {
            let info = bad_root.export_group_info().expect("GroupInfo");
            let tree = bad_root.export_ratchet_tree().expect("tree");
            assert!(
                pending.complete(&info, &tree).is_err(),
                "{tag}: complete must fail"
            );
        }
        assert!(dir_entries(dir.path()).is_empty(), "{tag}: nothing written");
    }
}

#[test]
fn admission_certificate_requires_active_read_and_admit_at_current_generations() {
    let (mut w, _root) = genesis("certificate");
    w.delegate("bob", &["read", "write", "admit"]);
    // Move bob's admit to generation 1 so the certificate must report real generations.
    w.revoke("bob", "admit");
    w.regrant("bob", "admit", 1);
    // A direct root-anchored subject has no delegation expiry.
    w.ok(
        ROOT,
        &json!({"command":"grant", "subject":"frank", "right":"read", "generation":0,
                "fresh_keys":true, "subject_key":lower_hex(identity("frank").public_key())}),
    );
    w.regrant("frank", "admit", 0);

    // Positive: bob's certificate.
    let prepared = w.prepare("bob");
    let preimage = prepared.preimage().to_vec();
    assert!(!preimage.is_empty());
    let before = w.checkpoint();
    let frontier = w.frontier();
    let certificate = w.certificate("bob", &preimage).expect("bob is certified");
    assert_eq!(
        w.checkpoint(),
        before,
        "issuing a certificate is not admission: the kernel is unchanged"
    );
    assert_eq!(w.frontier(), frontier);
    let issued = AdmissionCertificate::verify(&certificate, &w.apf_public, &RustCrypto::default())
        .expect("certificate verifies under the APF key");
    let policy_revision = before["policy_revision"].as_u64().expect("policy revision");
    assert_eq!(
        issued,
        AdmissionCertificate {
            apf_key_id: w.apf_key_id(),
            group: GROUP.into(),
            subject: "bob".into(),
            read_generation: 0,
            admit_generation: 1,
            policy_revision,
            not_after: EXPIRES,
            key_package_preimage_hash: sha256(&preimage),
        }
    );
    assert_eq!(w.generation("bob", "read"), 0);
    assert_eq!(w.generation("bob", "admit"), 1);
    assert_eq!(
        decode_admission(&certificate, &w.apf_public),
        TestAdmission {
            version: 2,
            apf_key_id: w.apf_key_id(),
            group: GROUP.as_bytes().to_vec(),
            subject: b"bob".to_vec(),
            read_generation: 0,
            admit_generation: 1,
            policy_revision,
            not_after: EXPIRES,
            key_package_preimage_hash: sha256(&preimage),
        }
    );
    code(
        AdmissionCertificate::verify(
            &certificate,
            &DalekSigner::from_seed([0x5d; 32]).public_key(),
            &RustCrypto::default(),
        ),
        "unauthenticated",
    );

    // The finalized KeyPackage embeds exactly that certificate over that preimage, and
    // its leaf carries bob's incarnation with the zero placeholder.
    let candidate = prepared.finalize(&certificate).expect("finalize");
    let key_package = parse_key_package(candidate.key_package());
    assert_eq!(
        unknown_payloads(key_package.extensions().iter(), CERT_EXT),
        vec![certificate.clone()]
    );
    assert_eq!(
        key_package
            .canonical_binding_bytes(CERT_EXT)
            .expect("canonical binding bytes"),
        preimage
    );
    let leaf = key_package.leaf_node();
    assert_eq!(credential_identity(leaf.credential()), b"bob");
    assert_eq!(
        leaf.signature_key().as_slice(),
        identity("bob").public_key()
    );
    let incarnations = unknown_payloads(leaf.extensions().iter(), INC_EXT);
    assert_eq!(incarnations.len(), 1);
    assert_eq!(
        decode_incarnation(&incarnations[0]),
        TestIncarnation {
            version: 1,
            subject: b"bob".to_vec(),
            rights: vec![(1, 0), (2, 0), (4, 1)],
            admission_cert_hash: ZERO_HASH.to_vec(),
        }
    );

    // Positive: a subject without a delegation record gets not_after = u64::MAX.
    let frank = w.prepare("frank");
    let frank_certificate = w.certificate("frank", frank.preimage()).expect("frank");
    let frank_issued =
        AdmissionCertificate::verify(&frank_certificate, &w.apf_public, &RustCrypto::default())
            .expect("frank's certificate verifies");
    assert_eq!(frank_issued.subject, "frank");
    assert_eq!(frank_issued.not_after, u64::MAX);
    assert_eq!(
        frank_issued.key_package_preimage_hash,
        sha256(frank.preimage())
    );

    // Negatives. A subject without `admit`.
    w.delegate("dave", &["read", "write"]);
    let dave = w.prepare("dave");
    rejected(
        &mut w,
        "dave",
        &certificate_body(dave.preimage()),
        "unauthorized",
    );
    // A subject whose `read` was revoked.
    w.delegate("erin", &["read", "write", "admit"]);
    let erin = w.prepare("erin");
    let erin_preimage = erin.preimage().to_vec();
    w.certificate("erin", &erin_preimage)
        .expect("erin is certified before the revoke");
    w.revoke("erin", "read");
    rejected(
        &mut w,
        "erin",
        &certificate_body(&erin_preimage),
        "unauthorized",
    );
    // A subject whose delegation has expired at the trusted `now`.
    w.delegate_until("gail", &["read", "admit"], NOW + 10);
    let gail = w.prepare("gail");
    let gail_preimage = gail.preimage().to_vec();
    w.clock.set(NOW + 11);
    rejected(
        &mut w,
        "gail",
        &certificate_body(&gail_preimage),
        "unauthorized",
    );
    w.clock.set(NOW);
    w.certificate("gail", &gail_preimage)
        .expect("gail is certified again inside her validity");
    // An unregistered actor.
    rejected_with(
        &mut w,
        "mallory",
        &identity("mallory"),
        &certificate_body(&preimage),
        "unauthenticated",
    );
    // A registered actor signing with another subject's key.
    rejected_with(
        &mut w,
        "bob",
        &identity("dave"),
        &certificate_body(&preimage),
        "unauthenticated",
    );
    drop(candidate);

    // A policy-only adapter from `Adapter::create` has no group.
    let policy_dir = adapter_dir();
    let (provider, _) = scripted_provider(b"certificate/policy-only");
    let mut policy = Adapter::create(
        policy_dir.path(),
        GROUP,
        ROOT,
        identity(ROOT).public_key(),
        provider,
        FixedClock::new(NOW),
    )
    .expect("policy-only adapter");
    let root_key = identity(ROOT);
    // Positive path on that adapter: a routed kernel command works.
    policy
        .handle(&sign(
            root_key.signer(),
            GROUP,
            ROOT,
            1,
            &json!({"command":"allocate", "op":"op-1"}),
        ))
        .expect("allocate on the policy-only adapter");
    let policy_before = policy.checkpoint().expect("checkpoint");
    code(
        policy.handle(&sign(
            root_key.signer(),
            GROUP,
            ROOT,
            2,
            &certificate_body(&preimage),
        )),
        "uninitialized",
    );
    code(
        policy.handle(&sign(
            root_key.signer(),
            GROUP,
            ROOT,
            3,
            &submit_body(&frontier, b"\x00\x01"),
        )),
        "uninitialized",
    );
    assert_eq!(policy.checkpoint().expect("checkpoint"), policy_before);
    let trace = policy.trace();
    assert_eq!(trace.len(), 3, "{trace:?}");
    assert_eq!(trace[1]["outcome"], json!("uninitialized"));
    assert_eq!(trace[2]["outcome"], json!("uninitialized"));
}

#[test]
fn admitted_frontier_matches_kernel_branch_at_every_member() {
    let (mut w, mut root) = genesis("frontier");
    w.delegate("bob", &["read", "write", "admin", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    let genesis_frontier = w.frontier();

    // Bob is admitted by the root.
    let bob_candidate = w.candidate("bob");
    let bob_staged = root
        .stage_add(bob_candidate.key_package())
        .expect("root stages bob");
    assert_eq!(wire_format(&bob_staged.commit), WireFormat::PublicMessage);
    assert_eq!(root.frontier().expect("root frontier"), genesis_frontier);
    let bob_admitted = canonical(&mut w, ROOT, &mut root, &bob_staged, &mut []);
    let mut bob = bob_candidate
        .join(&bob_staged.welcome, &bob_admitted.ack)
        .expect("bob joins");
    let ack = w.verify_ack(&bob_admitted.ack);
    assert_eq!(ack.apf_key_id, w.apf_key_id());
    assert_eq!(ack.group, GROUP);
    assert_eq!(ack.parent, genesis_frontier);
    assert_eq!(ack.successor, bob_admitted.frontier);
    assert_eq!(ack.commit_hash, sha256(&bob_staged.commit));
    assert_eq!(ack.kind, AckKind::Admit);
    // R-11 (c): the ack carries the kernel policy at the canonical step.
    let checkpoint = w.checkpoint();
    assert_eq!(json!(ack.policy_revision), checkpoint["policy_revision"]);
    assert_eq!(
        json!(lower_hex(&ack.policy_digest)),
        checkpoint["policy_digest"]
    );

    // Carol is admitted through a commit staged by bob, an admin member other than
    // the founder; the root merges it as a receiver.
    let carol_candidate = w.candidate("carol");
    let carol_staged = bob
        .stage_add(carol_candidate.key_package())
        .expect("bob stages carol");
    assert_eq!(wire_format(&carol_staged.commit), WireFormat::PublicMessage);
    let carol_admitted = canonical(&mut w, "bob", &mut bob, &carol_staged, &mut [&mut root]);
    let mut carol = carol_candidate
        .join(&carol_staged.welcome, &carol_admitted.ack)
        .expect("carol joins");
    let ack = w.verify_ack(&carol_admitted.ack);
    assert_eq!(ack.parent, bob_admitted.frontier);
    assert_eq!(ack.successor, carol_admitted.frontier);
    assert_eq!(ack.commit_hash, sha256(&carol_staged.commit));
    assert_eq!(ack.kind, AckKind::Admit);

    let frontier = w.frontier();
    assert_eq!(frontier.epoch, 2);
    let checkpoint = w.checkpoint();
    assert_eq!(checkpoint["epoch"], json!(2));
    assert_eq!(checkpoint["branch"], json!(frontier.branch));
    assert_eq!(checkpoint["roster"], json!([ROOT, "bob", "carol"]));
    assert_eq!(frontier, carol_admitted.frontier);
    for (name, client) in [
        ("root", &mut root),
        ("bob", &mut bob),
        ("carol", &mut carol),
    ] {
        assert_eq!(client.frontier().expect("frontier"), frontier, "{name}");
        assert_eq!(raw_frontier(client), frontier, "{name} raw GroupContext");
    }
    assert_ne!(bob_admitted.frontier.branch, genesis_frontier.branch);
    assert_ne!(carol_admitted.frontier.branch, bob_admitted.frontier.branch);

    // Every member sees the joiners' leaves with their incarnations and zero placeholder.
    for (subject, rights) in [
        ("bob", vec![(1, 0), (2, 0), (3, 0), (4, 0)]),
        ("carol", vec![(1, 0), (2, 0), (4, 0)]),
    ] {
        for viewer in [&mut root, &mut bob, &mut carol] {
            let leaf = leaf_of(viewer, subject);
            assert_eq!(
                leaf.signature_key().as_slice(),
                identity(subject).public_key()
            );
            let incarnations = unknown_payloads(leaf.extensions().iter(), INC_EXT);
            assert_eq!(incarnations.len(), 1);
            assert_eq!(
                decode_incarnation(&incarnations[0]),
                TestIncarnation {
                    version: 1,
                    subject: subject.as_bytes().to_vec(),
                    rights: rights.clone(),
                    admission_cert_hash: ZERO_HASH.to_vec(),
                }
            );
        }
    }
    // The apf_anchor is unchanged by admission.
    assert_eq!(current_anchor(&mut carol), decode_anchor(&w.apf_anchor));

    // A reopened adapter keeps the admitted frontier.
    let World { dir, adapter, .. } = w;
    drop(adapter);
    let (provider, _) = scripted_provider(b"frontier/reopen");
    let mut reopened = Adapter::open(dir.path(), provider, FixedClock::new(NOW)).expect("reopen");
    assert_eq!(reopened.frontier().expect("frontier"), frontier);
}

#[test]
fn add_commit_without_valid_v2_certificate_is_noncanonical() {
    let (mut w, mut root) = genesis("no-certificate");
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    w.delegate("dave", &["read", "write", "admit"]);
    let ciphersuite = group_ciphersuite(&mut root);

    // Positive path: bob is admitted.
    let (mut bob, _) = admit(&mut w, ROOT, &mut root, "bob", &mut []);
    let parent = w.frontier();
    let carol_rights = codes(&w.rights_of("carol"));
    let carol_identity = identity("carol");

    let refuse = |w: &mut World, root: &mut Client, key_package: &[u8], case: &str| {
        let staged = root
            .stage_add(key_package)
            .unwrap_or_else(|err| panic!("{case}: root stages the add, got {err}"));
        let err = refused_commit(w, ROOT, root, &staged, "noncanonical_commit");
        assert_eq!(w.frontier(), parent, "{case}: {err}");
        assert_eq!(bob.frontier().expect("bob frontier"), parent);
    };

    // No certificate at all.
    let provider = w.provider("carol");
    let bundle = KeyPackage::builder()
        .leaf_node_capabilities(leaf_capabilities())
        .leaf_node_extensions(
            Extensions::single(Extension::Unknown(
                INC_EXT,
                UnknownExtension(encode_incarnation("carol", &carol_rights, &ZERO_HASH)),
            ))
            .expect("leaf extension"),
        )
        .build(
            ciphersuite,
            &provider,
            carol_identity.signer(),
            CredentialWithKey {
                credential: BasicCredential::new(b"carol".to_vec()).into(),
                signature_key: carol_identity.signer().to_public_vec().into(),
            },
        )
        .expect("KeyPackage without certificate");
    let no_certificate = bundle
        .key_package()
        .tls_serialize_detached()
        .expect("serialize");
    refuse(&mut w, &mut root, &no_certificate, "no certificate");

    // Garbage certificate bytes.
    let garbage = w
        .prepare("carol")
        .finalize(b"not an admission certificate")
        .expect("finalize accepts any bytes");
    refuse(
        &mut w,
        &mut root,
        garbage.key_package(),
        "garbage certificate",
    );

    // A correct certificate re-signed by another key, and one with a flipped signature.
    let stranger = DalekSigner::from_seed([0x6e; 32]);
    let prepared = w.prepare("carol");
    let genuine = w
        .certificate("carol", prepared.preimage())
        .expect("carol certificate");
    let fields = AdmissionCertificate::verify(&genuine, &w.apf_public, &RustCrypto::default())
        .expect("genuine certificate verifies");
    let resigned = fields.sign(&stranger).expect("stranger signs");
    let other_key = prepared.finalize(&resigned).expect("finalize");
    refuse(
        &mut w,
        &mut root,
        other_key.key_package(),
        "certificate by another key",
    );
    let prepared = w.prepare("carol");
    let genuine = w
        .certificate("carol", prepared.preimage())
        .expect("carol certificate");
    let flipped = prepared.finalize(&flip_last(&genuine)).expect("finalize");
    refuse(
        &mut w,
        &mut root,
        flipped.key_package(),
        "flipped signature",
    );

    // A genuine certificate for another subject: dave certifies carol's preimage.
    let prepared = w.prepare("carol");
    let for_dave = w
        .certificate("dave", prepared.preimage())
        .expect("dave certificate");
    assert_eq!(
        AdmissionCertificate::verify(&for_dave, &w.apf_public, &RustCrypto::default())
            .expect("verifies")
            .subject,
        "dave"
    );
    let other_subject = prepared.finalize(&for_dave).expect("finalize");
    refuse(
        &mut w,
        &mut root,
        other_subject.key_package(),
        "another subject",
    );

    // A genuine certificate for carol over a different preimage.
    let first = w.prepare("carol");
    let second = w.prepare("carol");
    assert_ne!(first.preimage(), second.preimage());
    let for_second = w
        .certificate("carol", second.preimage())
        .expect("carol certificate");
    let other_preimage = first.finalize(&for_second).expect("finalize");
    refuse(
        &mut w,
        &mut root,
        other_preimage.key_package(),
        "different preimage",
    );
    drop(second);

    // A valid admission afterwards succeeds.
    let (_carol, admitted) = admit(&mut w, ROOT, &mut root, "carol", &mut [&mut bob]);
    assert_eq!(admitted.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob", "carol"]));
}

#[test]
fn add_commit_with_stale_generation_certificate_is_noncanonical() {
    let (mut w, mut root) = genesis("stale-generation");
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    w.delegate_until("dave", &["read", "write", "admit"], NOW + 100);

    // Positive path: carol is admitted at generation 0.
    let (mut carol, _) = admit(&mut w, ROOT, &mut root, "carol", &mut []);

    // Bob is certified at generation 0 ...
    let stale = w.candidate("bob");
    let stale_certificate = unknown_payloads(
        parse_key_package(stale.key_package()).extensions().iter(),
        CERT_EXT,
    );
    assert_eq!(stale_certificate.len(), 1);
    let issued =
        AdmissionCertificate::verify(&stale_certificate[0], &w.apf_public, &RustCrypto::default())
            .expect("generation-0 certificate");
    assert_eq!(issued.read_generation, 0);
    // ... then his read is revoked and re-granted with fresh keys at generation 1.
    w.revoke("bob", "read");
    w.regrant("bob", "read", 1);
    assert_eq!(w.generation("bob", "read"), 1);
    assert_eq!(
        w.checkpoint()["read_fenced"],
        json!(false),
        "bob is no roster reader yet, so the revoke does not fence"
    );
    let staged = root
        .stage_add(stale.key_package())
        .expect("stage stale add");
    refused_commit(&mut w, ROOT, &mut root, &staged, "noncanonical_commit");
    assert_eq!(carol.frontier().expect("carol"), w.frontier());

    // A KeyPackage claiming the new generation cannot reuse the old certificate.
    let relabeled = w
        .prepare("bob")
        .finalize(&stale_certificate[0])
        .expect("finalize");
    let staged = root.stage_add(relabeled.key_package()).expect("stage");
    refused_commit(&mut w, ROOT, &mut root, &staged, "noncanonical_commit");

    // A certificate that has outlived its delegation at the trusted `now`.
    let expiring = w.candidate("dave");
    let issued = AdmissionCertificate::verify(
        &unknown_payloads(
            parse_key_package(expiring.key_package())
                .extensions()
                .iter(),
            CERT_EXT,
        )[0],
        &w.apf_public,
        &RustCrypto::default(),
    )
    .expect("dave certificate");
    assert_eq!(issued.not_after, NOW + 100);
    w.clock.set(NOW + 101);
    let staged = root.stage_add(expiring.key_package()).expect("stage");
    refused_commit(&mut w, ROOT, &mut root, &staged, "noncanonical_commit");
    w.clock.set(NOW);

    // A fresh KeyPackage whose incarnation carries the new generations is admitted.
    assert_eq!(
        w.rights_of("bob"),
        vec![(Right::Read, 1), (Right::Write, 0), (Right::Admit, 0)]
    );
    let fresh = w.candidate("bob");
    let issued = AdmissionCertificate::verify(
        &unknown_payloads(
            parse_key_package(fresh.key_package()).extensions().iter(),
            CERT_EXT,
        )[0],
        &w.apf_public,
        &RustCrypto::default(),
    )
    .expect("fresh certificate");
    assert_eq!(issued.read_generation, 1);
    assert_eq!(issued.admit_generation, 0);
    let staged = root
        .stage_add(fresh.key_package())
        .expect("stage fresh add");
    let admitted = canonical(&mut w, ROOT, &mut root, &staged, &mut [&mut carol]);
    let mut bob = fresh
        .join(&staged.welcome, &admitted.ack)
        .expect("bob joins");
    assert_eq!(bob.frontier().expect("bob"), w.frontier());
    let leaf = leaf_of(&mut root, "bob");
    assert_eq!(
        decode_incarnation(&unknown_payloads(leaf.extensions().iter(), INC_EXT)[0]).rights,
        vec![(1, 1), (2, 0), (4, 0)]
    );
    assert_eq!(raw_frontier(&mut bob), w.frontier());
}

#[test]
fn add_commit_from_non_admin_sender_is_noncanonical() {
    let (mut w, mut root) = genesis("non-admin");
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    w.delegate("dave", &["read", "admit"]);

    // Positive path: the root admits bob.
    let (mut bob, _) = admit(&mut w, ROOT, &mut root, "bob", &mut []);
    let parent = w.frontier();

    // Bob, without `admin`, stages a valid Add for carol: the kernel refuses it.
    let carol = w.candidate("carol");
    let by_bob = bob.stage_add(carol.key_package()).expect("bob stages");
    refused_commit(&mut w, "bob", &mut bob, &by_bob, "unauthorized");

    // The root's commit submitted by an actor other than its MLS sender.
    let by_root = root.stage_add(carol.key_package()).expect("root stages");
    rejected(
        &mut w,
        "bob",
        &submit_body(&by_root.parent, &by_root.commit),
        "noncanonical_commit",
    );
    rejected(
        &mut w,
        "dave",
        &submit_body(&by_root.parent, &by_root.commit),
        "noncanonical_commit",
    );
    assert_eq!(w.frontier(), parent);
    assert_eq!(bob.frontier().expect("bob"), parent);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob"]));

    // The root's own submission then succeeds.
    let admitted = canonical(&mut w, ROOT, &mut root, &by_root, &mut [&mut bob]);
    let carol = carol
        .join(&by_root.welcome, &admitted.ack)
        .expect("carol joins");
    assert_eq!(carol.frontier().expect("carol"), w.frontier());
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob", "carol"]));
}

#[test]
fn commit_with_unexpected_extra_proposal_is_noncanonical() {
    let (mut w, mut root) = genesis("extra-proposal");
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    w.delegate("dave", &["read", "write", "admit"]);

    // Positive path: bob is admitted.
    let (mut bob, _) = admit(&mut w, ROOT, &mut root, "bob", &mut []);
    let parent = w.frontier();
    let carol = w.candidate("carol");
    let dave = w.candidate("dave");
    let carol_kp = parse_key_package(carol.key_package());
    let dave_kp = parse_key_package(dave.key_package());
    let anchor = current_anchor(&mut root);
    let mut raised = anchor.clone();
    raised.apf_key_id = sha256(b"another APF key");
    let changed = extensions_with_anchor(&mut root, Some(&raised));
    let same = extensions_with_anchor(&mut root, None);

    type Case<'a> = (&'a str, Vec<KeyPackage>, Option<Extensions<GroupContext>>);
    let cases: Vec<Case<'_>> = vec![
        (
            "add plus apf_anchor change",
            vec![carol_kp.clone()],
            Some(changed.clone()),
        ),
        ("two adds", vec![carol_kp.clone(), dave_kp], None),
        ("apf_anchor change alone", vec![], Some(changed)),
        ("add plus unchanged extensions", vec![carol_kp], Some(same)),
    ];
    for (case, adds, extensions) in cases {
        let commit = raw_commit(&mut root, adds, extensions);
        assert_eq!(wire_format(&commit), WireFormat::PublicMessage);
        let err = rejected(
            &mut w,
            ROOT,
            &submit_body(&parent, &commit),
            "noncanonical_commit",
        );
        root.discard_pending().expect("discard pending");
        assert_eq!(root.frontier().expect("root"), parent, "{case}: {err}");
        assert_eq!(raw_frontier(&mut root), parent, "{case}");
        assert_eq!(current_anchor(&mut root), anchor, "{case}");
    }
    assert_eq!(w.frontier(), parent);

    // The honest single Add then succeeds.
    let staged = root.stage_add(carol.key_package()).expect("stage");
    let admitted = canonical(&mut w, ROOT, &mut root, &staged, &mut [&mut bob]);
    let mut carol = carol
        .join(&staged.welcome, &admitted.ack)
        .expect("carol joins");
    assert_eq!(current_anchor(&mut carol), anchor);
    assert_eq!(carol.frontier().expect("carol"), w.frontier());
}

#[test]
fn sibling_commits_on_one_parent_have_exactly_one_canonical_winner() {
    let (mut w, mut root) = genesis("siblings");
    w.delegate("carol", &["read", "write", "admin", "admit"]);
    w.delegate("dave", &["read", "write", "admit"]);
    w.delegate("erin", &["read", "write", "admit"]);

    // Positive path: carol, an admin, is admitted.
    let (mut carol, _) = admit(&mut w, ROOT, &mut root, "carol", &mut []);
    let parent = w.frontier();

    // Two admins stage Adds on the same parent.
    let dave = w.candidate("dave");
    let erin = w.candidate("erin");
    let root_staged = root
        .stage_add(dave.key_package())
        .expect("root stages dave");
    let carol_staged = carol
        .stage_add(erin.key_package())
        .expect("carol stages erin");
    assert_eq!(root_staged.parent, parent);
    assert_eq!(carol_staged.parent, parent);
    assert_ne!(root_staged.commit, carol_staged.commit);

    // The first submission wins.
    let winner = w
        .submit(ROOT, &root_staged.parent, &root_staged.commit)
        .expect("first sibling is canonical");
    assert_eq!(winner.frontier.epoch, parent.epoch + 1);
    assert_eq!(w.frontier(), winner.frontier);
    // The second sibling's parent is no longer current.
    rejected(
        &mut w,
        "carol",
        &submit_body(&carol_staged.parent, &carol_staged.commit),
        "stale_frontier",
    );
    // The winner cannot be sequenced twice either.
    rejected(
        &mut w,
        ROOT,
        &submit_body(&root_staged.parent, &root_staged.commit),
        "stale_frontier",
    );
    assert_eq!(w.frontier(), winner.frontier);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "carol", "dave"]));

    // The loser discards its pending commit and merges the winner.
    carol.discard_pending().expect("carol discards");
    assert_eq!(carol.frontier().expect("carol"), parent);
    assert_eq!(
        root.apply_ack(&root_staged.commit, &winner.ack)
            .expect("root merges"),
        winner.frontier
    );
    assert_eq!(
        carol
            .apply_ack(&root_staged.commit, &winner.ack)
            .expect("carol merges the winner"),
        winner.frontier
    );
    let mut dave = dave
        .join(&root_staged.welcome, &winner.ack)
        .expect("dave joins");
    let next = w.frontier();
    for client in [&mut root, &mut carol, &mut dave] {
        assert_eq!(client.frontier().expect("frontier"), next);
        assert_eq!(raw_frontier(client), next);
    }

    // The loser re-stages on the new parent and wins there.
    let restaged = carol
        .stage_add(erin.key_package())
        .expect("carol re-stages");
    assert_eq!(restaged.parent, next);
    let admitted = canonical(
        &mut w,
        "carol",
        &mut carol,
        &restaged,
        &mut [&mut root, &mut dave],
    );
    let erin = erin
        .join(&restaged.welcome, &admitted.ack)
        .expect("erin joins");
    assert_eq!(erin.frontier().expect("erin"), w.frontier());
    assert_eq!(w.frontier().epoch, parent.epoch + 2);
}

#[test]
fn client_refuses_commit_without_matching_canonical_ack() {
    let (mut w, mut root) = genesis("client-ack");
    w.delegate("bob", &["read", "write", "admit"]);
    w.delegate("carol", &["read", "write", "admit"]);
    let apf = w.apf_signer();

    // Positive path: bob is admitted.
    let genesis_frontier = w.frontier();
    let (mut bob, bob_admitted) = admit(&mut w, ROOT, &mut root, "bob", &mut []);
    let parent = w.frontier();
    assert_ne!(genesis_frontier, parent);

    // The root's Add for carol becomes canonical; the committer merges it.
    let carol = w.candidate("carol");
    let staged = root.stage_add(carol.key_package()).expect("stage carol");
    let admitted = w
        .submit(ROOT, &staged.parent, &staged.commit)
        .expect("canonical");
    assert_eq!(
        root.apply_ack(&staged.commit, &admitted.ack)
            .expect("root merges"),
        admitted.frontier
    );
    let good = w.verify_ack(&admitted.ack);
    assert_eq!(good.parent, parent);
    // R-11: a client stores the ack it merged under; a joiner the ack it joined under.
    assert_eq!(root.last_ack(), Some(&good), "the committer stores its ack");
    let joined = w.verify_ack(&bob_admitted.ack);
    assert_eq!(bob.last_ack(), Some(&joined), "the joiner stores its ack");
    assert!(joined.policy_revision > 0, "delegations raised the policy");
    assert!(good.policy_revision >= joined.policy_revision);
    let below = joined.policy_revision - 1;

    let forge = |change: &dyn Fn(&mut CanonicalAck)| {
        let mut ack = good.clone();
        change(&mut ack);
        ack.sign(&apf).expect("forge APF-signed ack")
    };
    let other_branch = lower_hex(&sha256(b"not the successor"));
    let cases: Vec<(&str, Vec<u8>, Vec<u8>, &str)> = vec![
        (
            "bad signature",
            staged.commit.clone(),
            flip_last(&admitted.ack),
            "unauthenticated",
        ),
        (
            "ack signed by another key",
            staged.commit.clone(),
            good.sign(&DalekSigner::from_seed([0x7f; 32]))
                .expect("sign"),
            "unauthenticated",
        ),
        (
            "ack for a different commit",
            staged.commit.clone(),
            bob_admitted.ack.clone(),
            "binding_mismatch",
        ),
        (
            "commit hash of other bytes",
            staged.commit.clone(),
            forge(&|ack| ack.commit_hash = sha256(b"another commit")),
            "binding_mismatch",
        ),
        (
            "other commit bytes under the right ack",
            flip_last(&staged.commit),
            admitted.ack.clone(),
            "binding_mismatch",
        ),
        (
            "wrong successor branch",
            staged.commit.clone(),
            forge(&|ack| ack.successor.branch = other_branch.clone()),
            "binding_mismatch",
        ),
        (
            "wrong successor epoch",
            staged.commit.clone(),
            forge(&|ack| ack.successor.epoch += 1),
            "binding_mismatch",
        ),
        (
            "parent is not the client's frontier",
            staged.commit.clone(),
            forge(&|ack| ack.parent = genesis_frontier.clone()),
            "binding_mismatch",
        ),
        (
            "parent branch differs",
            staged.commit.clone(),
            forge(&|ack| ack.parent.branch = other_branch.clone()),
            "binding_mismatch",
        ),
        (
            "policy revision below the stored ack's (R-11)",
            staged.commit.clone(),
            forge(&|ack| ack.policy_revision = below),
            "binding_mismatch",
        ),
    ];
    for (case, commit, ack, expected) in cases {
        let err = code(bob.apply_ack(&commit, &ack), expected);
        assert_eq!(
            bob.last_ack(),
            Some(&joined),
            "{case}: stored ack unchanged"
        );
        assert_eq!(bob.frontier().expect("bob"), parent, "{case}: {err}");
        assert_eq!(
            raw_frontier(&mut bob),
            parent,
            "{case}: raw state unchanged"
        );
    }

    // The correct ack then merges.
    assert_eq!(
        bob.apply_ack(&staged.commit, &admitted.ack)
            .expect("bob merges under the right ack"),
        admitted.frontier
    );
    assert_eq!(bob.frontier().expect("bob"), w.frontier());
    assert_eq!(raw_frontier(&mut bob), w.frontier());
    assert_eq!(bob.last_ack(), Some(&good));
    // Replaying the merged commit is refused: its parent is no longer bob's frontier.
    code(
        bob.apply_ack(&staged.commit, &admitted.ack),
        "binding_mismatch",
    );
    assert_eq!(bob.frontier().expect("bob"), w.frontier());
    let carol = carol
        .join(&staged.welcome, &admitted.ack)
        .expect("carol joins");
    assert_eq!(carol.frontier().expect("carol"), w.frontier());
}

#[test]
fn joiner_rejects_welcome_whose_frontier_differs_from_ack() {
    let (mut w, mut root) = genesis("joiner-ack");
    let apf = w.apf_signer();
    for subject in ["bob", "carol", "dave", "erin", "frank", "gina", "hank"] {
        w.delegate(subject, &["read", "write", "admit"]);
    }

    // Positive path: bob joins under the right ack.
    let (mut bob, bob_admitted) = admit(&mut w, ROOT, &mut root, "bob", &mut []);

    // Each refusing joiner's Add is canonical; only its join is refused. A refused
    // join consumes the candidate, so every case uses its own candidate.
    type Forge<'a> = Box<dyn Fn(&Admitted, &CanonicalAck) -> Vec<u8> + 'a>;
    let cases: Vec<(&str, Forge<'_>, &str)> = vec![
        (
            "carol",
            Box::new(|_, _| bob_admitted.ack.clone()),
            "binding_mismatch",
        ),
        (
            "dave",
            Box::new(|_, good| {
                let mut ack = good.clone();
                ack.successor.branch = lower_hex(&sha256(b"not the joined frontier"));
                ack.sign(&apf).expect("forge")
            }),
            "binding_mismatch",
        ),
        (
            "erin",
            Box::new(|admitted, _| flip_last(&admitted.ack)),
            "unauthenticated",
        ),
        (
            "frank",
            Box::new(|_, good| {
                good.sign(&DalekSigner::from_seed([0x7e; 32]))
                    .expect("sign")
            }),
            "unauthenticated",
        ),
        (
            "gina",
            Box::new(|_, good| {
                let mut ack = good.clone();
                ack.kind = AckKind::Update;
                ack.sign(&apf).expect("forge")
            }),
            "binding_mismatch",
        ),
    ];
    for (subject, forge, expected) in cases {
        let candidate = w.candidate(subject);
        let staged = root.stage_add(candidate.key_package()).expect("stage");
        let admitted = canonical(&mut w, ROOT, &mut root, &staged, &mut [&mut bob]);
        let good = w.verify_ack(&admitted.ack);
        let ack = forge(&admitted, &good);
        let err = code(candidate.join(&staged.welcome, &ack).map(|_| ()), expected);
        assert_eq!(w.frontier(), admitted.frontier, "{subject}: {err}");
    }

    // A joiner that pinned another APF key refuses a genuine ack.
    let prepared = {
        let rights = w.rights_of("hank");
        let provider = w.provider("hank");
        PreparedJoin::prepare(
            GROUP,
            "hank",
            &rights,
            identity("hank"),
            provider,
            &DalekSigner::from_seed([0x7d; 32]).public_key(),
        )
        .expect("prepare with another pinned key")
    };
    let certificate = w
        .certificate("hank", prepared.preimage())
        .expect("hank certificate");
    let pinned_elsewhere = prepared.finalize(&certificate).expect("finalize");
    let staged = root
        .stage_add(pinned_elsewhere.key_package())
        .expect("stage");
    let admitted = canonical(&mut w, ROOT, &mut root, &staged, &mut [&mut bob]);
    code(
        pinned_elsewhere
            .join(&staged.welcome, &admitted.ack)
            .map(|_| ()),
        "unauthenticated",
    );

    // The correct ack joins.
    w.delegate("ivy", &["read", "write", "admit"]);
    let (mut ivy, admitted) = admit(&mut w, ROOT, &mut root, "ivy", &mut [&mut bob]);
    assert_eq!(admitted.frontier.epoch, 8);
    assert_eq!(ivy.frontier().expect("ivy"), w.frontier());
    assert_eq!(raw_frontier(&mut ivy), w.frontier());
    assert_eq!(current_anchor(&mut ivy), decode_anchor(&w.apf_anchor));
}

#[test]
fn incarnation_relabeling_to_fresh_generation_is_rejected() {
    let (mut w, mut root) = genesis("incarnation");
    for subject in ["bob", "carol", "dave"] {
        w.delegate(subject, &["read", "write", "admit"]);
    }
    let ciphersuite = group_ciphersuite(&mut root);

    // Positive path: a KeyPackage forged honestly through raw OpenMLS is admitted, so
    // the refusals below come from the incarnation and key checks alone.
    let bob_rights = codes(&w.rights_of("bob"));
    let honest = certified_forgery(
        &mut w,
        ciphersuite,
        "bob",
        &identity("bob"),
        "bob",
        Some(encode_incarnation("bob", &bob_rights, &ZERO_HASH)),
    );
    let staged = root.stage_add(&honest).expect("stage honest forgery");
    canonical(&mut w, ROOT, &mut root, &staged, &mut []);
    assert_eq!(w.checkpoint()["roster"], json!([ROOT, "bob"]));
    let parent = w.frontier();

    let carol = codes(&w.rights_of("carol"));
    assert_eq!(carol, vec![(1, 0), (2, 0), (4, 0)]);
    let cases: Vec<(&str, ClientIdentity, Option<Vec<u8>>)> = vec![
        (
            "higher read generation",
            identity("carol"),
            Some(encode_incarnation(
                "carol",
                &[(1, 1), (2, 0), (4, 0)],
                &ZERO_HASH,
            )),
        ),
        (
            "higher admit generation",
            identity("carol"),
            Some(encode_incarnation(
                "carol",
                &[(1, 0), (2, 0), (4, 3)],
                &ZERO_HASH,
            )),
        ),
        (
            "another subject",
            identity("carol"),
            Some(encode_incarnation("dave", &carol, &ZERO_HASH)),
        ),
        (
            "extra right",
            identity("carol"),
            Some(encode_incarnation(
                "carol",
                &[(1, 0), (2, 0), (3, 0), (4, 0)],
                &ZERO_HASH,
            )),
        ),
        (
            "missing right",
            identity("carol"),
            Some(encode_incarnation("carol", &[(1, 0), (4, 0)], &ZERO_HASH)),
        ),
        (
            "non-zero admission_cert_hash",
            identity("carol"),
            Some(encode_incarnation("carol", &carol, &[0x01; 32])),
        ),
        (
            "short zero admission_cert_hash",
            identity("carol"),
            Some(encode_incarnation("carol", &carol, &[0x00; 31])),
        ),
        ("no incarnation", identity("carol"), None),
        (
            "unregistered signature key",
            identity("carol@impostor"),
            Some(encode_incarnation("carol", &carol, &ZERO_HASH)),
        ),
        (
            "another subject's registered key",
            identity("dave"),
            Some(encode_incarnation("carol", &carol, &ZERO_HASH)),
        ),
    ];
    for (case, signer, incarnation) in cases {
        let key_package =
            certified_forgery(&mut w, ciphersuite, "carol", &signer, "carol", incarnation);
        let parsed = parse_key_package(&key_package);
        assert_eq!(
            credential_identity(parsed.leaf_node().credential()),
            b"carol"
        );
        let staged = root
            .stage_add(&key_package)
            .unwrap_or_else(|err| panic!("{case}: root stages, got {err}"));
        let err = refused_commit(&mut w, ROOT, &mut root, &staged, "noncanonical_commit");
        assert_eq!(w.frontier(), parent, "{case}: {err}");
    }

    // An honest admission afterwards succeeds.
    let (carol_client, admitted) = admit(&mut w, ROOT, &mut root, "carol", &mut []);
    assert_eq!(admitted.frontier.epoch, parent.epoch + 1);
    assert_eq!(carol_client.frontier().expect("carol"), w.frontier());
}
