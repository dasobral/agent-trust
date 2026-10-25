//! TLS encodings shared by the adapter and client endpoints (`docs/adapter-contract.md`
//! §4.1–§4.6, C-9, C-14, C-15). Every signed structure is `struct { TBS tbs; opaque signature<V>; }`
//! signed over the TLS encoding of `tbs` with the scheme of the group's suite: Ed25519 or
//! ML-DSA-44 (C-42).

use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};

use crate::suite::Suite;

pub const FRONTIER_LABEL: &[u8] = b"agent-trust/frontier/v1";
pub const FOUNDER_LABEL: &[u8] = b"agent-trust/founder/v1";
pub const CANONICAL_LABEL: &[u8] = b"agent-trust/canonical/v1";
pub const ADMISSION_MAGIC: &[u8] = b"AT-APF-KP";
pub const ADMISSION_VERSION: u8 = 2;
/// KeyPackage extension carrying the admission certificate (existing codepoint).
pub const ADMISSION_EXTENSION_TYPE: u16 = 0xf042;
/// GroupContext extension `apf_anchor` (§4.2).
pub const APF_ANCHOR_EXTENSION_TYPE: u16 = 0xf043;
/// LeafNode extension `authz_incarnation` (§4.3).
pub const AUTHZ_INCARNATION_EXTENSION_TYPE: u16 = 0xf044;

/// Version byte of `apf_anchor` and `authz_incarnation`.
const STRUCT_VERSION: u8 = 1;
/// Length of the QUIC-style two-byte prefix of a signature `opaque<V>`: 64-byte Ed25519
/// signatures (`0x40 0x40`) and 2420-byte ML-DSA-44 signatures (`0x49 0x74`) both use the
/// two-byte form (C-9, C-42).
const SIGNATURE_PREFIX_LEN: usize = 2;

/// The two-byte QUIC-style prefix of an `opaque<V>` of `len` bytes (64 ≤ len < 16384).
fn signature_prefix(len: usize) -> [u8; SIGNATURE_PREFIX_LEN] {
    [0x40 | (len >> 8) as u8, (len & 0xff) as u8]
}

/// Rights with their wire codes (C-9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Right {
    Read = 1,
    Write = 2,
    Admin = 3,
    Admit = 4,
}

impl Right {
    pub fn code(self) -> u8 {
        self as u8
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Read),
            2 => Some(Self::Write),
            3 => Some(Self::Admin),
            4 => Some(Self::Admit),
            _ => None,
        }
    }

    /// Kernel right name: `read`, `write`, `admin` or `admit`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
            Self::Admit => "admit",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            "admit" => Some(Self::Admit),
            _ => None,
        }
    }
}

/// Canonical frontier `(epoch, branch)` (§4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    pub epoch: u64,
    /// Lowercase hex SHA-256 of `FrontierInput`.
    pub branch: String,
}

impl Frontier {
    /// Computes the frontier from the four `GroupContext` values.
    pub fn compute(
        group_id: &[u8],
        epoch: u64,
        tree_hash: &[u8],
        confirmed_transcript_hash: &[u8],
    ) -> Result<Self, String> {
        let mut w = Writer::default();
        w.opaque(FRONTIER_LABEL)?;
        w.opaque(group_id)?;
        w.u64(epoch)?;
        w.opaque(tree_hash)?;
        w.opaque(confirmed_transcript_hash)?;
        Ok(Self {
            epoch,
            branch: hex::encode(Sha256::digest(w.finish())),
        })
    }
}

/// `apf_anchor` GroupContext extension payload (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApfAnchor {
    pub version: u8,
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub policy_revision: u64,
    /// SHA-256 bytes (not hex) of the kernel policy snapshot.
    pub policy_digest: Vec<u8>,
}

impl ApfAnchor {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.u8(self.version);
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.u64(self.policy_revision)?;
        w.opaque(&self.policy_digest)?;
        Ok(w.finish())
    }

    /// Decodes exactly one well-formed version-1 payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != STRUCT_VERSION {
            return Err("malformed: apf_anchor version".into());
        }
        let anchor = Self {
            version,
            apf_key_id: r.opaque()?,
            group: r.string()?,
            policy_revision: r.u64()?,
            policy_digest: r.opaque()?,
        };
        r.finish()?;
        Ok(anchor)
    }
}

/// `authz_incarnation` LeafNode extension payload (§4.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthzIncarnation {
    pub version: u8,
    pub subject: String,
    /// Sorted by right code, without duplicates.
    pub rights: Vec<(Right, u64)>,
    /// SHA-256 of the founder certificate, or 32 zero bytes for a joiner.
    pub admission_cert_hash: Vec<u8>,
}

impl AuthzIncarnation {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.u8(self.version);
        w.opaque(self.subject.as_bytes())?;
        w.opaque(&encode_rights(&self.rights)?)?;
        w.opaque(&self.admission_cert_hash)?;
        Ok(w.finish())
    }

    /// Decodes exactly one well-formed version-1 payload with sorted, distinct rights.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let version = r.u8()?;
        if version != STRUCT_VERSION {
            return Err("malformed: authz_incarnation version".into());
        }
        let incarnation = Self {
            version,
            subject: r.string()?,
            rights: decode_rights(&r.opaque()?)?,
            admission_cert_hash: r.opaque()?,
        };
        r.finish()?;
        Ok(incarnation)
    }
}

/// Founder certificate TBS (C-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FounderCertificate {
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub subject: String,
    pub rights: Vec<(Right, u64)>,
    pub signature_key: Vec<u8>,
}

/// Admission certificate v2 TBS (§4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionCertificate {
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub subject: String,
    pub read_generation: u64,
    pub admit_generation: u64,
    pub policy_revision: u64,
    pub not_after: u64,
    pub key_package_preimage_hash: Vec<u8>,
}

/// Kind of a canonical acknowledgement (§4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AckKind {
    Admit = 1,
    Repair = 2,
    Update = 3,
}

impl AckKind {
    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Admit),
            2 => Some(Self::Repair),
            3 => Some(Self::Update),
            _ => None,
        }
    }
}

/// Canonical acknowledgement TBS (§4.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalAck {
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub parent: Frontier,
    pub successor: Frontier,
    /// SHA-256 of the exact commit `MlsMessage` bytes.
    pub commit_hash: Vec<u8>,
    pub kind: AckKind,
}

/// A TBS structure that is signed as `struct { tbs; opaque signature<V>; }`.
pub trait SignedStructure: Sized {
    /// TLS encoding of the TBS.
    fn tbs(&self) -> Result<Vec<u8>, String>;
    /// Decodes a TBS encoding.
    fn decode_tbs(bytes: &[u8]) -> Result<Self, String>;

    /// Signs the TBS and returns the signed structure encoding.
    fn sign(&self, signer: &impl Signer) -> Result<Vec<u8>, String> {
        let mut out = self.tbs()?;
        let signature = signer
            .sign(&out)
            .map_err(|_| "malformed: signing failed".to_string())?;
        out.extend(opaque(&signature)?);
        Ok(out)
    }

    /// Decodes a signed structure and verifies its signature under `public_key`, with
    /// the scheme of the suite that `public_key` belongs to (C-42). A bad signature is
    /// `unauthenticated`; a bad encoding is `malformed`.
    ///
    /// The APF signs with the group's one scheme (C-9, C-42), so the trailing
    /// `opaque signature<V>` has that scheme's fixed length: 66 bytes for Ed25519, 2422
    /// for ML-DSA-44. The TBS before it must decode exactly and re-encode to the same
    /// bytes, so the signed bytes have one canonical meaning.
    fn verify(
        bytes: &[u8],
        public_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, String> {
        let suite = key_suite(public_key)?;
        let (decoded, tbs, signature) = split_signed::<Self>(bytes, suite)?;
        crypto
            .verify_signature(suite.signature_scheme(), tbs, public_key, signature)
            .map_err(|_| "unauthenticated".to_string())?;
        Ok(decoded)
    }
}

/// The suite of a verifying key; a key of neither suite cannot verify (`unauthenticated`).
fn key_suite(public_key: &[u8]) -> Result<Suite, String> {
    Suite::from_public_key(public_key).ok_or_else(|| "unauthenticated".to_string())
}

/// Splits a signed structure into its canonically decoded TBS, the TBS bytes and the
/// raw signature of `suite`'s length (see [`SignedStructure::verify`]).
fn split_signed<T: SignedStructure>(
    bytes: &[u8],
    suite: Suite,
) -> Result<(T, &[u8], &[u8]), String> {
    let length = suite.signature_len();
    let split = bytes
        .len()
        .checked_sub(SIGNATURE_PREFIX_LEN + length)
        .ok_or_else(|| "malformed: signed structure".to_string())?;
    let (tbs, signature) = bytes.split_at(split);
    if signature[..SIGNATURE_PREFIX_LEN] != signature_prefix(length) {
        return Err("malformed: signature encoding".into());
    }
    let decoded = T::decode_tbs(tbs)?;
    if decoded.tbs()? != tbs {
        return Err("malformed: non-canonical encoding".into());
    }
    Ok((decoded, tbs, &signature[SIGNATURE_PREFIX_LEN..]))
}

/// [`SignedStructure::verify`] without an OpenMLS provider, for holders of a signed
/// structure that no longer have one, such as a pending delivery (C-18): Ed25519 with
/// ed25519-dalek's strict verification (the check the RustCrypto provider applies),
/// ML-DSA-44 with the `ml-dsa` crate and an empty context (C-42).
pub(crate) fn verify_without_provider<T: SignedStructure>(
    bytes: &[u8],
    public_key: &[u8],
) -> Result<T, String> {
    let suite = key_suite(public_key)?;
    let (decoded, tbs, signature) = split_signed::<T>(bytes, suite)?;
    if !suite.verify_without_provider(tbs, public_key, signature) {
        return Err("unauthenticated".into());
    }
    Ok(decoded)
}

impl SignedStructure for FounderCertificate {
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(FOUNDER_LABEL)?;
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.opaque(self.subject.as_bytes())?;
        w.opaque(&encode_rights(&self.rights)?)?;
        w.opaque(&self.signature_key)?;
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(FOUNDER_LABEL)?;
        let founder = Self {
            apf_key_id: r.opaque()?,
            group: r.string()?,
            subject: r.string()?,
            rights: decode_rights(&r.opaque()?)?,
            signature_key: r.opaque()?,
        };
        r.finish()?;
        Ok(founder)
    }
}

impl SignedStructure for AdmissionCertificate {
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(ADMISSION_MAGIC)?;
        w.u8(ADMISSION_VERSION);
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.opaque(self.subject.as_bytes())?;
        w.u64(self.read_generation)?;
        w.u64(self.admit_generation)?;
        w.u64(self.policy_revision)?;
        w.u64(self.not_after)?;
        w.opaque(&self.key_package_preimage_hash)?;
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(ADMISSION_MAGIC)?;
        if r.u8()? != ADMISSION_VERSION {
            return Err("malformed: admission certificate version".into());
        }
        let certificate = Self {
            apf_key_id: r.opaque()?,
            group: r.string()?,
            subject: r.string()?,
            read_generation: r.u64()?,
            admit_generation: r.u64()?,
            policy_revision: r.u64()?,
            not_after: r.u64()?,
            key_package_preimage_hash: r.opaque()?,
        };
        r.finish()?;
        Ok(certificate)
    }
}

impl SignedStructure for CanonicalAck {
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(CANONICAL_LABEL)?;
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.u64(self.parent.epoch)?;
        // C-13: a branch is its 64-character lowercase hex string as ASCII bytes.
        w.opaque(self.parent.branch.as_bytes())?;
        w.u64(self.successor.epoch)?;
        w.opaque(self.successor.branch.as_bytes())?;
        w.opaque(&self.commit_hash)?;
        w.u8(self.kind as u8);
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(CANONICAL_LABEL)?;
        let apf_key_id = r.opaque()?;
        let group = r.string()?;
        let parent = Frontier {
            epoch: r.u64()?,
            branch: r.string()?,
        };
        let successor = Frontier {
            epoch: r.u64()?,
            branch: r.string()?,
        };
        let commit_hash = r.opaque()?;
        let kind = AckKind::from_code(r.u8()?).ok_or("malformed: ack kind")?;
        r.finish()?;
        Ok(Self {
            apf_key_id,
            group,
            parent,
            successor,
            commit_hash,
            kind,
        })
    }
}

/// `RightGeneration rights<V>` body: concatenated `uint8 right ‖ uint64 generation`,
/// strictly increasing by right code.
fn encode_rights(rights: &[(Right, u64)]) -> Result<Vec<u8>, String> {
    if rights.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err("malformed: rights must be sorted and distinct".into());
    }
    let mut w = Writer::default();
    for (right, generation) in rights {
        w.u8(right.code());
        w.u64(*generation)?;
    }
    Ok(w.finish())
}

fn decode_rights(bytes: &[u8]) -> Result<Vec<(Right, u64)>, String> {
    let mut r = Reader::new(bytes);
    let mut rights: Vec<(Right, u64)> = Vec::new();
    while !r.is_empty() {
        let right = Right::from_code(r.u8()?).ok_or("malformed: right code")?;
        let generation = r.u64()?;
        if rights.last().is_some_and(|(last, _)| *last >= right) {
            return Err("malformed: rights must be sorted and distinct".into());
        }
        rights.push((right, generation));
    }
    Ok(rights)
}

fn opaque(bytes: &[u8]) -> Result<Vec<u8>, String> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .map_err(|_| "malformed: encoding".to_string())
}

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn u64(&mut self, value: u64) -> Result<(), String> {
        self.out.extend(
            value
                .tls_serialize_detached()
                .map_err(|_| "malformed: encoding".to_string())?,
        );
        Ok(())
    }

    fn opaque(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.out.extend(opaque(bytes)?);
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.out
    }
}

struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { rest: bytes }
    }

    fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    fn u8(&mut self) -> Result<u8, String> {
        u8::tls_deserialize(&mut self.rest).map_err(|_| "malformed: uint8".to_string())
    }

    fn u64(&mut self) -> Result<u64, String> {
        u64::tls_deserialize(&mut self.rest).map_err(|_| "malformed: uint64".to_string())
    }

    fn opaque(&mut self) -> Result<Vec<u8>, String> {
        VLBytes::tls_deserialize(&mut self.rest)
            .map(|bytes| bytes.as_slice().to_vec())
            .map_err(|_| "malformed: opaque".to_string())
    }

    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.opaque()?).map_err(|_| "malformed: utf-8".to_string())
    }

    fn label(&mut self, expected: &[u8]) -> Result<(), String> {
        if self.opaque()? != expected {
            return Err("malformed: label".into());
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err("malformed: trailing bytes".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 4.3: frozen content, release certificates, consume receipts, envelopes
// (C-14, C-15)
// ---------------------------------------------------------------------------

pub const OPERATION_LABEL: &[u8] = b"agent-trust/operation/v1";
pub const RELEASE_LABEL: &[u8] = b"agent-trust/release/v1";
pub const CONSUME_LABEL: &[u8] = b"agent-trust/consume/v1";

/// Lowercase hex digest of the frozen operation (C-14): SHA-256 of
/// `TLS { label, op, resource, content_type, SHA-256(payload), epoch, branch,
/// policy_revision }`, with the payload hash as raw bytes and the branch as ASCII hex.
pub fn operation_digest(
    op: &str,
    resource: &str,
    content_type: &[u8],
    payload: &[u8],
    frontier: &Frontier,
    policy_revision: u64,
) -> Result<String, String> {
    let mut w = Writer::default();
    w.opaque(OPERATION_LABEL)?;
    w.opaque(op.as_bytes())?;
    w.opaque(resource.as_bytes())?;
    w.opaque(content_type)?;
    w.opaque(&Sha256::digest(payload))?;
    w.u64(frontier.epoch)?;
    w.opaque(frontier.branch.as_bytes())?;
    w.u64(policy_revision)?;
    Ok(hex::encode(Sha256::digest(w.finish())))
}

/// MLS application plaintext `FrozenContent { content_type, payload }` (C-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenContent {
    pub content_type: Vec<u8>,
    pub payload: Vec<u8>,
}

impl FrozenContent {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(&self.content_type)?;
        w.opaque(&self.payload)?;
        Ok(w.finish())
    }

    /// Decodes exactly one `FrozenContent`; trailing bytes are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let content = Self {
            content_type: r.opaque()?,
            payload: r.opaque()?,
        };
        r.finish()?;
        Ok(content)
    }
}

/// Release certificate TBS (§4.5, C-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseCertificate {
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub op: String,
    pub actor: String,
    pub right: Right,
    pub resource: String,
    /// Empty when the operation has no invocation.
    pub invocation: String,
    pub frontier: Frontier,
    pub policy_revision: u64,
    /// Kernel digest (lowercase hex).
    pub digest: String,
    pub writer_generation: u64,
    /// `(subject, read generation)`, sorted by subject.
    pub readers: Vec<(String, u64)>,
    /// Kernel release `event_hash` (lowercase hex).
    pub kernel_event_hash: String,
}

impl SignedStructure for ReleaseCertificate {
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(RELEASE_LABEL)?;
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.opaque(self.op.as_bytes())?;
        w.opaque(self.actor.as_bytes())?;
        w.u8(self.right.code());
        w.opaque(self.resource.as_bytes())?;
        w.opaque(self.invocation.as_bytes())?;
        w.u64(self.frontier.epoch)?;
        // C-13 / C-14: hashes the kernel stores as hex travel as ASCII hex.
        w.opaque(self.frontier.branch.as_bytes())?;
        w.u64(self.policy_revision)?;
        w.opaque(self.digest.as_bytes())?;
        w.u64(self.writer_generation)?;
        w.opaque(&encode_readers(&self.readers)?)?;
        w.opaque(self.kernel_event_hash.as_bytes())?;
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(RELEASE_LABEL)?;
        let apf_key_id = r.opaque()?;
        let group = r.string()?;
        let op = r.string()?;
        let actor = r.string()?;
        let right = Right::from_code(r.u8()?).ok_or("malformed: right code")?;
        let resource = r.string()?;
        let invocation = r.string()?;
        let frontier = Frontier {
            epoch: r.u64()?,
            branch: r.string()?,
        };
        let policy_revision = r.u64()?;
        let digest = r.string()?;
        let writer_generation = r.u64()?;
        let readers = decode_readers(&r.opaque()?)?;
        let kernel_event_hash = r.string()?;
        r.finish()?;
        Ok(Self {
            apf_key_id,
            group,
            op,
            actor,
            right,
            resource,
            invocation,
            frontier,
            policy_revision,
            digest,
            writer_generation,
            readers,
            kernel_event_hash,
        })
    }
}

/// Consume receipt TBS (C-15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsumeReceipt {
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub op: String,
    pub recipient: String,
    /// SHA-256 of the signed release certificate bytes.
    pub release_certificate_hash: Vec<u8>,
}

impl SignedStructure for ConsumeReceipt {
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(CONSUME_LABEL)?;
        w.opaque(&self.apf_key_id)?;
        w.opaque(self.group.as_bytes())?;
        w.opaque(self.op.as_bytes())?;
        w.opaque(self.recipient.as_bytes())?;
        w.opaque(&self.release_certificate_hash)?;
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(CONSUME_LABEL)?;
        let receipt = Self {
            apf_key_id: r.opaque()?,
            group: r.string()?,
            op: r.string()?,
            recipient: r.string()?,
            release_certificate_hash: r.opaque()?,
        };
        r.finish()?;
        Ok(receipt)
    }
}

/// `Envelope { certificate, mls_message }` (C-14).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Signed release certificate bytes.
    pub certificate: Vec<u8>,
    /// Exact `MlsMessage` bytes.
    pub mls_message: Vec<u8>,
}

impl Envelope {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(&self.certificate)?;
        w.opaque(&self.mls_message)?;
        Ok(w.finish())
    }

    /// Decodes exactly one envelope; trailing bytes are refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        let envelope = Self {
            certificate: r.opaque()?,
            mls_message: r.opaque()?,
        };
        r.finish()?;
        Ok(envelope)
    }
}

/// `ReaderGeneration readers<V>` body: concatenated `opaque subject<V> ‖ uint64
/// generation`, strictly increasing by subject bytes (sorted, no duplicates).
fn encode_readers(readers: &[(String, u64)]) -> Result<Vec<u8>, String> {
    if readers
        .windows(2)
        .any(|pair| pair[0].0.as_bytes() >= pair[1].0.as_bytes())
    {
        return Err("malformed: readers must be sorted and distinct".into());
    }
    let mut w = Writer::default();
    for (subject, generation) in readers {
        w.opaque(subject.as_bytes())?;
        w.u64(*generation)?;
    }
    Ok(w.finish())
}

fn decode_readers(bytes: &[u8]) -> Result<Vec<(String, u64)>, String> {
    let mut r = Reader::new(bytes);
    let mut readers: Vec<(String, u64)> = Vec::new();
    while !r.is_empty() {
        let subject = r.string()?;
        let generation = r.u64()?;
        if readers
            .last()
            .is_some_and(|(last, _)| last.as_bytes() >= subject.as_bytes())
        {
            return Err("malformed: readers must be sorted and distinct".into());
        }
        readers.push((subject, generation));
    }
    Ok(readers)
}

// ---------------------------------------------------------------------------
// Phase 4.4a: repair confirmation (§4.7, C-23)
// ---------------------------------------------------------------------------

pub const CONFIRM_LABEL: &[u8] = b"agent-trust/confirm/v1";

/// `SHA-256(label ‖ branch ‖ epoch_authenticator)` with the branch as ASCII hex (C-23):
/// a plain concatenation, not a TLS structure. Only this hash leaves the client.
pub fn epoch_authenticator_hash(branch: &str, epoch_authenticator: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(CONFIRM_LABEL);
    hasher.update(branch.as_bytes());
    hasher.update(epoch_authenticator);
    hasher.finalize().to_vec()
}

/// Repair confirmation TBS (§4.7, C-23), signed with the member's registered key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepairConfirmation {
    pub group: String,
    pub frontier: Frontier,
    pub epoch_authenticator_hash: Vec<u8>,
}

impl SignedStructure for RepairConfirmation {
    /// `ConfirmationTBS { opaque label<V>; opaque group<V>; uint64 epoch;
    /// opaque branch<V>; opaque epoch_authenticator_hash<V>; }`, branch as ASCII hex.
    fn tbs(&self) -> Result<Vec<u8>, String> {
        let mut w = Writer::default();
        w.opaque(CONFIRM_LABEL)?;
        w.opaque(self.group.as_bytes())?;
        w.u64(self.frontier.epoch)?;
        w.opaque(self.frontier.branch.as_bytes())?;
        w.opaque(&self.epoch_authenticator_hash)?;
        Ok(w.finish())
    }

    fn decode_tbs(bytes: &[u8]) -> Result<Self, String> {
        let mut r = Reader::new(bytes);
        r.label(CONFIRM_LABEL)?;
        let confirmation = Self {
            group: r.string()?,
            frontier: Frontier {
                epoch: r.u64()?,
                branch: r.string()?,
            },
            epoch_authenticator_hash: r.opaque()?,
        };
        r.finish()?;
        Ok(confirmation)
    }
}
