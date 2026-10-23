//! TLS encodings shared by the adapter and client endpoints (`docs/adapter-contract.md`
//! §4.1–§4.6, C-9). Every signed structure is `struct { TBS tbs; opaque signature<V>; }`
//! signed with Ed25519 over the TLS encoding of `tbs`.

use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};

pub const FRONTIER_LABEL: &[u8] = b"agent-trust/frontier/v1";
pub const FOUNDER_LABEL: &[u8] = b"agent-trust/founder/v1";
pub const CANONICAL_LABEL: &[u8] = b"agent-trust/canonical/v1";
pub const ADMISSION_MAGIC: &[u8] = b"AT-APF-KP";
pub const ADMISSION_VERSION: u8 = 2;
/// KeyPackage extension carrying the admission certificate (existing codepoint).
pub const ADMISSION_EXTENSION_TYPE: u16 = 0xf042;
/// GroupContext extension `acc_context` (§4.2).
pub const ACC_CONTEXT_EXTENSION_TYPE: u16 = 0xf043;
/// LeafNode extension `authz_incarnation` (§4.3).
pub const AUTHZ_INCARNATION_EXTENSION_TYPE: u16 = 0xf044;

/// Version byte of `acc_context` and `authz_incarnation`.
const STRUCT_VERSION: u8 = 1;
/// Ed25519 signature length.
const SIGNATURE_LEN: usize = 64;
/// QUIC-style length prefix of a 64-byte `opaque<V>` (two-byte form, value 64).
const SIGNATURE_PREFIX: [u8; 2] = [0x40, 0x40];

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

/// `acc_context` GroupContext extension payload (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccContext {
    pub version: u8,
    pub apf_key_id: Vec<u8>,
    pub group: String,
    pub policy_revision: u64,
    /// SHA-256 bytes (not hex) of the kernel policy snapshot.
    pub policy_digest: Vec<u8>,
}

impl AccContext {
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
            return Err("malformed: acc_context version".into());
        }
        let acc = Self {
            version,
            apf_key_id: r.opaque()?,
            group: r.string()?,
            policy_revision: r.u64()?,
            policy_digest: r.opaque()?,
        };
        r.finish()?;
        Ok(acc)
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

    /// Decodes a signed structure and verifies its Ed25519 signature under `public_key`.
    /// A bad signature is `unauthenticated`; a bad encoding is `malformed`.
    ///
    /// The APF signs with Ed25519 only (C-9), so the trailing `opaque signature<V>` is
    /// exactly 66 bytes. The TBS before it must decode exactly and re-encode to the same
    /// bytes, so the signed bytes have one canonical meaning.
    fn verify(
        bytes: &[u8],
        public_key: &[u8],
        crypto: &impl OpenMlsCrypto,
    ) -> Result<Self, String> {
        let split = bytes
            .len()
            .checked_sub(SIGNATURE_PREFIX.len() + SIGNATURE_LEN)
            .ok_or_else(|| "malformed: signed structure".to_string())?;
        let (tbs, signature) = bytes.split_at(split);
        if signature[..SIGNATURE_PREFIX.len()] != SIGNATURE_PREFIX {
            return Err("malformed: signature encoding".into());
        }
        let decoded = Self::decode_tbs(tbs)?;
        if decoded.tbs()? != tbs {
            return Err("malformed: non-canonical encoding".into());
        }
        crypto
            .verify_signature(
                SignatureScheme::ED25519,
                tbs,
                public_key,
                &signature[SIGNATURE_PREFIX.len()..],
            )
            .map_err(|_| "unauthenticated".to_string())?;
        Ok(decoded)
    }
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
