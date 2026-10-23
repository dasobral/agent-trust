//! Shared test support for the adapter suites (`docs/adapter-contract.md` §4.8, §4.9, §8).
//!
//! Everything here is test-only. `ScriptedRand` is deterministic and MUST NOT be used
//! outside tests. The `RequestTBS` encoder below is written independently of
//! `src/adapter.rs` so the tests can check the adapter's encoding against it.
#![allow(dead_code)]

use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use agent_trust::adapter::{Clock, SignedRequest};
use ed25519_dalek::{Signer as DalekSignerTrait, SigningKey};
use openmls_rust_crypto::{MemoryStorage, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tls_codec::{Serialize as TlsSerialize, VLBytes};

/// The `RequestTBS` label, spelled out here independently of the adapter constant.
pub const TEST_REQUEST_LABEL: &[u8] = b"agent-trust/request/v1";

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/// An `OpenMlsProvider` with stock RustCrypto crypto, memory storage and a pluggable rand.
pub struct TestProvider<R: OpenMlsRand> {
    crypto: RustCrypto,
    storage: MemoryStorage,
    rand: R,
}

impl<R: OpenMlsRand> TestProvider<R> {
    pub fn new(rand: R) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
            rand,
        }
    }
}

impl<R: OpenMlsRand> OpenMlsProvider for TestProvider<R> {
    type CryptoProvider = RustCrypto;
    type RandProvider = R;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}

// ---------------------------------------------------------------------------
// Rand implementations
// ---------------------------------------------------------------------------

/// One recorded draw: the requested length and the exact bytes returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draw {
    pub len: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug)]
struct ScriptedState {
    seed: Vec<u8>,
    counter: u64,
    draws: Vec<Draw>,
}

/// Deterministic, test-only randomness. Draw `i` is the concatenation of
/// `SHA-256(seed || i || block)` for `block = 0, 1, ...`, truncated to the requested
/// length (`i` and `block` as big-endian u64). Clones share one state, so a test can
/// keep a handle and inspect every draw after the provider was moved into the adapter.
#[derive(Clone, Debug)]
pub struct ScriptedRand {
    state: Arc<Mutex<ScriptedState>>,
}

impl ScriptedRand {
    pub fn new(seed: &[u8]) -> Self {
        Self {
            state: Arc::new(Mutex::new(ScriptedState {
                seed: seed.to_vec(),
                counter: 0,
                draws: Vec::new(),
            })),
        }
    }

    /// Every draw so far, in order.
    pub fn draws(&self) -> Vec<Draw> {
        self.state.lock().expect("scripted rand lock").draws.clone()
    }

    fn draw(&self, len: usize) -> Vec<u8> {
        let mut state = self.state.lock().expect("scripted rand lock");
        let index = state.counter;
        state.counter += 1;
        let mut out = Vec::with_capacity(len);
        let mut block = 0u64;
        while out.len() < len {
            let mut hasher = Sha256::new();
            hasher.update(&state.seed);
            hasher.update(index.to_be_bytes());
            hasher.update(block.to_be_bytes());
            out.extend_from_slice(&hasher.finalize());
            block += 1;
        }
        out.truncate(len);
        state.draws.push(Draw {
            len,
            bytes: out.clone(),
        });
        out
    }
}

impl OpenMlsRand for ScriptedRand {
    type Error = std::convert::Infallible;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        let bytes = self.draw(N);
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        Ok(self.draw(len))
    }
}

/// The error every `FailingRand` draw returns.
#[derive(Debug)]
pub struct EntropyFailure;

impl fmt::Display for EntropyFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("test rand always fails")
    }
}

impl std::error::Error for EntropyFailure {}

/// A rand provider whose every draw fails.
#[derive(Clone, Copy, Debug, Default)]
pub struct FailingRand;

impl OpenMlsRand for FailingRand {
    type Error = EntropyFailure;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        Err(EntropyFailure)
    }

    fn random_vec(&self, _len: usize) -> Result<Vec<u8>, Self::Error> {
        Err(EntropyFailure)
    }
}

pub fn scripted_provider(seed: &[u8]) -> (TestProvider<ScriptedRand>, ScriptedRand) {
    let rand = ScriptedRand::new(seed);
    (TestProvider::new(rand.clone()), rand)
}

// ---------------------------------------------------------------------------
// Clock
// ---------------------------------------------------------------------------

/// A settable clock. Clones share one value.
#[derive(Clone, Debug)]
pub struct FixedClock {
    now: Arc<AtomicU64>,
}

impl FixedClock {
    pub fn new(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }

    pub fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}

impl Clock for FixedClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Directories and result codes
// ---------------------------------------------------------------------------

/// A fresh, existing and empty temporary directory for one adapter. C-5 makes
/// `create` fail on existing files, not on an existing directory.
pub fn adapter_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temporary adapter directory")
}

/// Asserts that `result` is an error whose code is `expected` (exactly, or followed by `:`).
pub fn code<T>(result: Result<T, String>, expected: &str) -> String {
    let err = match result {
        Err(err) => err,
        Ok(_) => panic!("request should be rejected with {expected}"),
    };
    assert!(
        err == expected || err.starts_with(&format!("{expected}:")),
        "expected {expected}, got {err}"
    );
    err
}

// ---------------------------------------------------------------------------
// Independent keys and request encoding
// ---------------------------------------------------------------------------

/// Ed25519 public key that ed25519-dalek derives from `seed`.
pub fn dalek_public(seed: &[u8]) -> Vec<u8> {
    let seed: [u8; 32] = seed.try_into().expect("32-byte Ed25519 seed");
    SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
        .to_vec()
}

/// An OpenMLS `Signer` backed directly by ed25519-dalek, independent of the adapter.
pub struct DalekSigner {
    key: SigningKey,
}

impl DalekSigner {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn public_key(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }
}

impl Signer for DalekSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

fn vl(bytes: &[u8]) -> Vec<u8> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .expect("VLBytes encoding")
}

/// `RequestTBS` (§4.8) encoded with `tls_codec`, independently of `src/adapter.rs`:
/// `opaque label<V>`, `opaque group<V>`, `opaque actor<V>`, `uint64 sequence`, `opaque body<V>`.
pub fn independent_tbs(group: &str, actor: &str, sequence: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(vl(TEST_REQUEST_LABEL));
    out.extend(vl(group.as_bytes()));
    out.extend(vl(actor.as_bytes()));
    out.extend(sequence.tls_serialize_detached().expect("uint64 encoding"));
    out.extend(vl(body));
    out
}

/// Builds a `SignedRequest` without the adapter: the body is `serde_json::to_vec(body)`
/// and the signature covers `independent_tbs`.
pub fn sign(
    signer: &impl Signer,
    group: &str,
    actor: &str,
    sequence: u64,
    body: &Value,
) -> SignedRequest {
    let body = serde_json::to_vec(body).expect("JSON body");
    let signature = signer
        .sign(&independent_tbs(group, actor, sequence, &body))
        .expect("test signature");
    SignedRequest {
        actor: actor.to_owned(),
        sequence,
        body,
        signature,
    }
}

/// Lowercase hex of `bytes`.
pub fn lower_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// True if `needle` occurs anywhere in `haystack`.
pub fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Every regular file in `dir`, with its name and bytes.
pub fn files_in(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read adapter directory") {
        let entry = entry.expect("directory entry");
        if entry.file_type().expect("file type").is_file() {
            let name = entry.file_name().to_string_lossy().into_owned();
            out.push((name, std::fs::read(entry.path()).expect("read file")));
        }
    }
    out.sort();
    out
}
