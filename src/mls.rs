//! A small MLS laboratory backed by OpenMLS.
//!
//! Each endpoint owns a real MLS group and an independent crypto provider.  The
//! `roster` is the set of endpoints allowed to originate application traffic;
//! stale copies are retained only for adversarial decryption experiments.
//!
//! Endpoint state lives in the OpenMLS SQLite storage provider: in memory by
//! default, or one file per endpoint with [`MlsLab::open_durable`]. Every MLS
//! operation on an endpoint is one SQLite transaction, so an epoch transition
//! is installed completely or not at all. Laboratory metadata (roster names, the
//! laboratory APF key, admission evidence) is held in memory only.
//!
//! OpenMLS protocol randomness (`OpenMlsRand`) and the laboratory's Ed25519
//! signature-key seeds come from the configured [`EntropySource`]. Randomness
//! internal to RustCrypto and hpke-rs (for example HPKE encapsulation) is not
//! routed through that source.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::Duration,
};

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_qrand::{QrngClient, QrngError, QrngRand};
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::{
    crypto::OpenMlsCrypto,
    random::OpenMlsRand,
    signatures::Signer,
    types::{Ciphersuite, SignatureScheme},
    OpenMlsProvider,
};
use rusqlite::OpenFlags;
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize, Serialize};
use zeroize::Zeroize;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const GROUP_ID: &[u8] = b"agent-trust-mls-lab";
const APF_BINDING_EXTENSION_TYPE: u16 = 0xf042;
const APF_CERTIFICATE_MAGIC: &[u8] = b"AT-APF-KP";
const APF_CERTIFICATE_VERSION: u8 = 1;
const ACC_CONTEXT_EXTENSION_TYPE: u16 = 0xf043;
const INCARNATION_EXTENSION_TYPE: u16 = 0xf044;
const ACC_CONTEXT_MAGIC: &[u8] = b"AT-ACC";
const INCARNATION_MAGIC: &[u8] = b"AT-INC";
const BINDING_VERSION: u8 = 1;

/// Randomness source for OpenMLS protocol randomness and laboratory signature keys.
#[derive(Clone, Default)]
pub enum EntropySource {
    /// RustCrypto's ChaCha20 generator seeded from the operating system.
    #[default]
    Os,
    /// A QRNG Open API endpoint. Failures are errors; there is no fallback.
    Qrng(Arc<QrngClient>),
}

// Manual Debug: never print the QRNG client, whose Debug includes the endpoint.
impl std::fmt::Debug for EntropySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Os => "EntropySource::Os",
            Self::Qrng(_) => "EntropySource::Qrng(..)",
        })
    }
}

/// The `OpenMlsRand` selected by an [`EntropySource`].
enum LabRand {
    Os(RustCrypto),
    Qrng(QrngRand),
}

impl LabRand {
    fn new(source: &EntropySource) -> Self {
        match source {
            EntropySource::Os => Self::Os(RustCrypto::default()),
            EntropySource::Qrng(client) => Self::Qrng(QrngRand::new(client.clone())),
        }
    }
}

impl std::fmt::Debug for LabRand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Os(_) => "LabRand::Os",
            Self::Qrng(_) => "LabRand::Qrng",
        })
    }
}

#[derive(Debug)]
enum LabRandError {
    Os(<RustCrypto as OpenMlsRand>::Error),
    Qrng(QrngError),
}

impl std::fmt::Display for LabRandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Os(error) => write!(f, "OS randomness failed: {error}"),
            Self::Qrng(error) => write!(f, "QRNG entropy unavailable: {error}"),
        }
    }
}

impl std::error::Error for LabRandError {}

impl OpenMlsRand for LabRand {
    type Error = LabRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        match self {
            Self::Os(rand) => rand.random_array().map_err(LabRandError::Os),
            Self::Qrng(rand) => rand.random_array().map_err(LabRandError::Qrng),
        }
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Os(rand) => rand.random_vec(len).map_err(LabRandError::Os),
            Self::Qrng(rand) => rand.random_vec(len).map_err(LabRandError::Qrng),
        }
    }
}

/// `serde_json` codec for the OpenMLS SQLite storage provider.
#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

type LabStorage = SqliteStorageProvider<JsonCodec, Rc<Connection>>;

/// Per-endpoint OpenMLS provider: stock RustCrypto, the OpenMLS SQLite storage
/// provider (in memory, or one rollback-journal file per durable endpoint), and
/// the selected randomness source. The connection is shared with the storage
/// provider so that the laboratory can bracket each MLS operation in a single
/// SQLite transaction.
struct LabProvider {
    crypto: RustCrypto,
    storage: LabStorage,
    rand: LabRand,
    connection: Rc<Connection>,
}

impl LabProvider {
    fn in_memory(source: &EntropySource) -> Result<Self, String> {
        Self::from_connection(Connection::open_in_memory().map_err(error)?, source)
    }

    /// Creates a new state file. An existing file is never reused.
    fn create_file(path: &Path, source: &EntropySource) -> Result<Self, String> {
        if path.exists() {
            return Err(format!("state file already exists: {}", path.display()));
        }
        let connection = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
        )
        .map_err(error)?;
        Self::from_file_connection(connection, source)
    }

    /// Opens an existing state file, as a restarted process would.
    fn open_file(path: &Path, source: &EntropySource) -> Result<Self, String> {
        if !path.is_file() {
            return Err(format!("state file missing: {}", path.display()));
        }
        let connection =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(error)?;
        Self::from_file_connection(connection, source)
    }

    fn from_file_connection(
        connection: Connection,
        source: &EntropySource,
    ) -> Result<Self, String> {
        // Rollback-journal mode: with no open transaction the main file alone is
        // the complete durable state, which defines the retained-copy adversary.
        let mode: String = connection
            .query_row("PRAGMA journal_mode = DELETE", [], |row| row.get(0))
            .map_err(error)?;
        if mode != "delete" {
            return Err(format!("unexpected SQLite journal mode: {mode}"));
        }
        connection
            .execute_batch("PRAGMA synchronous = FULL")
            .map_err(error)?;
        Self::from_connection(connection, source)
    }

    fn from_connection(mut connection: Connection, source: &EntropySource) -> Result<Self, String> {
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut connection)
            .run_migrations()
            .map_err(error)?;
        let connection = Rc::new(connection);
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection.clone()),
            rand: LabRand::new(source),
            connection,
        })
    }

    /// Exact copy of this provider's database into a new in-memory database.
    fn snapshot(&self, source: &EntropySource) -> Result<Self, String> {
        let mut copy = Connection::open_in_memory().map_err(error)?;
        rusqlite::backup::Backup::new(&self.connection, &mut copy)
            .map_err(error)?
            .run_to_completion(256, Duration::ZERO, None)
            .map_err(error)?;
        Self::from_connection(copy, source)
    }

    /// Starts the durable transaction that brackets one MLS operation.
    fn begin(&self) -> Result<(), String> {
        self.connection
            .execute_batch("BEGIN IMMEDIATE")
            .map_err(error)
    }

    /// The durability boundary: the operation's writes become visible to a
    /// restarted process only after this succeeds.
    fn commit(&self) -> Result<(), String> {
        self.connection.execute_batch("COMMIT").map_err(error)
    }

    fn rollback(&self) {
        let _ = self.connection.execute_batch("ROLLBACK");
    }

    /// Generates an Ed25519 signature key pair from a 32-byte seed drawn from
    /// this provider's entropy source, rather than `SignatureKeyPair::new`,
    /// which always uses `OsRng`.
    fn generate_signer(&self) -> Result<SignatureKeyPair, String> {
        let mut seed: [u8; 32] = self.rand.random_array().map_err(error)?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public = signing_key.verifying_key().to_bytes().to_vec();
        let signer = SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public);
        seed.zeroize();
        Ok(signer)
    }
}

impl OpenMlsProvider for LabProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = LabRand;
    type StorageProvider = LabStorage;

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

/// Removes a state file the laboratory created for an operation that failed.
fn discard_state_file(path: &Path) {
    let _ = std::fs::remove_file(path);
    let mut journal = path.as_os_str().to_owned();
    journal.push("-journal");
    let _ = std::fs::remove_file(journal);
}

struct Endpoint {
    provider: LabProvider,
    group: MlsGroup,
    signer: Option<SignatureKeyPair>,
    admission_key_package: Option<Vec<u8>>,
    prepared_canonical: Option<Vec<u8>>,
    state_file: Option<PathBuf>,
    crash_before_commit: bool,
}

/// A durable member whose process died; it holds no open state, only what a
/// restarted process needs to find its file, plus commits it has missed.
struct OfflineEndpoint {
    state_file: PathBuf,
    signer_public: Vec<u8>,
    admission_key_package: Option<Vec<u8>>,
    prepared_canonical: Option<Vec<u8>>,
    pending_commits: Vec<Vec<u8>>,
}

struct PendingMember {
    provider: LabProvider,
    signer: SignatureKeyPair,
    key_package: KeyPackageBundle,
    key_package_wire: Vec<u8>,
    prepared_canonical: Vec<u8>,
}

impl PendingMember {
    fn new(
        name: &str,
        generation: u64,
        apf_signer: &SignatureKeyPair,
        entropy: &EntropySource,
        state_file: Option<&Path>,
        binding: Option<&Binding>,
    ) -> Result<Self, String> {
        let provider = match state_file {
            Some(path) => LabProvider::create_file(path, entropy)?,
            None => LabProvider::in_memory(entropy)?,
        };
        provider.begin()?;
        let staged = Self::stage(name, generation, apf_signer, &provider, binding);
        match staged {
            Ok((signer, key_package, key_package_wire, prepared_canonical)) => {
                provider.commit()?;
                Ok(Self {
                    provider,
                    signer,
                    key_package,
                    key_package_wire,
                    prepared_canonical,
                })
            }
            Err(error) => {
                provider.rollback();
                Err(error)
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn stage(
        name: &str,
        generation: u64,
        apf_signer: &SignatureKeyPair,
        provider: &LabProvider,
        binding: Option<&Binding>,
    ) -> Result<(SignatureKeyPair, KeyPackageBundle, Vec<u8>, Vec<u8>), String> {
        let signer = provider.generate_signer()?;
        signer.store(provider.storage()).map_err(error)?;
        let mut builder = KeyPackage::builder().leaf_node_capabilities(bound_capabilities());
        if let Some(binding) = binding {
            let incarnation = encode_incarnation(
                &binding.group,
                name,
                generation,
                signer.public(),
                apf_signer,
            )?;
            builder = builder.leaf_node_extensions(
                Extensions::single(unknown_extension(INCARNATION_EXTENSION_TYPE, incarnation))
                    .map_err(error)?,
            );
        }
        let prepared = builder
            .prepare(
                CIPHERSUITE,
                provider,
                &signer,
                credential(name, &signer),
                APF_BINDING_EXTENSION_TYPE,
            )
            .map_err(error)?;
        let prepared_canonical = prepared.canonical_binding_bytes().to_vec();
        let certificate = issue_admission_certificate(
            GROUP_ID,
            name,
            generation,
            &prepared_canonical,
            apf_signer,
        )?;
        let key_package = prepared
            .with_external_binding(certificate)
            .map_err(error)?
            .finalize(provider, &signer)
            .map_err(error)?;
        let key_package_wire = key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(error)?;
        Ok((signer, key_package, key_package_wire, prepared_canonical))
    }
}

impl Endpoint {
    /// Runs `op` as one SQLite transaction. On failure the transaction rolls
    /// back and the in-memory group is reloaded from storage, so the in-memory
    /// group never runs ahead of the durable state.
    fn atomic<T>(&mut self, op: impl FnOnce(&mut Self) -> Result<T, String>) -> Result<T, String> {
        self.provider.begin()?;
        let result = op(self).and_then(|value| self.provider.commit().map(|()| value));
        if let Err(original) = &result {
            self.provider.rollback();
            if let Err(reload) = self.reload() {
                return Err(format!(
                    "{original}; reload after rollback failed: {reload}"
                ));
            }
        }
        result
    }

    fn reload(&mut self) -> Result<(), String> {
        let group_id = self.group.group_id().clone();
        self.group = MlsGroup::load(self.provider.storage(), &group_id)
            .map_err(error)?
            .ok_or_else(|| "group missing from storage".to_owned())?;
        Ok(())
    }

    fn process_commit_unchecked(&mut self, wire: &[u8]) -> Result<(), String> {
        let message = protocol_message(wire)?;
        let processed = self
            .group
            .process_message(&self.provider, message)
            .map_err(error)?;
        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(commit) => self
                .group
                .merge_staged_commit(&self.provider, *commit)
                .map_err(error),
            _ => Err("MLS commit did not stage".into()),
        }
    }

    /// Processes and merges a commit in one transaction; a bound endpoint
    /// commits only if the merged state passes the coherence check.
    fn process_commit(&mut self, wire: &[u8], binding: Option<&Binding>) -> Result<(), String> {
        self.atomic(|endpoint| {
            let parent_revision = binding.map(|binding| {
                acc_revision_of(&endpoint.group, &endpoint.provider.crypto, binding)
            });
            endpoint.process_commit_unchecked(wire)?;
            if let (Some(binding), Some(parent_revision)) = (binding, parent_revision) {
                check_coherence(
                    &endpoint.group,
                    &endpoint.provider.crypto,
                    binding,
                    Some(parent_revision),
                )?;
            }
            Ok(())
        })
    }

    /// Loads a durable endpoint from its state file, as a restarted process.
    fn load(
        state_file: PathBuf,
        signer_public: Option<&[u8]>,
        entropy: &EntropySource,
    ) -> Result<Self, String> {
        let provider = LabProvider::open_file(&state_file, entropy)?;
        let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(GROUP_ID))
            .map_err(error)?
            .ok_or_else(|| "group missing from state file".to_owned())?;
        let signer = match signer_public {
            Some(public) => Some(
                SignatureKeyPair::read(provider.storage(), public, SignatureScheme::ED25519)
                    .ok_or_else(|| "signing key missing from state file".to_owned())?,
            ),
            None => None,
        };
        Ok(Self {
            provider,
            group,
            signer,
            admission_key_package: None,
            prepared_canonical: None,
            state_file: Some(state_file),
            crash_before_commit: false,
        })
    }
}

/// A real OpenMLS group endpoint laboratory.
///
/// Endpoints share `Rc` SQLite connections with their storage providers, so the
/// laboratory is deliberately `!Send`.
pub struct MlsLab {
    roster: BTreeMap<String, Endpoint>,
    stale: BTreeMap<String, Endpoint>,
    offline: BTreeMap<String, OfflineEndpoint>,
    apf_signer: SignatureKeyPair,
    entropy: EntropySource,
    state_dir: Option<PathBuf>,
    binding: Option<Binding>,
}

/// Epochs observed when a durable member restarts: the epoch loaded from its
/// state file, and the epoch after redelivery of commits it missed while down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartReport {
    pub loaded_epoch: u64,
    pub caught_up_epoch: u64,
}

/// Evidence returned after independently validating an embedded admission binding.
#[derive(Debug)]
pub struct AdmissionBindingEvidence {
    pub subject: String,
    pub generation: u64,
    pub prepared_canonical: Vec<u8>,
    pub recomputed_canonical: Vec<u8>,
    pub certificate_preimage_hash: Vec<u8>,
    pub final_key_package: Vec<u8>,
}

impl MlsLab {
    /// Verifies retained admission evidence against an expected APF incarnation.
    pub fn verify_member_admission_for(
        &self,
        name: &str,
        expected_subject: &str,
        expected_generation: u64,
    ) -> Result<AdmissionBindingEvidence, String> {
        let endpoint = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let final_key_package = endpoint
            .admission_key_package
            .as_ref()
            .ok_or_else(|| "member has no staged admission evidence".to_owned())?;
        let prepared_canonical = endpoint
            .prepared_canonical
            .as_ref()
            .ok_or_else(|| "member has no prepared canonical bytes".to_owned())?;
        let verified = verify_admission_key_package(
            &endpoint.provider,
            final_key_package,
            expected_subject,
            expected_generation,
            &self.apf_signer.to_public_vec(),
        )?;
        if verified.recomputed_canonical != *prepared_canonical {
            return Err("prepared and recomputed KeyPackage bytes differ".into());
        }
        Ok(AdmissionBindingEvidence {
            subject: verified.subject,
            generation: verified.generation,
            prepared_canonical: prepared_canonical.clone(),
            recomputed_canonical: verified.recomputed_canonical,
            certificate_preimage_hash: verified.preimage_hash,
            final_key_package: final_key_package.clone(),
        })
    }

    /// Verifies the staged KeyPackage admission evidence retained for a member.
    pub fn verify_member_admission(&self, name: &str) -> Result<AdmissionBindingEvidence, String> {
        self.verify_member_admission_for(name, name, 0)
    }

    /// Creates the group with Alice as its founding member, using OS-seeded
    /// randomness and in-memory storage.
    pub fn new() -> Result<Self, String> {
        Self::with_entropy(EntropySource::Os)
    }

    /// Creates an in-memory laboratory drawing randomness from `source`.
    pub fn with_entropy(entropy: EntropySource) -> Result<Self, String> {
        Self::create(entropy, None, None)
    }

    /// Creates a durable laboratory: each endpoint keeps its OpenMLS state in
    /// `<dir>/<name>.sqlite`. Existing state files are never reused.
    pub fn open_durable(dir: &Path, entropy: EntropySource) -> Result<Self, String> {
        if !dir.is_dir() {
            return Err(format!("state directory missing: {}", dir.display()));
        }
        Self::create(entropy, Some(dir.to_path_buf()), None)
    }

    /// Creates a laboratory bound to APF group `apf_group`: the group context
    /// carries a signed `acc_context` (revision 0, roster `alice@0`), every leaf
    /// carries a signed `authz_incarnation`, and both are required capabilities.
    /// Membership changes then go only through [`MlsLab::transition`].
    pub fn create_bound(
        entropy: EntropySource,
        state_dir: Option<&Path>,
        apf_group: &str,
    ) -> Result<Self, String> {
        if let Some(dir) = state_dir {
            if !dir.is_dir() {
                return Err(format!("state directory missing: {}", dir.display()));
            }
        }
        ensure_name(apf_group)?;
        Self::create(
            entropy,
            state_dir.map(Path::to_path_buf),
            Some(apf_group.to_owned()),
        )
    }

    fn create(
        entropy: EntropySource,
        state_dir: Option<PathBuf>,
        apf_group: Option<String>,
    ) -> Result<Self, String> {
        let state_file = state_dir.as_ref().map(|dir| dir.join("alice.sqlite"));
        let provider = match &state_file {
            Some(path) => LabProvider::create_file(path, &entropy)?,
            None => LabProvider::in_memory(&entropy)?,
        };
        let founded = (|| {
            provider.begin()?;
            let signer = provider.generate_signer()?;
            let apf_signer = provider.generate_signer()?;
            signer.store(provider.storage()).map_err(error)?;
            let mut builder = MlsGroup::builder()
                .with_group_id(GroupId::from_slice(GROUP_ID))
                .use_ratchet_tree_extension(true);
            let binding = match &apf_group {
                None => None,
                Some(group) => {
                    let binding = Binding {
                        group: group.clone(),
                        apf_public: apf_signer.to_public_vec(),
                    };
                    let incarnation =
                        encode_incarnation(group, "alice", 0, signer.public(), &apf_signer)?;
                    let acc = encode_acc_context(group, 0, &[("alice".into(), 0)], &apf_signer)?;
                    builder = builder
                        .with_capabilities(bound_capabilities())
                        .with_leaf_node_extensions(
                            Extensions::single(unknown_extension(
                                INCARNATION_EXTENSION_TYPE,
                                incarnation,
                            ))
                            .map_err(error)?,
                        )
                        .map_err(error)?
                        .with_group_context_extensions(bound_group_context_extensions(acc)?);
                    Some(binding)
                }
            };
            let group = builder
                .build(&provider, &signer, credential("alice", &signer))
                .map_err(error)?;
            if let Some(binding) = &binding {
                check_coherence(&group, &provider.crypto, binding, None)?;
            }
            provider.commit()?;
            Ok::<_, String>((signer, apf_signer, group, binding))
        })();
        let (signer, apf_signer, group, binding) = match founded {
            Ok(founded) => founded,
            Err(failure) => {
                provider.rollback();
                drop(provider);
                if let Some(path) = &state_file {
                    discard_state_file(path);
                }
                return Err(failure);
            }
        };
        Ok(Self {
            roster: BTreeMap::from([(
                "alice".to_owned(),
                Endpoint {
                    provider,
                    group,
                    signer: Some(signer),
                    admission_key_package: None,
                    prepared_canonical: None,
                    state_file,
                    crash_before_commit: false,
                },
            )]),
            stale: BTreeMap::new(),
            offline: BTreeMap::new(),
            apf_signer,
            entropy,
            state_dir,
            binding,
        })
    }

    fn name_in_use(&self, name: &str) -> bool {
        self.roster.contains_key(name)
            || self.stale.contains_key(name)
            || self.offline.contains_key(name)
    }

    /// The state file a new durable endpoint would use; refuses existing files.
    fn new_state_path(&self, name: &str) -> Result<Option<PathBuf>, String> {
        let Some(dir) = &self.state_dir else {
            return Ok(None);
        };
        let path = dir.join(format!("{name}.sqlite"));
        if path.exists() {
            return Err(format!("state file already exists: {}", path.display()));
        }
        Ok(Some(path))
    }

    /// Delivers a commit to every current member except `skip`, and queues it
    /// for offline members. A member armed with `arm_crash_before_commit` dies
    /// after OpenMLS has written the successor state but before COMMIT; it
    /// becomes offline and does not block the others.
    fn deliver_commit(&mut self, wire: &[u8], skip: &[&str]) -> Result<(), String> {
        let binding = self.binding.clone();
        for offline in self.offline.values_mut() {
            offline.pending_commits.push(wire.to_vec());
        }
        let names: Vec<String> = self
            .roster
            .keys()
            .filter(|name| !skip.contains(&name.as_str()))
            .cloned()
            .collect();
        for name in names {
            let endpoint = self.roster.get_mut(&name).expect("listed member");
            if !endpoint.crash_before_commit {
                endpoint.process_commit(wire, binding.as_ref())?;
                continue;
            }
            endpoint.provider.begin()?;
            if let Err(failure) = endpoint.process_commit_unchecked(wire) {
                endpoint.provider.rollback();
                endpoint.reload()?;
                return Err(failure);
            }
            // Simulated process death: the connection closes with the
            // transaction still open, so SQLite discards the uncommitted writes.
            let endpoint = self.roster.remove(&name).expect("listed member");
            let offline = OfflineEndpoint {
                state_file: endpoint
                    .state_file
                    .clone()
                    .ok_or_else(|| "crash injection requires durable state".to_owned())?,
                signer_public: endpoint
                    .signer
                    .as_ref()
                    .ok_or_else(|| "crashed member has no signing key".to_owned())?
                    .to_public_vec(),
                admission_key_package: endpoint.admission_key_package.clone(),
                prepared_canonical: endpoint.prepared_canonical.clone(),
                pending_commits: vec![wire.to_vec()],
            };
            drop(endpoint);
            self.offline.insert(name, offline);
        }
        Ok(())
    }

    /// Adds a member using a KeyPackage and makes every continuing member merge
    /// the authenticated commit; the new member joins from its Welcome.
    pub fn add_member(&mut self, name: &str) -> Result<(), String> {
        self.ensure_unbound()?;
        ensure_name(name)?;
        if self.name_in_use(name) {
            return Err("member name already used".into());
        }
        let state_file = self.new_state_path(name)?;
        let result = self.add_member_inner(name, state_file.as_deref());
        if result.is_err() && !self.name_in_use(name) {
            if let Some(path) = &state_file {
                discard_state_file(path);
            }
        }
        result
    }

    fn add_member_inner(&mut self, name: &str, state_file: Option<&Path>) -> Result<(), String> {
        let joiner =
            PendingMember::new(name, 0, &self.apf_signer, &self.entropy, state_file, None)?;
        let verified = verify_admission_key_package(
            &joiner.provider,
            &joiner.key_package_wire,
            name,
            0,
            &self.apf_signer.to_public_vec(),
        )?;
        if verified.recomputed_canonical != joiner.prepared_canonical {
            return Err("prepared and recomputed KeyPackage bytes differ".into());
        }
        let key_package = joiner.key_package.key_package().clone();
        let (commit_wire, welcome) = self
            .roster
            .get_mut("alice")
            .ok_or_else(|| "alice endpoint unavailable".to_owned())?
            .atomic(|committer| {
                let signer = committer
                    .signer
                    .as_ref()
                    .ok_or_else(|| "committer has no signing key".to_owned())?;
                let (commit, welcome, _) = committer
                    .group
                    .add_members(&committer.provider, signer, &[key_package])
                    .map_err(error)?;
                let commit_wire = commit.tls_serialize_detached().map_err(error)?;
                committer
                    .group
                    .merge_pending_commit(&committer.provider)
                    .map_err(error)?;
                Ok((commit_wire, welcome))
            })?;

        self.deliver_commit(&commit_wire, &["alice"])?;

        let welcome = welcome_from_out(welcome)?;
        joiner.provider.begin()?;
        let joined = StagedWelcome::new_from_welcome(
            &joiner.provider,
            &MlsGroupJoinConfig::default(),
            welcome,
            None,
        )
        .and_then(|staged| staged.into_group(&joiner.provider))
        .map_err(error);
        let group = match joined.and_then(|group| joiner.provider.commit().map(|()| group)) {
            Ok(group) => group,
            Err(failure) => {
                joiner.provider.rollback();
                return Err(failure);
            }
        };
        self.roster.insert(
            name.to_owned(),
            Endpoint {
                provider: joiner.provider,
                group,
                signer: Some(joiner.signer),
                admission_key_package: Some(joiner.key_package_wire),
                prepared_canonical: Some(joiner.prepared_canonical),
                state_file: state_file.map(Path::to_path_buf),
                crash_before_commit: false,
            },
        );
        Ok(())
    }

    /// Encrypts an application message with authenticated data using a current
    /// MLS member's sender ratchet.
    pub fn protect(&mut self, sender: &str, payload: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        if self.offline.contains_key(sender) {
            return Err("sender is offline".into());
        }
        self.roster
            .get_mut(sender)
            .ok_or_else(|| "sender is not a current member".to_owned())?
            .atomic(|endpoint| {
                let signer = endpoint
                    .signer
                    .as_ref()
                    .ok_or_else(|| "sender has no signing key".to_owned())?;
                endpoint.group.set_aad(aad.to_vec());
                endpoint
                    .group
                    .create_message(&endpoint.provider, signer, payload)
                    .map_err(error)?
                    .tls_serialize_detached()
                    .map_err(error)
            })
    }

    /// Processes an MLS wire message with the requested endpoint's retained
    /// state.  Stale endpoints deliberately take this same real MLS path.
    pub fn decrypt(&mut self, recipient: &str, wire: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        if self.offline.contains_key(recipient) {
            return Err("recipient is offline".into());
        }
        self.roster
            .get_mut(recipient)
            .or_else(|| self.stale.get_mut(recipient))
            .ok_or_else(|| "unknown recipient".to_owned())?
            .atomic(|endpoint| {
                let message = protocol_message(wire)?;
                let processed = endpoint
                    .group
                    .process_message(&endpoint.provider, message)
                    .map_err(error)?;
                let aad = processed.aad().to_vec();
                match processed.into_content() {
                    ProcessedMessageContent::ApplicationMessage(message) => {
                        Ok((message.into_bytes(), aad))
                    }
                    _ => Err("MLS message was not application data".into()),
                }
            })
    }

    /// Removes a current member with a real MLS Remove commit.  Every continuing
    /// endpoint processes and merges the resulting confirmed commit.  The
    /// removed endpoint is retained as stale state only for decryption attacks.
    pub fn remove_member(&mut self, name: &str) -> Result<(), String> {
        self.ensure_unbound()?;
        if self.offline.contains_key(name) {
            return Err("member is offline".into());
        }
        if !self.roster.contains_key(name) {
            return Err("member is not current".into());
        }
        if self.roster.len() < 2 {
            return Err("cannot remove the only member".into());
        }
        let committer_name = self
            .roster
            .keys()
            .find(|candidate| candidate.as_str() != name)
            .cloned()
            .ok_or_else(|| "no continuing committer".to_owned())?;
        let removed_index = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?
            .group
            .own_leaf_index();

        let commit_wire = self
            .roster
            .get_mut(&committer_name)
            .expect("selected committer")
            .atomic(|committer| {
                let signer = committer
                    .signer
                    .as_ref()
                    .ok_or_else(|| "committer has no signing key".to_owned())?;
                let (commit, _, _) = committer
                    .group
                    .remove_members(&committer.provider, signer, &[removed_index])
                    .map_err(error)?;
                let commit_wire = commit.tls_serialize_detached().map_err(error)?;
                committer
                    .group
                    .merge_pending_commit(&committer.provider)
                    .map_err(error)?;
                Ok(commit_wire)
            })?;

        self.deliver_commit(&commit_wire, &[committer_name.as_str(), name])?;

        let removed = self.roster.remove(name).expect("checked current member");
        self.stale.insert(name.to_owned(), removed);
        Ok(())
    }

    /// Copies a member's stored group state and secret storage to a distinct
    /// stale in-memory endpoint.  This is intentionally outside the active roster.
    pub fn snapshot_member(&mut self, name: &str, snapshot_name: &str) -> Result<(), String> {
        ensure_name(snapshot_name)?;
        if self.name_in_use(snapshot_name) {
            return Err("snapshot name already used".into());
        }
        let original = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let provider = original.provider.snapshot(&self.entropy)?;
        let group_id = original.group.group_id().clone();
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(error)?
            .ok_or_else(|| "snapshot group missing from copied storage".to_owned())?;
        let endpoint = Endpoint {
            provider,
            group,
            signer: None,
            admission_key_package: original.admission_key_package.clone(),
            prepared_canonical: original.prepared_canonical.clone(),
            state_file: None,
            crash_before_commit: false,
        };
        self.stale.insert(snapshot_name.to_owned(), endpoint);
        Ok(())
    }

    /// Byte-for-byte copy of a current member's quiescent state file, opened in
    /// a fresh connection as a stale endpoint outside the roster. Every
    /// laboratory operation commits or rolls back before returning, so no
    /// transaction is open while the copy is taken.
    pub fn retain_storage_copy(&mut self, name: &str, copy_name: &str) -> Result<(), String> {
        ensure_name(copy_name)?;
        if self.name_in_use(copy_name) {
            return Err("copy name already used".into());
        }
        let original = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let source = original
            .state_file
            .clone()
            .ok_or_else(|| "member has no durable state".to_owned())?;
        let target = self
            .new_state_path(copy_name)?
            .ok_or_else(|| "member has no durable state".to_owned())?;
        let admission_key_package = original.admission_key_package.clone();
        let prepared_canonical = original.prepared_canonical.clone();
        std::fs::copy(&source, &target).map_err(error)?;
        let mut endpoint = Endpoint::load(target, None, &self.entropy)?;
        endpoint.admission_key_package = admission_key_package;
        endpoint.prepared_canonical = prepared_canonical;
        self.stale.insert(copy_name.to_owned(), endpoint);
        Ok(())
    }

    /// Arms a fault: the member's next commit processing writes the successor
    /// state and then dies before the durable COMMIT.
    pub fn arm_crash_before_commit(&mut self, name: &str) -> Result<(), String> {
        let endpoint = self
            .roster
            .get_mut(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        if endpoint.state_file.is_none() {
            return Err("crash injection requires durable state".into());
        }
        endpoint.crash_before_commit = true;
        Ok(())
    }

    /// Restarts a durable member: all in-memory state is dropped, the group and
    /// signing key are reloaded from its state file, and commits it missed while
    /// offline are redelivered.
    pub fn restart_member(&mut self, name: &str) -> Result<RestartReport, String> {
        let mut offline = if let Some(offline) = self.offline.remove(name) {
            offline
        } else {
            let endpoint = self
                .roster
                .get(name)
                .ok_or_else(|| "member is not current".to_owned())?;
            let state_file = endpoint
                .state_file
                .clone()
                .ok_or_else(|| "member has no durable state".to_owned())?;
            let signer_public = endpoint
                .signer
                .as_ref()
                .ok_or_else(|| "member has no signing key".to_owned())?
                .to_public_vec();
            let endpoint = self.roster.remove(name).expect("checked current member");
            let offline = OfflineEndpoint {
                state_file,
                signer_public,
                admission_key_package: endpoint.admission_key_package.clone(),
                prepared_canonical: endpoint.prepared_canonical.clone(),
                pending_commits: Vec::new(),
            };
            drop(endpoint);
            offline
        };

        let restarted = (|| {
            let mut endpoint = Endpoint::load(
                offline.state_file.clone(),
                Some(&offline.signer_public),
                &self.entropy,
            )?;
            endpoint.admission_key_package = offline.admission_key_package.clone();
            endpoint.prepared_canonical = offline.prepared_canonical.clone();
            let loaded_epoch = endpoint.group.epoch().as_u64();
            for wire in &offline.pending_commits {
                endpoint.process_commit(wire, self.binding.as_ref())?;
            }
            Ok::<_, String>((endpoint, loaded_epoch))
        })();
        match restarted {
            Ok((endpoint, loaded_epoch)) => {
                let caught_up_epoch = endpoint.group.epoch().as_u64();
                self.roster.insert(name.to_owned(), endpoint);
                Ok(RestartReport {
                    loaded_epoch,
                    caught_up_epoch,
                })
            }
            Err(failure) => {
                offline.pending_commits.shrink_to_fit();
                self.offline.insert(name.to_owned(), offline);
                Err(failure)
            }
        }
    }

    /// The state file of a durable current, stale, or offline endpoint.
    pub fn state_file(&self, name: &str) -> Option<PathBuf> {
        self.roster
            .get(name)
            .or_else(|| self.stale.get(name))
            .and_then(|endpoint| endpoint.state_file.clone())
            .or_else(|| {
                self.offline
                    .get(name)
                    .map(|offline| offline.state_file.clone())
            })
    }

    /// Returns a current or stale endpoint's MLS signature public key.
    pub fn member_signature_key(&self, name: &str) -> Option<Vec<u8>> {
        self.roster
            .get(name)
            .or_else(|| self.stale.get(name))
            .and_then(|endpoint| endpoint.group.own_leaf_node())
            .map(|leaf| leaf.signature_key().as_slice().to_vec())
    }

    /// Returns the epoch held by a current or stale endpoint.
    pub fn member_epoch(&self, name: &str) -> Option<u64> {
        self.roster
            .get(name)
            .or_else(|| self.stale.get(name))
            .map(|endpoint| endpoint.group.epoch().as_u64())
    }

    fn ensure_unbound(&self) -> Result<(), String> {
        if self.binding.is_some() {
            Err("bound laboratory: membership changes go through the LAP adapter".into())
        } else {
            Ok(())
        }
    }

    fn require_binding(&self) -> Result<Binding, String> {
        self.binding
            .clone()
            .ok_or_else(|| "operation requires a bound laboratory".to_owned())
    }

    /// Performs one bound membership transition as a single regular commit
    /// with a forced UpdatePath and an `acc_context` GroupContextExtensions
    /// proposal. Inside the committer's SQLite transaction the commit is
    /// staged, merged, coherence-checked, and its evidence handed to
    /// `canonicalize` (the APF compare-and-swap). If `canonicalize` fails the
    /// committer rolls back to the parent epoch. Only after it succeeds is the
    /// commit delivered and the Welcome processed.
    pub fn transition<T>(
        &mut self,
        committer: &str,
        spec: TransitionSpec<'_>,
        canonicalize: impl FnOnce(&TransitionEvidence) -> Result<T, String>,
    ) -> Result<T, String> {
        let binding = self.require_binding()?;
        if !self.roster.contains_key(committer) {
            return Err("committer is not a current online member".into());
        }
        if spec.remove.contains(&committer) {
            return Err("a committer cannot remove itself".into());
        }
        let joiner_file = match spec.add {
            Some((subject, generation)) => {
                ensure_name(subject)?;
                if self.roster.contains_key(subject) || self.offline.contains_key(subject) {
                    return Err("member name already used".into());
                }
                // A removed earlier incarnation of the subject stays available
                // as a retired stale endpoint; its state file is never reused.
                self.retire_stale(subject);
                self.new_state_path(&format!("{subject}-g{generation}"))?
            }
            None => None,
        };
        let result = self.transition_inner(
            committer,
            &spec,
            &binding,
            joiner_file.as_deref(),
            canonicalize,
        );
        if result.is_err() {
            if let (Some((subject, _)), Some(path)) = (spec.add, &joiner_file) {
                if !self.name_in_use(subject) {
                    discard_state_file(path);
                }
            }
        }
        result
    }

    fn transition_inner<T>(
        &mut self,
        committer: &str,
        spec: &TransitionSpec<'_>,
        binding: &Binding,
        joiner_file: Option<&Path>,
        canonicalize: impl FnOnce(&TransitionEvidence) -> Result<T, String>,
    ) -> Result<T, String> {
        let joiner = match spec.add {
            Some((subject, generation)) => {
                let joiner = PendingMember::new(
                    subject,
                    generation,
                    &self.apf_signer,
                    &self.entropy,
                    joiner_file,
                    Some(binding),
                )?;
                let verified = verify_admission_key_package(
                    &joiner.provider,
                    &joiner.key_package_wire,
                    subject,
                    generation,
                    &self.apf_signer.to_public_vec(),
                )?;
                if verified.recomputed_canonical != joiner.prepared_canonical {
                    return Err("prepared and recomputed KeyPackage bytes differ".into());
                }
                Some(joiner)
            }
            None => None,
        };
        let acc = encode_acc_context(
            &binding.group,
            spec.acc_revision,
            &spec.acc_roster,
            &self.apf_signer,
        )?;
        let extensions = bound_group_context_extensions(acc)?;
        let key_package = joiner
            .as_ref()
            .map(|joiner| joiner.key_package.key_package().clone());
        let removals: Vec<String> = spec.remove.iter().map(|name| (*name).to_owned()).collect();

        let (out, commit_wire, welcome, removed) = self
            .roster
            .get_mut(committer)
            .expect("checked committer")
            .atomic(|c| {
                let parent = MlsFrontier::of(c.group.public_group().group_context());
                let parent_revision = acc_revision_of(&c.group, &c.provider.crypto, binding);
                let subjects = leaf_subjects(&c.group, &c.provider.crypto, binding)?;
                let indices = leaf_indices(&subjects, &removals)?;
                let signer = c
                    .signer
                    .as_ref()
                    .ok_or_else(|| "committer has no signing key".to_owned())?;
                let bundle = c
                    .group
                    .commit_builder()
                    .propose_adds(key_package)
                    .propose_removals(indices)
                    .propose_group_context_extensions(extensions)
                    .map_err(error)?
                    .force_self_update(true)
                    .load_psks(c.provider.storage())
                    .map_err(error)?
                    .build(c.provider.rand(), c.provider.crypto(), signer, |_| true)
                    .map_err(error)?
                    .stage_commit(&c.provider)
                    .map_err(error)?;
                let commit = bundle.commit().tls_serialize_detached().map_err(error)?;
                let welcome = bundle.to_welcome_msg();
                let pending = c
                    .group
                    .pending_commit()
                    .ok_or_else(|| "commit was not staged".to_owned())?;
                let update_path = pending.update_path_leaf_node().is_some();
                let removed = pending
                    .remove_proposals()
                    .map(|proposal| {
                        subjects
                            .get(&proposal.remove_proposal().removed())
                            .cloned()
                            .ok_or_else(|| "removed leaf has no incarnation".to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let mut added = pending
                    .add_proposals()
                    .map(|proposal| {
                        leaf_incarnation(
                            proposal.add_proposal().key_package().leaf_node(),
                            &c.provider.crypto,
                            binding,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                if added.len() > 1 {
                    return Err("a transition admits at most one member".into());
                }
                let staged = MlsFrontier::of(pending.group_context());
                c.group.merge_pending_commit(&c.provider).map_err(error)?;
                check_coherence(&c.group, &c.provider.crypto, binding, Some(parent_revision))?;
                let (acc_revision, acc_roster) =
                    read_acc_context(&c.group, &c.provider.crypto, binding)?;
                let successor = MlsFrontier::of(c.group.public_group().group_context());
                if successor != staged {
                    return Err("staged and merged frontiers differ".into());
                }
                let evidence = TransitionEvidence {
                    parent,
                    successor,
                    removed: removed.clone(),
                    added: added.pop(),
                    update_path,
                    acc_revision,
                    acc_roster,
                    commit: commit.clone(),
                };
                let out = canonicalize(&evidence)?;
                Ok((out, commit, welcome, removed))
            })?;

        let mut skip = vec![committer];
        skip.extend(removed.iter().map(String::as_str));
        self.deliver_commit(&commit_wire, &skip)?;
        for name in &removed {
            if let Some(endpoint) = self.roster.remove(name) {
                self.stale.insert(name.clone(), endpoint);
            }
            self.offline.remove(name);
        }

        if let (Some(joiner), Some((subject, _))) = (joiner, spec.add) {
            let welcome = welcome_from_out(
                welcome.ok_or_else(|| "Add commit produced no Welcome".to_owned())?,
            )?;
            joiner.provider.begin()?;
            let joined = StagedWelcome::new_from_welcome(
                &joiner.provider,
                &MlsGroupJoinConfig::default(),
                welcome,
                None,
            )
            .and_then(|staged| staged.into_group(&joiner.provider))
            .map_err(error)
            .and_then(|group| {
                check_coherence(&group, &joiner.provider.crypto, binding, None)?;
                Ok(group)
            })
            .and_then(|group| joiner.provider.commit().map(|()| group));
            let group = match joined {
                Ok(group) => group,
                Err(failure) => {
                    joiner.provider.rollback();
                    return Err(failure);
                }
            };
            self.roster.insert(
                subject.to_owned(),
                Endpoint {
                    provider: joiner.provider,
                    group,
                    signer: Some(joiner.signer),
                    admission_key_package: Some(joiner.key_package_wire),
                    prepared_canonical: Some(joiner.prepared_canonical),
                    state_file: joiner_file.map(Path::to_path_buf),
                    crash_before_commit: false,
                },
            );
        }
        Ok(out)
    }

    /// Adversary model: a compromised member endpoint creates a commit that
    /// bypasses the APF and the adapter, carrying arbitrary `acc_context` bytes
    /// and removals. The rogue member does not install it; the returned commit
    /// can be offered to honest members with [`MlsLab::process_commit_as`].
    pub fn adversarial_commit(
        &mut self,
        committer: &str,
        acc_context: Vec<u8>,
        remove: &[&str],
    ) -> Result<Vec<u8>, String> {
        let binding = self.require_binding()?;
        let removals: Vec<String> = remove.iter().map(|name| (*name).to_owned()).collect();
        self.roster
            .get_mut(committer)
            .ok_or_else(|| "committer is not a current member".to_owned())?
            .atomic(|c| {
                let subjects = leaf_subjects(&c.group, &c.provider.crypto, &binding)?;
                let indices = leaf_indices(&subjects, &removals)?;
                let signer = c
                    .signer
                    .as_ref()
                    .ok_or_else(|| "committer has no signing key".to_owned())?;
                let bundle = c
                    .group
                    .commit_builder()
                    .propose_removals(indices)
                    .propose_group_context_extensions(bound_group_context_extensions(acc_context)?)
                    .map_err(error)?
                    .force_self_update(true)
                    .load_psks(c.provider.storage())
                    .map_err(error)?
                    .build(c.provider.rand(), c.provider.crypto(), signer, |_| true)
                    .map_err(error)?
                    .stage_commit(&c.provider)
                    .map_err(error)?;
                let wire = bundle.commit().tls_serialize_detached().map_err(error)?;
                c.group
                    .clear_pending_commit(c.provider.storage())
                    .map_err(error)?;
                Ok(wire)
            })
    }

    /// Offers a commit to one current member, which processes it with the
    /// same transactional, coherence-checked path used for honest delivery.
    pub fn process_commit_as(&mut self, member: &str, wire: &[u8]) -> Result<(), String> {
        let binding = self.binding.clone();
        self.roster
            .get_mut(member)
            .ok_or_else(|| "member is not current".to_owned())?
            .process_commit(wire, binding.as_ref())
    }

    /// Signs an `acc_context` with the laboratory APF key (adversarial tests
    /// use it to build honestly signed but stale or incoherent bindings).
    ///
    /// # Panics
    /// Panics if the laboratory is not bound.
    pub fn sign_acc_context(&self, revision: u64, roster: &[(&str, u64)]) -> Vec<u8> {
        let binding = self.binding.as_ref().expect("bound laboratory");
        let roster: Vec<(String, u64)> = roster
            .iter()
            .map(|(subject, generation)| ((*subject).to_owned(), *generation))
            .collect();
        encode_acc_context(&binding.group, revision, &roster, &self.apf_signer)
            .expect("encode acc_context")
    }

    fn retire_stale(&mut self, subject: &str) {
        if let Some(endpoint) = self.stale.remove(subject) {
            let retired = (0..)
                .map(|k| format!("{subject}-retired-{k}"))
                .find(|name| !self.name_in_use(name))
                .expect("unbounded names");
            self.stale.insert(retired, endpoint);
        }
    }

    /// Client rollback: replaces a durable member's state file with an earlier
    /// byte copy (taken with [`MlsLab::retain_storage_copy`]) and restarts the
    /// member from it. The APF must not trust the rolled-back client state.
    pub fn restore_member_from(&mut self, name: &str, copy_name: &str) -> Result<(), String> {
        let copy_file = self
            .stale
            .get(copy_name)
            .and_then(|endpoint| endpoint.state_file.clone())
            .ok_or_else(|| "copy has no durable state".to_owned())?;
        let endpoint = self
            .roster
            .get(name)
            .ok_or_else(|| "member is not current".to_owned())?;
        let state_file = endpoint
            .state_file
            .clone()
            .ok_or_else(|| "member has no durable state".to_owned())?;
        let signer_public = endpoint
            .signer
            .as_ref()
            .ok_or_else(|| "member has no signing key".to_owned())?
            .to_public_vec();
        let endpoint = self.roster.remove(name).expect("checked current member");
        let admission_key_package = endpoint.admission_key_package.clone();
        let prepared_canonical = endpoint.prepared_canonical.clone();
        drop(endpoint);
        std::fs::copy(&copy_file, &state_file).map_err(error)?;
        let mut restored = Endpoint::load(state_file, Some(&signer_public), &self.entropy)?;
        restored.admission_key_package = admission_key_package;
        restored.prepared_canonical = prepared_canonical;
        self.roster.insert(name.to_owned(), restored);
        Ok(())
    }

    fn endpoint(&self, name: &str) -> Option<&Endpoint> {
        self.roster.get(name).or_else(|| self.stale.get(name))
    }

    /// The verified `acc_context` installed at a member: `(revision, roster)`.
    pub fn acc_context(&self, name: &str) -> Option<(u64, Vec<(String, u64)>)> {
        let binding = self.binding.as_ref()?;
        let endpoint = self.endpoint(name)?;
        read_acc_context(&endpoint.group, &endpoint.provider.crypto, binding).ok()
    }

    /// Verified leaf incarnations of the ratchet tree held by a member.
    pub fn incarnations(&self, name: &str) -> Vec<(String, u64)> {
        let (Some(binding), Some(endpoint)) = (self.binding.as_ref(), self.endpoint(name)) else {
            return Vec::new();
        };
        endpoint
            .group
            .members()
            .filter_map(|member| endpoint.group.public_group().leaf(member.index))
            .filter_map(|leaf| leaf_incarnation(leaf, &endpoint.provider.crypto, binding).ok())
            .collect()
    }

    /// The MLS frontier installed at an online current or stale endpoint.
    pub fn frontier(&self, name: &str) -> Option<MlsFrontier> {
        self.endpoint(name)
            .map(|endpoint| MlsFrontier::of(endpoint.group.public_group().group_context()))
    }

    pub(crate) fn apf_sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        self.apf_signer.sign(message).map_err(error)
    }

    pub(crate) fn apf_verify(&self, message: &[u8], signature: &[u8]) -> bool {
        RustCrypto::default()
            .verify_signature(
                SignatureScheme::ED25519,
                message,
                &self.apf_signer.to_public_vec(),
                signature,
            )
            .is_ok()
    }

    pub fn epoch(&self) -> u64 {
        self.roster
            .values()
            .next()
            .map(|endpoint| endpoint.group.epoch().as_u64())
            .unwrap_or(0)
    }

    /// Current MLS members, including durable members that are offline.
    pub fn members(&self) -> Vec<String> {
        let mut members: Vec<String> = self
            .roster
            .keys()
            .chain(self.offline.keys())
            .cloned()
            .collect();
        members.sort();
        members
    }
}

/// APF binding of a laboratory created with [`MlsLab::create_bound`].
#[derive(Clone)]
struct Binding {
    group: String,
    apf_public: Vec<u8>,
}

/// MLS epoch identity used as the APF canonical frontier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlsFrontier {
    pub epoch: u64,
    pub tree_hash: Vec<u8>,
    pub confirmed_transcript_hash: Vec<u8>,
}

impl MlsFrontier {
    fn of(context: &GroupContext) -> Self {
        Self {
            epoch: context.epoch().as_u64(),
            tree_hash: context.tree_hash().to_vec(),
            confirmed_transcript_hash: context.confirmed_transcript_hash().to_vec(),
        }
    }
}

/// What a bound membership transition must contain.
pub struct TransitionSpec<'a> {
    /// A joining subject and its APF read generation.
    pub add: Option<(&'a str, u64)>,
    /// Subjects to remove, identified through their leaf incarnations.
    pub remove: &'a [&'a str],
    pub acc_revision: u64,
    pub acc_roster: Vec<(String, u64)>,
}

/// Evidence derived from the real staged and merged commit, handed to the APF.
#[derive(Clone, Debug)]
pub struct TransitionEvidence {
    pub parent: MlsFrontier,
    pub successor: MlsFrontier,
    /// Subjects of the commit's actual Remove proposals (via leaf incarnations).
    pub removed: Vec<String>,
    /// Incarnation of the commit's actual Add proposal, if any.
    pub added: Option<(String, u64)>,
    pub update_path: bool,
    /// `acc_context` installed by the merged commit.
    pub acc_revision: u64,
    pub acc_roster: Vec<(String, u64)>,
    pub commit: Vec<u8>,
}

fn unknown_extension(extension_type: u16, bytes: Vec<u8>) -> Extension {
    Extension::Unknown(extension_type, UnknownExtension(bytes))
}

fn bound_capabilities() -> Capabilities {
    Capabilities::builder()
        .extensions(vec![
            ExtensionType::Unknown(APF_BINDING_EXTENSION_TYPE),
            ExtensionType::Unknown(ACC_CONTEXT_EXTENSION_TYPE),
            ExtensionType::Unknown(INCARNATION_EXTENSION_TYPE),
        ])
        .build()
}

fn bound_group_context_extensions(
    acc_context: Vec<u8>,
) -> Result<Extensions<GroupContext>, String> {
    Extensions::from_vec(vec![
        unknown_extension(ACC_CONTEXT_EXTENSION_TYPE, acc_context),
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[
                ExtensionType::Unknown(ACC_CONTEXT_EXTENSION_TYPE),
                ExtensionType::Unknown(INCARNATION_EXTENSION_TYPE),
            ],
            &[],
            &[],
        )),
    ])
    .map_err(error)
}

pub(crate) fn sorted_roster(roster: &[(String, u64)]) -> Vec<(String, u64)> {
    let mut roster = roster.to_vec();
    roster.sort();
    roster
}

/// `acc_context`: APF-signed policy revision and `(subject, generation)` roster.
fn encode_acc_context(
    group: &str,
    revision: u64,
    roster: &[(String, u64)],
    signer: &impl Signer,
) -> Result<Vec<u8>, String> {
    let roster = sorted_roster(roster);
    let mut payload = ACC_CONTEXT_MAGIC.to_vec();
    payload.push(BINDING_VERSION);
    append_sized(&mut payload, group.as_bytes())?;
    payload.extend_from_slice(&revision.to_be_bytes());
    let count = u16::try_from(roster.len()).map_err(|_| "acc_context roster too large")?;
    payload.extend_from_slice(&count.to_be_bytes());
    for (subject, generation) in &roster {
        append_sized(&mut payload, subject.as_bytes())?;
        payload.extend_from_slice(&generation.to_be_bytes());
    }
    let signature = signer.sign(&payload).map_err(error)?;
    append_sized(&mut payload, &signature)?;
    Ok(payload)
}

fn decode_acc_context(
    bytes: &[u8],
    crypto: &impl OpenMlsCrypto,
    apf_public: &[u8],
) -> Result<(String, u64, Vec<(String, u64)>), String> {
    let mut input = bytes;
    if take(&mut input, ACC_CONTEXT_MAGIC.len())? != ACC_CONTEXT_MAGIC
        || take(&mut input, 1)?[0] != BINDING_VERSION
    {
        return Err("invalid acc_context header".into());
    }
    let group = utf8(take_sized(&mut input)?)?;
    let revision = take_u64(&mut input)?;
    let count = u16::from_be_bytes(
        take(&mut input, 2)?
            .try_into()
            .map_err(|_| "invalid acc_context roster")?,
    );
    let mut roster = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let subject = utf8(take_sized(&mut input)?)?;
        roster.push((subject, take_u64(&mut input)?));
    }
    let signed_len = bytes.len() - input.len();
    let signature = take_sized(&mut input)?;
    if !input.is_empty() {
        return Err("trailing acc_context bytes".into());
    }
    crypto
        .verify_signature(
            SignatureScheme::ED25519,
            &bytes[..signed_len],
            apf_public,
            signature,
        )
        .map_err(|_| "invalid acc_context signature".to_owned())?;
    Ok((group, revision, roster))
}

/// `authz_incarnation`: APF-signed subject, generation, and leaf signature key.
fn encode_incarnation(
    group: &str,
    subject: &str,
    generation: u64,
    signature_key: &[u8],
    signer: &impl Signer,
) -> Result<Vec<u8>, String> {
    let mut payload = INCARNATION_MAGIC.to_vec();
    payload.push(BINDING_VERSION);
    append_sized(&mut payload, group.as_bytes())?;
    append_sized(&mut payload, subject.as_bytes())?;
    payload.extend_from_slice(&generation.to_be_bytes());
    append_sized(&mut payload, signature_key)?;
    let signature = signer.sign(&payload).map_err(error)?;
    append_sized(&mut payload, &signature)?;
    Ok(payload)
}

fn decode_incarnation(
    bytes: &[u8],
    crypto: &impl OpenMlsCrypto,
    apf_public: &[u8],
) -> Result<(String, String, u64, Vec<u8>), String> {
    let mut input = bytes;
    if take(&mut input, INCARNATION_MAGIC.len())? != INCARNATION_MAGIC
        || take(&mut input, 1)?[0] != BINDING_VERSION
    {
        return Err("invalid authz_incarnation header".into());
    }
    let group = utf8(take_sized(&mut input)?)?;
    let subject = utf8(take_sized(&mut input)?)?;
    let generation = take_u64(&mut input)?;
    let signature_key = take_sized(&mut input)?.to_vec();
    let signed_len = bytes.len() - input.len();
    let signature = take_sized(&mut input)?;
    if !input.is_empty() {
        return Err("trailing authz_incarnation bytes".into());
    }
    crypto
        .verify_signature(
            SignatureScheme::ED25519,
            &bytes[..signed_len],
            apf_public,
            signature,
        )
        .map_err(|_| "invalid authz_incarnation signature".to_owned())?;
    Ok((group, subject, generation, signature_key))
}

fn take_u64(input: &mut &[u8]) -> Result<u64, String> {
    Ok(u64::from_be_bytes(
        take(input, 8)?
            .try_into()
            .map_err(|_| "invalid u64 field".to_owned())?,
    ))
}

fn utf8(bytes: &[u8]) -> Result<String, String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| "field is not UTF-8".to_owned())
}

/// Verified incarnation `(subject, generation)` of a leaf; the subject must be
/// the leaf credential's identity and the key the leaf's signature key.
fn leaf_incarnation(
    leaf: &LeafNode,
    crypto: &impl OpenMlsCrypto,
    binding: &Binding,
) -> Result<(String, u64), String> {
    let bytes = leaf
        .extensions()
        .unknown(INCARNATION_EXTENSION_TYPE)
        .ok_or_else(|| "leaf has no authz_incarnation".to_owned())?;
    let (group, subject, generation, signature_key) =
        decode_incarnation(&bytes.0, crypto, &binding.apf_public)?;
    if group != binding.group {
        return Err("authz_incarnation names another group".into());
    }
    if leaf.credential().serialized_content() != subject.as_bytes() {
        return Err("authz_incarnation subject differs from the leaf credential".into());
    }
    if leaf.signature_key().as_slice() != signature_key.as_slice() {
        return Err("authz_incarnation signature key differs from the leaf".into());
    }
    Ok((subject, generation))
}

/// The installed `acc_context` revision of a bound group (unverified read used
/// only to obtain the parent's lower bound before a commit is processed).
fn acc_revision_of(group: &MlsGroup, crypto: &impl OpenMlsCrypto, binding: &Binding) -> u64 {
    group
        .public_group()
        .group_context()
        .extensions()
        .unknown(ACC_CONTEXT_EXTENSION_TYPE)
        .and_then(|bytes| decode_acc_context(&bytes.0, crypto, &binding.apf_public).ok())
        .map(|(_, revision, _)| revision)
        .unwrap_or(0)
}

/// Verified `acc_context` of a bound group: `(revision, sorted roster)`.
fn read_acc_context(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    binding: &Binding,
) -> Result<(u64, Vec<(String, u64)>), String> {
    let bytes = group
        .public_group()
        .group_context()
        .extensions()
        .unknown(ACC_CONTEXT_EXTENSION_TYPE)
        .ok_or_else(|| "acc_context missing".to_owned())?;
    let (acc_group, revision, roster) = decode_acc_context(&bytes.0, crypto, &binding.apf_public)?;
    if acc_group != binding.group {
        return Err("acc_context names another group".into());
    }
    Ok((revision, sorted_roster(&roster)))
}

/// ACC coherence of a bound group state: a valid APF-signed `acc_context`
/// strictly newer than the parent's (`parent_revision`; `None` for group
/// creation and Welcome), valid incarnations on every leaf, and the leaf
/// incarnation multiset equal to the `acc_context` roster. Every honest
/// transition binds a strictly newer APF revision, so replaying the current
/// binding in a rogue commit cannot fork honest members.
fn check_coherence(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    binding: &Binding,
    parent_revision: Option<u64>,
) -> Result<(), String> {
    let coherence = |detail: String| format!("coherence: {detail}");
    let (revision, roster) = read_acc_context(group, crypto, binding).map_err(coherence)?;
    if let Some(parent) = parent_revision {
        if revision <= parent {
            return Err(coherence(format!(
                "acc_context revision {revision} is not newer than the parent's {parent}"
            )));
        }
    }
    let mut leaves = Vec::new();
    for member in group.members() {
        let leaf = group
            .public_group()
            .leaf(member.index)
            .ok_or_else(|| coherence("missing leaf".into()))?;
        leaves.push(leaf_incarnation(leaf, crypto, binding).map_err(coherence)?);
    }
    leaves.sort();
    if leaves != roster {
        return Err(coherence(
            "tree incarnations differ from the acc_context roster".into(),
        ));
    }
    Ok(())
}

/// Leaf index → verified incarnation subject for every member of `group`.
fn leaf_subjects(
    group: &MlsGroup,
    crypto: &impl OpenMlsCrypto,
    binding: &Binding,
) -> Result<BTreeMap<LeafNodeIndex, String>, String> {
    let mut subjects = BTreeMap::new();
    for member in group.members() {
        let leaf = group
            .public_group()
            .leaf(member.index)
            .ok_or_else(|| "missing leaf".to_owned())?;
        subjects.insert(member.index, leaf_incarnation(leaf, crypto, binding)?.0);
    }
    Ok(subjects)
}

fn leaf_indices(
    subjects: &BTreeMap<LeafNodeIndex, String>,
    names: &[String],
) -> Result<Vec<LeafNodeIndex>, String> {
    names
        .iter()
        .map(|name| {
            subjects
                .iter()
                .find(|(_, subject)| *subject == name)
                .map(|(index, _)| *index)
                .ok_or_else(|| format!("{name} has no leaf in the group"))
        })
        .collect()
}

struct VerifiedAdmission {
    subject: String,
    generation: u64,
    preimage_hash: Vec<u8>,
    recomputed_canonical: Vec<u8>,
}

fn issue_admission_certificate(
    group: &[u8],
    subject: &str,
    generation: u64,
    canonical: &[u8],
    signer: &impl Signer,
) -> Result<Vec<u8>, String> {
    let mut payload = Vec::new();
    payload.extend_from_slice(APF_CERTIFICATE_MAGIC);
    payload.push(APF_CERTIFICATE_VERSION);
    append_sized(&mut payload, group)?;
    append_sized(&mut payload, subject.as_bytes())?;
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&Sha256::digest(canonical));
    let signature = signer.sign(&payload).map_err(error)?;
    append_sized(&mut payload, &signature)?;
    Ok(payload)
}

fn verify_admission_key_package(
    provider: &LabProvider,
    wire: &[u8],
    expected_subject: &str,
    expected_generation: u64,
    apf_public_key: &[u8],
) -> Result<VerifiedAdmission, String> {
    let key_package = KeyPackageIn::tls_deserialize_exact(wire)
        .map_err(error)?
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(error)?;
    let recomputed_canonical = key_package
        .canonical_binding_bytes(APF_BINDING_EXTENSION_TYPE)
        .map_err(error)?;
    let certificate = key_package
        .extensions()
        .iter()
        .find_map(|extension| match extension {
            Extension::Unknown(extension_type, UnknownExtension(bytes))
                if *extension_type == APF_BINDING_EXTENSION_TYPE =>
            {
                Some(bytes.as_slice())
            }
            _ => None,
        })
        .ok_or_else(|| "APF binding extension missing".to_owned())?;

    let mut input = certificate;
    if take(&mut input, APF_CERTIFICATE_MAGIC.len())? != APF_CERTIFICATE_MAGIC {
        return Err("invalid APF certificate magic".into());
    }
    if take(&mut input, 1)?[0] != APF_CERTIFICATE_VERSION {
        return Err("unsupported APF certificate version".into());
    }
    let group = take_sized(&mut input)?;
    let subject = take_sized(&mut input)?;
    let generation = u64::from_be_bytes(
        take(&mut input, 8)?
            .try_into()
            .map_err(|_| "invalid APF generation".to_owned())?,
    );
    let preimage_hash = take(&mut input, 32)?.to_vec();
    let signed_len = certificate.len() - input.len();
    let signature = take_sized(&mut input)?;
    if !input.is_empty() {
        return Err("trailing APF certificate bytes".into());
    }
    if group != GROUP_ID {
        return Err("APF certificate group mismatch".into());
    }
    if subject != expected_subject.as_bytes() {
        return Err("APF certificate subject mismatch".into());
    }
    if generation != expected_generation {
        return Err("APF certificate generation mismatch".into());
    }
    if preimage_hash != Sha256::digest(&recomputed_canonical).as_slice() {
        return Err("APF certificate KeyPackage binding mismatch".into());
    }
    provider
        .crypto()
        .verify_signature(
            SignatureScheme::ED25519,
            &certificate[..signed_len],
            apf_public_key,
            signature,
        )
        .map_err(|_| "invalid APF certificate signature".to_owned())?;

    Ok(VerifiedAdmission {
        subject: String::from_utf8(subject.to_vec())
            .map_err(|_| "APF certificate subject is not UTF-8".to_owned())?,
        generation,
        preimage_hash,
        recomputed_canonical,
    })
}

fn append_sized(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let length = u16::try_from(value.len()).map_err(|_| "APF certificate field too large")?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn take_sized<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], String> {
    let length = u16::from_be_bytes(
        take(input, 2)?
            .try_into()
            .map_err(|_| "invalid APF certificate length".to_owned())?,
    ) as usize;
    take(input, length)
}

fn take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
    if input.len() < length {
        return Err("truncated APF certificate".into());
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

fn credential(name: &str, signer: &SignatureKeyPair) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(name.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    }
}

fn protocol_message(wire: &[u8]) -> Result<ProtocolMessage, String> {
    MlsMessageIn::tls_deserialize_exact(wire)
        .map_err(error)?
        .try_into_protocol_message()
        .map_err(error)
}

fn welcome_from_out(welcome: MlsMessageOut) -> Result<Welcome, String> {
    match MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().map_err(error)?)
        .map_err(error)?
        .extract()
    {
        MlsMessageBodyIn::Welcome(welcome) => Ok(welcome),
        _ => Err("MLS add operation did not produce a Welcome".into()),
    }
}

/// Names double as state-file stems, so they are restricted to a safe alphabet.
fn ensure_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        Err("member name must not be empty".into())
    } else if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        Err("member name must use only ASCII letters, digits, '-' or '_'".into())
    } else {
        Ok(())
    }
}

fn error<E: std::fmt::Debug>(error: E) -> String {
    format!("OpenMLS error: {error:?}")
}
