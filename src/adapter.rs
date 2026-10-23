//! Trusted adapter between authenticated clients, OpenMLS evidence and the APF kernel.
//!
//! Phase 4.1 surface: the APF signing key, client identities, signed requests
//! and the trusted clock (`docs/adapter-contract.md` §4.8, §4.9, §7, §8).
//! Phase 4.2 surface: genesis, the public sequencer and admission (§4.10, §5.1, §5.2).
//! The kernel stays key-free; only this adapter calls `Authority::execute`.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use openmls::messages::group_info::VerifiableGroupInfo;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::MemoryStorage;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::{random::OpenMlsRand, signatures::Signer, OpenMlsProvider};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize, VLBytes};

use crate::authority::Authority;
use crate::client::{
    context_frontier, unknown_payloads, ADAPTER_EXTENSIONS, CIPHERSUITE, ZERO_HASH,
};
use crate::wire::{
    AccContext, AckKind, AdmissionCertificate, AuthzIncarnation, CanonicalAck, FounderCertificate,
    Frontier, Right, SignedStructure, ACC_CONTEXT_EXTENSION_TYPE, ADMISSION_EXTENSION_TYPE,
    AUTHZ_INCARNATION_EXTENSION_TYPE,
};

/// Domain-separation label of `RequestTBS` (§4.8).
pub const REQUEST_LABEL: &[u8] = b"agent-trust/request/v1";
/// File names inside an adapter directory (§4.9, C-5).
pub const AUTHORITY_FILE: &str = "authority.sqlite";
pub const ADAPTER_FILE: &str = "adapter.sqlite";
pub const APF_KEY_FILE: &str = "apf-signing-key";

/// Ed25519 seed and public key length.
const KEY_LEN: usize = 32;
/// Longest accepted `command` string; matches the kernel identifier bound.
const MAX_COMMAND: usize = 256;
/// SQLite sidecar suffixes that must not pre-exist next to a new database.
const SIDECARS: [&str; 3] = ["-wal", "-shm", "-journal"];
/// Body fields the adapter alone sets (C-2).
const RESERVED: [&str; 2] = ["actor", "now"];
/// Commands `handle` routes to the kernel in phase 4.1 (C-3).
const ROUTED: [&str; 5] = ["grant", "delegate", "revoke", "invoke", "allocate"];
/// Kernel commands only the adapter itself may issue (C-3, C-7).
const ADAPTER_ONLY: [&str; 6] = [
    "init",
    "admit",
    "repair",
    "repair_stage",
    "repair_open",
    "subject_status",
];
/// Kernel commands routed from phase 4.3 on (C-3).
const NOT_YET_ROUTED: [&str; 5] = ["release", "persist", "emit", "consume", "abandon"];
/// Adapter flows `handle` routes in phase 4.2 (C-10); they are not kernel commands.
const CERTIFICATE_FLOW: &str = "admission_certificate";
const SUBMIT_FLOW: &str = "submit_commit";
/// The sequencer's OpenMLS storage inside a full adapter directory (C-8).
const SEQUENCER_FILE: &str = "sequencer.sqlite";
/// Longest accepted hex string for a KeyPackage preimage or a commit (1 MiB of bytes).
const MAX_MESSAGE_HEX: usize = 2_097_152;
/// `adapter_meta` value of `mode` for an adapter with an MLS group (C-8).
const FULL_MODE: &str = "full";
/// C-11 error code for every sequencer rejection at steps 2-6.
const NONCANONICAL: &str = "noncanonical_commit";

/// Trusted time source for every kernel `now` input.
pub trait Clock {
    fn now(&self) -> u64;
}

/// Wall-clock seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0)
    }
}

/// A client's own Ed25519 signing identity, generated from provider randomness (C-6).
pub struct ClientIdentity {
    signer: SignatureKeyPair,
}

impl ClientIdentity {
    /// Draws a 32-byte seed from `rand` and derives the key pair.
    pub fn generate(rand: &impl OpenMlsRand) -> Result<Self, String> {
        let mut seed = draw_seed(rand)?;
        let signer = key_pair_from_seed(&seed);
        // Best-effort wipe of the stack copy; `SignatureKeyPair` holds its own secret bytes.
        seed.fill(0);
        Ok(Self { signer })
    }

    /// The 32-byte Ed25519 public key.
    pub fn public_key(&self) -> &[u8] {
        self.signer.public()
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }
}

/// One 32-byte seed from the configured rand provider (§8). The provider's error is
/// deliberately dropped: it may describe an entropy endpoint.
fn draw_seed(rand: &impl OpenMlsRand) -> Result<[u8; KEY_LEN], String> {
    rand.random_array::<KEY_LEN>()
        .map_err(|_| "entropy_unavailable".to_string())
}

/// `SignatureKeyPair::from_raw` over a seed, with the public half from ed25519-dalek (C-6).
/// Never `SignatureKeyPair::new` or the provider's `signature_key_gen` (§8).
/// The caller wipes its own copy of `seed` afterwards.
fn key_pair_from_seed(seed: &[u8; KEY_LEN]) -> SignatureKeyPair {
    let public = ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes();
    SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec())
}

/// A request signed by its actor's registered key (§4.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedRequest {
    pub actor: String,
    pub sequence: u64,
    /// Exact JSON bytes of the request body; the signature covers these bytes.
    pub body: Vec<u8>,
    pub signature: Vec<u8>,
}

impl SignedRequest {
    /// TLS-encoded `RequestTBS { label, group, actor, sequence, body }`.
    pub fn to_be_signed(
        group: &str,
        actor: &str,
        sequence: u64,
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for opaque in [REQUEST_LABEL, group.as_bytes(), actor.as_bytes()] {
            out.extend(opaque_vector(opaque)?);
        }
        out.extend(
            sequence
                .tls_serialize_detached()
                .map_err(|_| "malformed: request encoding".to_string())?,
        );
        out.extend(opaque_vector(body)?);
        Ok(out)
    }

    /// Serializes `body` and signs the resulting `RequestTBS` with `signer`.
    pub fn sign(
        group: &str,
        actor: &str,
        sequence: u64,
        body: &Value,
        signer: &impl Signer,
    ) -> Result<Self, String> {
        let body = serde_json::to_vec(body).map_err(|_| "malformed: body".to_string())?;
        let tbs = Self::to_be_signed(group, actor, sequence, &body)?;
        let signature = signer
            .sign(&tbs)
            .map_err(|_| "malformed: signing failed".to_string())?;
        Ok(Self {
            actor: actor.to_owned(),
            sequence,
            body,
            signature,
        })
    }
}

/// `opaque x<V>`: a QUIC-style variable-length prefix followed by the bytes.
fn opaque_vector(bytes: &[u8]) -> Result<Vec<u8>, String> {
    VLBytes::new(bytes.to_vec())
        .tls_serialize_detached()
        .map_err(|_| "malformed: request encoding".to_string())
}

/// The trusted adapter: owns the APF key, authenticates requests and drives the kernel.
pub struct Adapter<P: OpenMlsProvider, C: Clock> {
    provider: P,
    clock: C,
    group: String,
    apf: SignatureKeyPair,
    kernel: Authority,
    store: Connection,
    /// The public sequencer; `None` for a policy-only adapter from `create` (C-8).
    sequencer: Option<Sequencer>,
}

impl<P: OpenMlsProvider, C: Clock> Adapter<P, C> {
    /// Creates a new adapter directory, the APF key and the kernel, and registers `root`.
    pub fn create(
        dir: &Path,
        group: &str,
        root: &str,
        root_public_key: &[u8],
        provider: P,
        clock: C,
    ) -> Result<Self, String> {
        let root_key = parse_public_key(root_public_key).ok_or("malformed: root_public_key")?;

        // C-5: refuse before drawing entropy if any file (or a database sidecar) exists.
        let paths = AdapterPaths::new(dir);
        for path in paths.all_with_sidecars() {
            if exists(&path)? {
                return Err(format!("already_initialized: {} exists", file_name(&path)));
            }
        }

        // C-6: one 32-byte draw; on failure nothing has been created.
        let mut seed = draw_seed(provider.rand())?;
        let apf = key_pair_from_seed(&seed);

        // Claim all three names atomically (`create_new`); undo every claim on failure.
        let mut claimed = Claimed::default();
        let result = (|| {
            let mut key_file = claimed.claim(&paths.key, true)?;
            claimed.claim(&paths.authority, false)?;
            claimed.claim(&paths.adapter, false)?;

            let written = key_file.write_all(&seed).and_then(|()| key_file.sync_all());
            seed.fill(0);
            written.map_err(|_| "malformed: cannot write apf key file".to_string())?;
            drop(key_file);

            let mut kernel = Authority::open(&paths.authority)?;
            kernel.execute(json!({"command":"init", "group":group, "root":root}))?;

            let store = init_store(&paths.adapter, group, apf.public(), root, &root_key, None)?;
            sync_dir(dir);
            Ok((kernel, store))
        })();

        seed.fill(0);
        match result {
            Ok((kernel, store)) => Ok(Self {
                provider,
                clock,
                group: group.to_owned(),
                apf,
                kernel,
                store,
                sequencer: None,
            }),
            Err(err) => {
                claimed.undo();
                Err(err)
            }
        }
    }

    /// Reopens an existing adapter directory.
    pub fn open(dir: &Path, provider: P, clock: C) -> Result<Self, String> {
        let paths = AdapterPaths::new(dir);
        for path in [&paths.authority, &paths.adapter, &paths.key] {
            if !exists(path)? {
                return Err(format!("uninitialized: {} missing", file_name(path)));
            }
        }

        let mut seed = [0u8; KEY_LEN];
        let mut file = File::open(&paths.key)
            .map_err(|_| "malformed: cannot read apf key file".to_string())?;
        let mut extra = [0u8; 1];
        let complete = file.read_exact(&mut seed).is_ok() && matches!(file.read(&mut extra), Ok(0));
        drop(file);
        if !complete {
            seed.fill(0);
            return Err("malformed: apf key file".into());
        }
        let apf = key_pair_from_seed(&seed);
        seed.fill(0);

        let store = open_store(&paths.adapter, false)?;
        let group = meta(&store, "group")?;
        if meta(&store, "apf_public_key")? != hex::encode(apf.public()) {
            return Err("binding_mismatch: apf key".into());
        }

        let mut kernel = Authority::open(&paths.authority)?;
        let checkpoint = kernel.execute(json!({"command":"checkpoint"}))?;
        if checkpoint["group"] != json!(group) {
            return Err("binding_mismatch: group".into());
        }

        // C-8: a full adapter reloads its sequencer, which must sit at the kernel frontier.
        let sequencer = match meta_opt(&store, "mode")?.as_deref() {
            None => None,
            Some(FULL_MODE) => {
                if !exists(&paths.sequencer)? {
                    return Err(format!("uninitialized: {SEQUENCER_FILE} missing"));
                }
                let sequencer = Sequencer::open(&paths.sequencer, &group)?;
                if sequencer.frontier()? != checkpoint_frontier(&checkpoint)? {
                    return Err("binding_mismatch: sequencer frontier".into());
                }
                let acc = sequencer.acc_context()?;
                if acc.apf_key_id != Sha256::digest(apf.public()).as_slice() || acc.group != group {
                    return Err("binding_mismatch: sequencer acc_context".into());
                }
                Some(sequencer)
            }
            Some(_) => return Err("malformed: adapter store mode".into()),
        };

        Ok(Self {
            provider,
            clock,
            group,
            apf,
            kernel,
            store,
            sequencer,
        })
    }

    /// The APF Ed25519 public key.
    pub fn apf_public_key(&self) -> &[u8] {
        self.apf.public()
    }

    /// `SHA-256(APF public key)`.
    pub fn apf_key_id(&self) -> Vec<u8> {
        Sha256::digest(self.apf.public()).to_vec()
    }

    /// Authenticates and routes one client request (C-2 to C-4).
    pub fn handle(&mut self, request: &SignedRequest) -> Result<Value, String> {
        // C-4 steps 1-4 in one immediate store transaction.
        let actor = self.authenticate(request)?;
        // C-4 steps 5-6 in a second one, held across the kernel call.
        self.route(&actor, request)
    }

    /// Trusted local read of the kernel checkpoint.
    pub fn checkpoint(&mut self) -> Result<Value, String> {
        self.kernel.execute(json!({"command":"checkpoint"}))
    }

    /// Trace events in handling order (C-5).
    pub fn trace(&self) -> Vec<Value> {
        let read = || -> rusqlite::Result<Vec<Value>> {
            let mut stmt = self.store.prepare(
                "SELECT actor, sequence, command, outcome FROM adapter_trace ORDER BY id",
            )?;
            let rows = stmt.query_map([], |row| {
                let sequence: String = row.get(1)?;
                Ok(json!({
                    "actor": row.get::<_, Option<String>>(0)?,
                    "sequence": sequence.parse::<u64>().ok(),
                    "command": row.get::<_, Option<String>>(2)?,
                    "outcome": row.get::<_, String>(3)?,
                }))
            })?;
            rows.collect()
        };
        read().unwrap_or_default()
    }

    /// C-4 steps 1-4. Returns the authenticated actor once its sequence is durable.
    /// A failure appends only its trace event: keys, sequences and the kernel are unchanged.
    fn authenticate(&mut self, request: &SignedRequest) -> Result<String, String> {
        self.store.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        let checked = self.check_signed(request);
        let (traced_actor, write) = match &checked {
            Ok(()) => (Some(request.actor.as_str()), None),
            Err((known, err)) => (known.then_some(request.actor.as_str()), Some(err.clone())),
        };
        let result = (|| -> rusqlite::Result<()> {
            match &write {
                None => {
                    self.store.execute(
                        "INSERT INTO adapter_sequences(actor, last_sequence) VALUES (?1, ?2)
                         ON CONFLICT(actor) DO UPDATE SET last_sequence = excluded.last_sequence",
                        params![request.actor, request.sequence.to_string()],
                    )?;
                }
                Some(err) => {
                    append_trace(&self.store, traced_actor, request.sequence, None, err)?;
                }
            }
            self.store.execute_batch("COMMIT")
        })();
        if let Err(err) = result {
            let _ = self.store.execute_batch("ROLLBACK");
            return Err(db(err));
        }
        match checked {
            Ok(()) => Ok(request.actor.clone()),
            Err((_, err)) => Err(err),
        }
    }

    /// C-4 steps 1-3 inside the open transaction. The error carries whether the actor
    /// is registered, which decides between a named and a `null` trace actor.
    fn check_signed(&self, request: &SignedRequest) -> Result<(), (bool, String)> {
        let unauthenticated = |known| (known, "unauthenticated".to_string());
        let key: Option<Vec<u8>> = self
            .store
            .query_row(
                "SELECT public_key FROM adapter_keys WHERE actor = ?1",
                [&request.actor],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| (false, db(err)))?;
        let key = key.ok_or_else(|| unauthenticated(false))?;

        let tbs = SignedRequest::to_be_signed(
            &self.group,
            &request.actor,
            request.sequence,
            &request.body,
        )
        .map_err(|_| unauthenticated(true))?;
        self.provider
            .crypto()
            .verify_signature(SignatureScheme::ED25519, &tbs, &key, &request.signature)
            .map_err(|_| unauthenticated(true))?;

        let last: Option<String> = self
            .store
            .query_row(
                "SELECT last_sequence FROM adapter_sequences WHERE actor = ?1",
                [&request.actor],
                |row| row.get(0),
            )
            .optional()
            .map_err(|err| (true, db(err)))?;
        if let Some(last) = last {
            let last: u64 = last
                .parse()
                .map_err(|_| (true, "malformed: corrupt sequence".to_string()))?;
            if request.sequence <= last {
                return Err(unauthenticated(true));
            }
        }
        Ok(())
    }

    /// C-4 steps 5-6, then key registration and the trace event, in one store transaction.
    fn route(&mut self, actor: &str, request: &SignedRequest) -> Result<Value, String> {
        self.store.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        let (command, outcome) = match self.prepare(actor, &request.body) {
            Err((command, err)) => (command, Err(err)),
            Ok((command, Routed::Kernel(kernel_request, registration))) => {
                let outcome = self.kernel.execute(kernel_request);
                let effect = registration.map_or(Effect::None, |(subject, key)| {
                    Effect::Register(subject, key)
                });
                (Some(command), outcome.map(|value| (value, effect)))
            }
            Ok((command, Routed::Certificate(preimage))) => {
                let outcome = self.issue_certificate(actor, &preimage);
                (Some(command), outcome.map(|value| (value, Effect::None)))
            }
            Ok((command, Routed::Submit(parent, commit))) => {
                let outcome = self.sequence_commit(actor, &parent, &commit);
                (
                    Some(command),
                    outcome.map(|(value, record)| (value, Effect::Admitted(record))),
                )
            }
        };
        let result = (|| -> rusqlite::Result<()> {
            match &outcome {
                Ok((_, effect)) => {
                    match effect {
                        Effect::None => {}
                        Effect::Register(subject, key) => {
                            self.store.execute(
                                "INSERT INTO adapter_keys(actor, public_key) VALUES (?1, ?2)",
                                params![subject, key.as_slice()],
                            )?;
                        }
                        Effect::Admitted(record) => insert_certificate(&self.store, record)?,
                    }
                    append_trace(
                        &self.store,
                        Some(actor),
                        request.sequence,
                        command.as_deref(),
                        "ok",
                    )?;
                }
                Err(err) => {
                    append_trace(
                        &self.store,
                        Some(actor),
                        request.sequence,
                        command.as_deref(),
                        err,
                    )?;
                }
            }
            self.store.execute_batch("COMMIT")
        })();
        if let Err(err) = result {
            // The kernel may already have committed; see the crash gap in the phase report.
            let _ = self.store.execute_batch("ROLLBACK");
            return Err(db(err));
        }
        outcome.map(|(value, _)| value)
    }

    /// C-4 step 5: parses and checks the body (C-1 to C-3, C-10) and builds the kernel
    /// request or the adapter flow. A kernel request carries the key to register on success.
    fn prepare(
        &mut self,
        actor: &str,
        body: &[u8],
    ) -> Result<(String, Routed), (Option<String>, String)> {
        let malformed = |command: Option<&str>, detail: &str| {
            (command.map(str::to_owned), format!("malformed: {detail}"))
        };
        let value: Value =
            serde_json::from_slice(body).map_err(|_| malformed(None, "request body"))?;
        let Value::Object(mut fields) = value else {
            return Err(malformed(None, "request object"));
        };
        let command = match fields.get("command") {
            Some(Value::String(c)) if !c.is_empty() && c.len() <= MAX_COMMAND => c.clone(),
            _ => return Err(malformed(None, "command")),
        };
        let cmd = Some(command.as_str());

        // C-2.
        if RESERVED.iter().any(|field| fields.contains_key(*field)) {
            return Err(malformed(cmd, "reserved field"));
        }
        // C-10 and C-11 step 1: adapter flows exist only on a full adapter.
        if command == CERTIFICATE_FLOW || command == SUBMIT_FLOW {
            if self.sequencer.is_none() {
                return Err((Some(command), "uninitialized: no group".into()));
            }
            let routed = if command == CERTIFICATE_FLOW {
                parse_certificate_body(&fields).map(Routed::Certificate)
            } else {
                parse_submit_body(&fields).map(|(parent, commit)| Routed::Submit(parent, commit))
            };
            return routed
                .map(|routed| (command.clone(), routed))
                .map_err(|err| (Some(command), err));
        }
        // C-3.
        if !ROUTED.contains(&command.as_str()) {
            let err = if ADAPTER_ONLY.contains(&command.as_str()) {
                "unauthorized".to_string()
            } else if NOT_YET_ROUTED.contains(&command.as_str()) {
                "malformed: unsupported command".to_string()
            } else {
                "malformed: unknown command".to_string()
            };
            return Err((Some(command), err));
        }

        // C-1.
        let subject_key = fields.remove("subject_key");
        let needs_key = match command.as_str() {
            "delegate" => true,
            "grant" => match fields.get("subject").and_then(Value::as_str) {
                Some(subject) => !self
                    .subject_known(subject)
                    .map_err(|err| (Some(command.clone()), err))?,
                // The kernel reports the malformed subject; no key may ride along.
                None => false,
            },
            _ => false,
        };
        let registration = match (needs_key, subject_key) {
            (false, None) => None,
            (false, Some(_)) | (true, None) => return Err(malformed(cmd, "subject_key")),
            (true, Some(raw)) => {
                let key = parse_hex_key(&raw).ok_or_else(|| malformed(cmd, "subject_key"))?;
                if self
                    .key_registered(&key)
                    .map_err(|err| (Some(command.clone()), err))?
                {
                    return Err((Some(command), "binding_mismatch".into()));
                }
                // A delegate without a string subject fails in the kernel and registers nothing.
                fields
                    .get("subject")
                    .and_then(Value::as_str)
                    .map(|subject| (subject.to_owned(), key))
            }
        };

        fields.insert("actor".into(), json!(actor));
        fields.insert("now".into(), json!(self.clock.now()));
        Ok((command, Routed::Kernel(Value::Object(fields), registration)))
    }

    /// A subject is known if it holds a registered key or the kernel already records it.
    /// The kernel check only matters if a crash separated a kernel commit from its
    /// registration; such a subject then stays unauthenticated instead of being rebound.
    fn subject_known(&mut self, subject: &str) -> Result<bool, String> {
        let registered: Option<i64> = self
            .store
            .query_row(
                "SELECT 1 FROM adapter_keys WHERE actor = ?1",
                [subject],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        if registered.is_some() {
            return Ok(true);
        }
        let checkpoint = self.kernel.execute(json!({"command":"checkpoint"}))?;
        Ok(checkpoint["grants"]
            .as_array()
            .is_some_and(|grants| grants.iter().any(|g| g["subject"] == json!(subject))))
    }

    fn key_registered(&self, key: &[u8; KEY_LEN]) -> Result<bool, String> {
        let found: Option<i64> = self
            .store
            .query_row(
                "SELECT 1 FROM adapter_keys WHERE public_key = ?1",
                [key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(found.is_some())
    }
}

/// The adapter files of one directory.
struct AdapterPaths {
    authority: PathBuf,
    adapter: PathBuf,
    key: PathBuf,
    sequencer: PathBuf,
}

impl AdapterPaths {
    fn new(dir: &Path) -> Self {
        Self {
            authority: dir.join(AUTHORITY_FILE),
            adapter: dir.join(ADAPTER_FILE),
            key: dir.join(APF_KEY_FILE),
            sequencer: dir.join(SEQUENCER_FILE),
        }
    }

    /// The four files of a full adapter plus the SQLite sidecars of its three databases.
    fn genesis_with_sidecars(&self) -> Vec<PathBuf> {
        let mut out = self.all_with_sidecars();
        out.push(self.sequencer.clone());
        for suffix in SIDECARS {
            let mut name = self.sequencer.as_os_str().to_owned();
            name.push(suffix);
            out.push(PathBuf::from(name));
        }
        out
    }

    /// The three files plus the SQLite sidecars of both databases.
    fn all_with_sidecars(&self) -> Vec<PathBuf> {
        let mut out = vec![
            self.authority.clone(),
            self.adapter.clone(),
            self.key.clone(),
        ];
        for db in [&self.authority, &self.adapter] {
            for suffix in SIDECARS {
                let mut name = db.as_os_str().to_owned();
                name.push(suffix);
                out.push(PathBuf::from(name));
            }
        }
        out
    }
}

/// Files created by one `create` call, removed again if `create` fails.
#[derive(Default)]
struct Claimed {
    paths: Vec<PathBuf>,
}

impl Claimed {
    /// Creates `path` exclusively; the APF key file gets owner-only permissions.
    fn claim(&mut self, path: &Path, secret: bool) -> Result<File, String> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if secret {
                options.mode(0o600);
            }
        }
        #[cfg(not(unix))]
        let _ = secret;
        match options.open(path) {
            Ok(file) => {
                self.paths.push(path.to_path_buf());
                Ok(file)
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                Err(format!("already_initialized: {} exists", file_name(path)))
            }
            Err(_) => Err(format!("malformed: cannot create {}", file_name(path))),
        }
    }

    /// Removes every claimed file and the SQLite sidecars this call created next to them.
    fn undo(self) {
        for path in self.paths {
            for suffix in SIDECARS {
                let mut name = path.as_os_str().to_owned();
                name.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(name));
            }
            let _ = std::fs::remove_file(path);
        }
    }
}

fn exists(path: &Path) -> Result<bool, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(_) => Err(format!("malformed: cannot inspect {}", file_name(path))),
    }
}

/// The bare file name, so errors never carry workspace paths.
fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Makes the new directory entries durable (best effort, Unix only).
fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    if let Ok(handle) = File::open(dir) {
        let _ = handle.sync_all();
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn open_store(path: &Path, create: bool) -> Result<Connection, String> {
    let store = if create {
        Connection::open(path)
    } else {
        Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
    }
    .map_err(db)?;
    store
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;")
        .map_err(db)?;
    store
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(db)?;
    Ok(store)
}

fn meta(store: &Connection, key: &str) -> Result<String, String> {
    store
        .query_row("SELECT v FROM adapter_meta WHERE k = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(db)?
        .ok_or_else(|| format!("malformed: adapter store {key}"))
}

/// Appends `{actor, sequence, command, outcome}`; `outcome` is `ok` or the bare error code.
fn append_trace(
    store: &Connection,
    actor: Option<&str>,
    sequence: u64,
    command: Option<&str>,
    outcome: &str,
) -> rusqlite::Result<usize> {
    store.execute(
        "INSERT INTO adapter_trace(actor, sequence, command, outcome) VALUES (?1, ?2, ?3, ?4)",
        params![actor, sequence.to_string(), command, error_code(outcome)],
    )
}

/// The stable code that begins an error string.
fn error_code(error: &str) -> &str {
    error.split(':').next().unwrap_or(error).trim()
}

/// A 32-byte Ed25519 public key that decodes to a curve point.
fn parse_public_key(bytes: &[u8]) -> Option<[u8; KEY_LEN]> {
    let key: [u8; KEY_LEN] = bytes.try_into().ok()?;
    ed25519_dalek::VerifyingKey::from_bytes(&key).ok()?;
    Some(key)
}

/// C-1: exactly 64 lowercase hex characters encoding a valid Ed25519 public key.
fn parse_hex_key(value: &Value) -> Option<[u8; KEY_LEN]> {
    let text = value.as_str()?;
    if text.len() != 2 * KEY_LEN || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    parse_public_key(&hex::decode(text).ok()?)
}

fn db(err: rusqlite::Error) -> String {
    format!("malformed: adapter database {err}")
}

// ---------------------------------------------------------------------------
// Phase 4.2: store helpers, routed flows, the sequencer and genesis
// ---------------------------------------------------------------------------

/// Creates `adapter.sqlite` with its tables, the group, the APF public key and the
/// root's request key. A full adapter (C-8) also records its mode and the founder
/// certificate, indexed by the root's leaf signature key (§4.3).
fn init_store(
    path: &Path,
    group: &str,
    apf_public: &[u8],
    root: &str,
    root_key: &[u8; KEY_LEN],
    founder: Option<&CertificateRecord>,
) -> Result<Connection, String> {
    let store = open_store(path, true)?;
    store
        .execute_batch(
            "BEGIN IMMEDIATE;
             CREATE TABLE adapter_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE adapter_keys (
                 actor TEXT PRIMARY KEY,
                 public_key BLOB NOT NULL UNIQUE);
             CREATE TABLE adapter_sequences (
                 actor TEXT PRIMARY KEY,
                 last_sequence TEXT NOT NULL);
             CREATE TABLE adapter_trace (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 actor TEXT,
                 sequence TEXT NOT NULL,
                 command TEXT,
                 outcome TEXT NOT NULL);",
        )
        .map_err(db)?;
    let populate = (|| {
        store.execute(
            "INSERT INTO adapter_meta(k, v) VALUES ('group', ?1), ('apf_public_key', ?2)",
            params![group, hex::encode(apf_public)],
        )?;
        store.execute(
            "INSERT INTO adapter_keys(actor, public_key) VALUES (?1, ?2)",
            params![root, root_key.as_slice()],
        )?;
        if let Some(founder) = founder {
            store.execute_batch(
                "CREATE TABLE adapter_certificates (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     signature_key BLOB NOT NULL,
                     subject TEXT NOT NULL,
                     epoch TEXT NOT NULL,
                     branch TEXT NOT NULL,
                     certificate BLOB NOT NULL);
                 CREATE INDEX adapter_certificates_by_key
                     ON adapter_certificates(signature_key);",
            )?;
            store.execute(
                "INSERT INTO adapter_meta(k, v) VALUES ('mode', ?1)",
                [FULL_MODE],
            )?;
            insert_certificate(&store, founder)?;
        }
        store.execute_batch("COMMIT")
    })();
    if let Err(err) = populate {
        let _ = store.execute_batch("ROLLBACK");
        return Err(db(err));
    }
    Ok(store)
}

fn meta_opt(store: &Connection, key: &str) -> Result<Option<String>, String> {
    store
        .query_row("SELECT v FROM adapter_meta WHERE k = ?1", [key], |row| {
            row.get(0)
        })
        .optional()
        .map_err(db)
}

fn insert_certificate(store: &Connection, record: &CertificateRecord) -> rusqlite::Result<()> {
    store.execute(
        "INSERT INTO adapter_certificates(signature_key, subject, epoch, branch, certificate)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            record.signature_key,
            record.subject,
            record.epoch.to_string(),
            record.branch,
            record.certificate
        ],
    )?;
    Ok(())
}

/// The kernel frontier `(epoch, branch)` of a checkpoint.
fn checkpoint_frontier(checkpoint: &Value) -> Result<Frontier, String> {
    Ok(Frontier {
        epoch: checkpoint["epoch"]
            .as_u64()
            .ok_or("malformed: kernel epoch")?,
        branch: checkpoint["branch"]
            .as_str()
            .ok_or("malformed: kernel branch")?
            .to_owned(),
    })
}

/// What `prepare` routes an authenticated request to.
enum Routed {
    /// A kernel request and the key to register if the kernel accepts it (C-1).
    Kernel(Value, Option<(String, [u8; KEY_LEN])>),
    /// `admission_certificate` over these preimage bytes (C-10).
    Certificate(Vec<u8>),
    /// `submit_commit` of these commit bytes on this parent frontier (C-10).
    Submit(Frontier, Vec<u8>),
}

/// The adapter store change that commits together with a successful request's trace event.
enum Effect {
    None,
    Register(String, [u8; KEY_LEN]),
    Admitted(CertificateRecord),
}

/// A founder or admission certificate retained for audit, indexed by the leaf signature
/// key it was admitted with (§4.3).
struct CertificateRecord {
    signature_key: Vec<u8>,
    subject: String,
    epoch: u64,
    branch: String,
    certificate: Vec<u8>,
}

/// `admission_certificate {key_package_preimage}` (C-10); unknown fields are refused.
fn parse_certificate_body(fields: &serde_json::Map<String, Value>) -> Result<Vec<u8>, String> {
    only_fields(fields, &["command", "key_package_preimage"])?;
    lower_hex_field(fields, "key_package_preimage")
}

/// `submit_commit {kind: "admit", parent_epoch, parent_branch, commit}` (C-10).
fn parse_submit_body(
    fields: &serde_json::Map<String, Value>,
) -> Result<(Frontier, Vec<u8>), String> {
    only_fields(
        fields,
        &["command", "kind", "parent_epoch", "parent_branch", "commit"],
    )?;
    if fields.get("kind").and_then(Value::as_str) != Some("admit") {
        return Err("malformed: kind".into());
    }
    let epoch = fields
        .get("parent_epoch")
        .and_then(Value::as_u64)
        .ok_or("malformed: parent_epoch")?;
    let branch = match fields.get("parent_branch") {
        Some(Value::String(branch)) if !branch.is_empty() && branch.len() <= MAX_COMMAND => {
            branch.clone()
        }
        _ => return Err("malformed: parent_branch".into()),
    };
    let commit = lower_hex_field(fields, "commit")?;
    Ok((Frontier { epoch, branch }, commit))
}

fn only_fields(fields: &serde_json::Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
    match fields.keys().find(|key| !allowed.contains(&key.as_str())) {
        Some(key) => Err(format!("malformed: unknown field {key}")),
        None => Ok(()),
    }
}

/// A nonempty, bounded, lowercase hex string field.
fn lower_hex_field(fields: &serde_json::Map<String, Value>, key: &str) -> Result<Vec<u8>, String> {
    let malformed = || format!("malformed: {key}");
    let text = fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    if text.is_empty()
        || text.len() > MAX_MESSAGE_HEX
        || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(malformed());
    }
    hex::decode(text).map_err(|_| malformed())
}

fn noncanonical(detail: &str) -> String {
    format!("{NONCANONICAL}: {detail}")
}

/// A basic credential's identity bytes.
fn credential_identity(credential: &Credential) -> Option<Vec<u8>> {
    BasicCredential::try_from(credential.clone())
        .ok()
        .map(|basic| basic.identity().to_vec())
}

/// One right of a kernel `subject_status` response (C-7).
struct RightStatus {
    right: Right,
    generation: u64,
    active: bool,
    effective: bool,
}

/// A parsed kernel `subject_status` response (C-7).
struct SubjectStatus {
    rights: Vec<RightStatus>,
    expires_at: Option<u64>,
}

impl SubjectStatus {
    fn parse(value: &Value) -> Result<Self, String> {
        let malformed = || "malformed: kernel subject_status".to_string();
        let rights = value["rights"]
            .as_array()
            .ok_or_else(malformed)?
            .iter()
            .map(|entry| {
                Ok(RightStatus {
                    right: entry["right"]
                        .as_str()
                        .and_then(Right::from_name)
                        .ok_or_else(malformed)?,
                    generation: entry["generation"].as_u64().ok_or_else(malformed)?,
                    active: entry["active"].as_bool().ok_or_else(malformed)?,
                    effective: entry["effective"].as_bool().ok_or_else(malformed)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let expires_at = match &value["expires_at"] {
            Value::Null => None,
            other => Some(other.as_u64().ok_or_else(malformed)?),
        };
        Ok(Self { rights, expires_at })
    }

    /// The generation of `right` if its grant is active and chain-valid at `now`.
    fn effective_generation(&self, right: Right) -> Option<u64> {
        self.rights
            .iter()
            .find(|status| status.right == right && status.active && status.effective)
            .map(|status| status.generation)
    }

    /// The subject's active rights and generations, sorted by right code.
    fn active_rights(&self) -> Vec<(Right, u64)> {
        let mut rights: Vec<(Right, u64)> = self
            .rights
            .iter()
            .filter(|status| status.active)
            .map(|status| (status.right, status.generation))
            .collect();
        rights.sort();
        rights
    }
}

/// serde_json codec for the sequencer's `openmls_sqlite_storage`.
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

/// The public sequencer (§3): an OpenMLS `PublicGroup` persisted in `sequencer.sqlite`.
/// It holds no epoch secrets and therefore cannot check confirmation tags.
struct Sequencer {
    conn: Connection,
    group: PublicGroup,
}

impl Sequencer {
    /// Builds the sequencer from the root's GroupInfo and ratchet tree into a new file.
    fn create(
        path: &Path,
        crypto: &impl OpenMlsCrypto,
        group_info: &[u8],
        ratchet_tree: &[u8],
    ) -> Result<Self, String> {
        let mut conn = open_store(path, true)?;
        SqliteStorageProvider::<JsonCodec, &mut Connection>::new(&mut conn)
            .run_migrations()
            .map_err(|_| "malformed: sequencer migrations".to_string())?;
        conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        let built = PublicGroup::from_external(
            crypto,
            &SqliteStorageProvider::<JsonCodec, &Connection>::new(&conn),
            parse_ratchet_tree(ratchet_tree)?,
            parse_group_info(group_info)?,
            ProposalStore::new(),
        );
        let group = match built {
            Ok((group, _)) => group,
            Err(err) => {
                let _ = conn.execute_batch("ROLLBACK");
                return Err(format!("binding_mismatch: group state {err:?}"));
            }
        };
        conn.execute_batch("COMMIT").map_err(db)?;
        Ok(Self { conn, group })
    }

    fn open(path: &Path, group: &str) -> Result<Self, String> {
        let conn = open_store(path, false)?;
        let group = PublicGroup::load(
            &SqliteStorageProvider::<JsonCodec, &Connection>::new(&conn),
            &GroupId::from_slice(group.as_bytes()),
        )
        .map_err(db)?
        .ok_or("corrupt_history: sequencer group missing")?;
        Ok(Self { conn, group })
    }

    fn frontier(&self) -> Result<Frontier, String> {
        context_frontier(self.group.group_context())
    }

    fn acc_payloads(&self) -> Vec<Vec<u8>> {
        unknown_payloads(
            self.group.group_context().extensions(),
            ACC_CONTEXT_EXTENSION_TYPE,
        )
    }

    fn acc_context(&self) -> Result<AccContext, String> {
        match self.acc_payloads().as_slice() {
            [acc] => AccContext::decode(acc),
            _ => Err("binding_mismatch: acc_context count".into()),
        }
    }

    /// C-11 steps 2-4 on the in-memory `PublicGroup`; nothing is merged or written.
    /// Returns the staged commit and the added KeyPackage.
    fn stage(
        &self,
        crypto: &impl OpenMlsCrypto,
        commit: &[u8],
        actor: &str,
        actor_key: &[u8],
    ) -> Result<(StagedCommit, KeyPackage), String> {
        // Step 2: a PublicMessage commit for this group and epoch that OpenMLS accepts.
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|_| noncanonical("commit encoding"))?;
        if message.wire_format() != WireFormat::PublicMessage {
            return Err(noncanonical("not a PublicMessage"));
        }
        let message = message
            .try_into_protocol_message()
            .map_err(|_| noncanonical("not a protocol message"))?;
        if message.group_id() != self.group.group_id()
            || message.epoch() != self.group.group_context().epoch()
        {
            return Err(noncanonical("group or epoch"));
        }
        let processed = self
            .group
            .process_message(crypto, message)
            .map_err(|_| noncanonical("commit does not process"))?;

        // Step 3: the sender leaf is the authenticated actor under its registered key.
        let Sender::Member(index) = *processed.sender() else {
            return Err(noncanonical("sender is not a member"));
        };
        let sender = self
            .group
            .leaf(index)
            .ok_or_else(|| noncanonical("sender leaf"))?;
        if credential_identity(sender.credential()).as_deref() != Some(actor.as_bytes())
            || sender.signature_key().as_slice() != actor_key
        {
            return Err(noncanonical("sender is not the actor"));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(noncanonical("not a commit"));
        };

        // Step 4: exactly one Add and nothing else, with an UpdatePath. The path leaf
        // keeps the sender's credential, key and extensions, so a commit cannot relabel
        // the committer's own authz_incarnation.
        let proposals: Vec<&QueuedProposal> = staged.queued_proposals().collect();
        if proposals.len() != 1 || !matches!(proposals[0].proposal(), Proposal::Add(_)) {
            return Err(noncanonical("proposals"));
        }
        let path_leaf = staged
            .update_path_leaf_node()
            .ok_or_else(|| noncanonical("no UpdatePath"))?;
        if path_leaf.credential() != sender.credential()
            || path_leaf.signature_key() != sender.signature_key()
            || path_leaf.extensions() != sender.extensions()
        {
            return Err(noncanonical("UpdatePath leaf"));
        }
        let key_package = staged
            .add_proposals()
            .next()
            .map(|add| add.add_proposal().key_package().clone())
            .ok_or_else(|| noncanonical("no Add"))?;
        Ok((*staged, key_package))
    }

    /// C-11 step 8: merges and persists in one sequencer transaction. On failure the
    /// in-memory group is reloaded from the unchanged file.
    fn merge(&mut self, staged: StagedCommit) -> Result<(), String> {
        self.conn.execute_batch("BEGIN IMMEDIATE").map_err(db)?;
        let storage = SqliteStorageProvider::<JsonCodec, &Connection>::new(&self.conn);
        let merged = self
            .group
            .merge_commit(&storage, staged)
            .map_err(|err| format!("malformed: sequencer merge {err:?}"))
            .and_then(|()| self.conn.execute_batch("COMMIT").map_err(db));
        if let Err(err) = merged {
            let _ = self.conn.execute_batch("ROLLBACK");
            let group_id = self.group.group_id().clone();
            if let Ok(Some(group)) = PublicGroup::load(&storage, &group_id) {
                self.group = group;
            }
            return Err(err);
        }
        Ok(())
    }
}

fn parse_group_info(bytes: &[u8]) -> Result<VerifiableGroupInfo, String> {
    match MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| "binding_mismatch: GroupInfo encoding".to_string())?
        .extract()
    {
        MlsMessageBodyIn::GroupInfo(group_info) => Ok(group_info),
        _ => Err("binding_mismatch: not a GroupInfo".into()),
    }
}

fn parse_ratchet_tree(bytes: &[u8]) -> Result<RatchetTreeIn, String> {
    RatchetTreeIn::tls_deserialize_exact(bytes)
        .map_err(|_| "binding_mismatch: ratchet tree encoding".to_string())
}

impl<P: OpenMlsProvider, C: Clock> Adapter<P, C> {
    /// Starts a full adapter with an MLS group (C-8, §5.1 steps 1-2).
    pub fn begin_genesis(
        dir: &Path,
        group: &str,
        root: &str,
        root_public_key: &[u8],
        provider: P,
        clock: C,
    ) -> Result<GenesisPending<P, C>, String> {
        let root_key = parse_public_key(root_public_key).ok_or("malformed: root_public_key")?;

        // C-8: refuse an existing file as `create` does, before drawing entropy.
        for path in AdapterPaths::new(dir).genesis_with_sidecars() {
            if exists(&path)? {
                return Err(format!("already_initialized: {} exists", file_name(&path)));
            }
        }

        // The policy snapshot and the root's rights come from an in-memory kernel with
        // the same group and root; `complete` checks the real kernel against them.
        let mut shadow = Authority::open(":memory:")?;
        shadow.execute(json!({"command":"init", "group":group, "root":root}))?;
        let status = SubjectStatus::parse(
            &shadow
                .execute(json!({"command":"subject_status", "subject":root, "now":clock.now()}))?,
        )?;
        let rights = status.active_rights();
        let checkpoint = shadow.execute(json!({"command":"checkpoint"}))?;
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .ok_or("malformed: kernel policy_revision")?;
        let policy_digest = checkpoint["policy_digest"]
            .as_str()
            .and_then(|digest| hex::decode(digest).ok())
            .ok_or("malformed: kernel policy_digest")?;
        drop(shadow);

        // §5.1 step 1 (C-6): one 32-byte draw; on failure nothing exists.
        let seed = Seed(draw_seed(provider.rand())?);
        let apf = key_pair_from_seed(&seed.0);
        let apf_key_id = Sha256::digest(apf.public()).to_vec();

        // §5.1 step 2: the founder certificate binds the root's generation-0 rights and key.
        let founder_certificate = FounderCertificate {
            apf_key_id: apf_key_id.clone(),
            group: group.to_owned(),
            subject: root.to_owned(),
            rights: rights.clone(),
            signature_key: root_key.to_vec(),
        }
        .sign(&apf)?;
        let acc_context = AccContext {
            version: 1,
            apf_key_id,
            group: group.to_owned(),
            policy_revision,
            policy_digest,
        }
        .encode()?;

        Ok(GenesisPending {
            provider,
            clock,
            dir: dir.to_path_buf(),
            group: group.to_owned(),
            root: root.to_owned(),
            root_key,
            rights,
            seed,
            apf,
            founder_certificate,
            acc_context,
        })
    }

    /// The current kernel frontier.
    pub fn frontier(&mut self) -> Result<Frontier, String> {
        let checkpoint = self.kernel.execute(json!({"command":"checkpoint"}))?;
        checkpoint_frontier(&checkpoint)
    }

    fn kernel_status(&mut self, subject: &str, now: u64) -> Result<SubjectStatus, String> {
        SubjectStatus::parse(
            &self
                .kernel
                .execute(json!({"command":"subject_status", "subject":subject, "now":now}))?,
        )
    }

    fn registered_key(&self, actor: &str) -> Result<Option<Vec<u8>>, String> {
        self.store
            .query_row(
                "SELECT public_key FROM adapter_keys WHERE actor = ?1",
                [actor],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)
    }

    /// C-10 `admission_certificate`: certifies `SHA-256(preimage)` for an actor whose
    /// `read` and `admit` grants are active and effective at `now`. It does not parse the
    /// preimage (C-13) and changes neither the kernel nor the sequencer.
    fn issue_certificate(&mut self, actor: &str, preimage: &[u8]) -> Result<Value, String> {
        let now = self.clock.now();
        let status = self.kernel_status(actor, now)?;
        let (Some(read_generation), Some(admit_generation)) = (
            status.effective_generation(Right::Read),
            status.effective_generation(Right::Admit),
        ) else {
            return Err("unauthorized".into());
        };
        let checkpoint = self.kernel.execute(json!({"command":"checkpoint"}))?;
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .ok_or("malformed: kernel policy_revision")?;
        let certificate = AdmissionCertificate {
            apf_key_id: self.apf_key_id(),
            group: self.group.clone(),
            subject: actor.to_owned(),
            read_generation,
            admit_generation,
            policy_revision,
            not_after: status.expires_at.unwrap_or(u64::MAX),
            key_package_preimage_hash: Sha256::digest(preimage).to_vec(),
        }
        .sign(&self.apf)?;
        Ok(json!({"certificate": hex::encode(certificate)}))
    }

    /// C-10 `submit_commit` with the C-11 checks in order. Steps 2-7 change neither the
    /// sequencer nor the kernel on failure: the commit is staged on the in-memory
    /// `PublicGroup` and merged only after the kernel `admit` has committed.
    fn sequence_commit(
        &mut self,
        actor: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<(Value, CertificateRecord), String> {
        let now = self.clock.now();
        // Step 1 (the group itself was checked in `prepare`).
        let current = self.frontier()?;
        if *parent != current {
            return Err("stale_frontier".into());
        }
        let actor_key = self
            .registered_key(actor)?
            .ok_or_else(|| noncanonical("actor key"))?;

        // Steps 2-4.
        let (staged, key_package) = self
            .sequencer
            .as_ref()
            .ok_or("uninitialized: no group")?
            .stage(self.provider.crypto(), commit, actor, &actor_key)?;

        // Step 5.
        let (subject, certificate) = self.check_admission(&key_package, now)?;

        // Step 6.
        let parent_accs = self
            .sequencer
            .as_ref()
            .ok_or("uninitialized: no group")?
            .acc_payloads();
        let successor_accs = unknown_payloads(
            staged.group_context().extensions(),
            ACC_CONTEXT_EXTENSION_TYPE,
        );
        if parent_accs.len() != 1 || successor_accs != parent_accs {
            return Err(noncanonical("acc_context changed"));
        }

        // Step 7: the kernel CAS and authorization; its errors pass through.
        let successor = context_frontier(staged.group_context())?;
        self.kernel.execute(json!({
            "command":"admit", "actor":actor, "subject":subject, "now":now,
            "parent_branch":current.branch, "new_branch":successor.branch,
            "epoch":successor.epoch,
        }))?;

        // Step 8. A failure from here on leaves the kernel ahead of the sequencer; see the
        // crash gap in the phase report.
        self.sequencer
            .as_mut()
            .ok_or("uninitialized: no group")?
            .merge(staged)?;
        let ack = CanonicalAck {
            apf_key_id: self.apf_key_id(),
            group: self.group.clone(),
            parent: current,
            successor: successor.clone(),
            commit_hash: Sha256::digest(commit).to_vec(),
            kind: AckKind::Admit,
        }
        .sign(&self.apf)?;
        let record = CertificateRecord {
            signature_key: key_package.leaf_node().signature_key().as_slice().to_vec(),
            subject,
            epoch: successor.epoch,
            branch: successor.branch.clone(),
            certificate,
        };
        Ok((
            json!({"epoch":successor.epoch, "branch":successor.branch, "ack":hex::encode(ack)}),
            record,
        ))
    }

    /// C-11 step 5: every certificate, key and incarnation check on the added KeyPackage.
    /// Returns the admitted subject and its exact certificate bytes.
    fn check_admission(
        &mut self,
        key_package: &KeyPackage,
        now: u64,
    ) -> Result<(String, Vec<u8>), String> {
        let certificates = unknown_payloads(key_package.extensions(), ADMISSION_EXTENSION_TYPE);
        let [certificate_bytes] = certificates.as_slice() else {
            return Err(noncanonical("admission certificate count"));
        };
        let certificate = AdmissionCertificate::verify(
            certificate_bytes,
            self.apf.public(),
            self.provider.crypto(),
        )
        .map_err(|_| noncanonical("admission certificate"))?;
        if certificate.apf_key_id != self.apf_key_id() || certificate.group != self.group {
            return Err(noncanonical("certificate issuer or group"));
        }
        let preimage = key_package
            .canonical_binding_bytes(ADMISSION_EXTENSION_TYPE)
            .map_err(|_| noncanonical("KeyPackage preimage"))?;
        if Sha256::digest(&preimage).as_slice() != certificate.key_package_preimage_hash {
            return Err(noncanonical("KeyPackage preimage hash"));
        }

        let leaf = key_package.leaf_node();
        let subject = certificate.subject.clone();
        if credential_identity(leaf.credential()).as_deref() != Some(subject.as_bytes()) {
            return Err(noncanonical("credential subject"));
        }
        let subject_key = self
            .registered_key(&subject)?
            .ok_or_else(|| noncanonical("subject key"))?;
        if leaf.signature_key().as_slice() != subject_key.as_slice() {
            return Err(noncanonical("leaf signature key"));
        }

        let status = self.kernel_status(&subject, now)?;
        if status.effective_generation(Right::Read) != Some(certificate.read_generation)
            || status.effective_generation(Right::Admit) != Some(certificate.admit_generation)
        {
            return Err(noncanonical("certified generations"));
        }
        if certificate.not_after < now {
            return Err(noncanonical("certificate expired"));
        }

        let incarnations = unknown_payloads(leaf.extensions(), AUTHZ_INCARNATION_EXTENSION_TYPE);
        let [incarnation] = incarnations.as_slice() else {
            return Err(noncanonical("authz_incarnation count"));
        };
        let incarnation = AuthzIncarnation::decode(incarnation)
            .map_err(|_| noncanonical("authz_incarnation encoding"))?;
        if incarnation.subject != subject
            || incarnation.rights != status.active_rights()
            || incarnation.admission_cert_hash != ZERO_HASH
        {
            return Err(noncanonical("authz_incarnation"));
        }
        Ok((subject, certificate_bytes.clone()))
    }
}

/// A 32-byte seed, zeroed on drop (best effort).
struct Seed([u8; KEY_LEN]);

impl Drop for Seed {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Genesis in progress (C-8): the APF key, founder certificate and genesis
/// `acc_context` exist in memory only; nothing is written until `complete`.
pub struct GenesisPending<P: OpenMlsProvider, C: Clock> {
    provider: P,
    clock: C,
    dir: PathBuf,
    group: String,
    root: String,
    root_key: [u8; KEY_LEN],
    /// The root's generation-0 rights that kernel `init` creates.
    rights: Vec<(Right, u64)>,
    seed: Seed,
    apf: SignatureKeyPair,
    founder_certificate: Vec<u8>,
    acc_context: Vec<u8>,
}

impl<P: OpenMlsProvider, C: Clock> GenesisPending<P, C> {
    pub fn apf_public_key(&self) -> &[u8] {
        self.apf.public()
    }

    /// Signed founder certificate bytes for the root client.
    pub fn founder_certificate(&self) -> &[u8] {
        &self.founder_certificate
    }

    /// Encoded genesis `acc_context` payload for the root client.
    pub fn acc_context(&self) -> &[u8] {
        &self.acc_context
    }

    /// Validates the root's group, writes the adapter files and initializes the kernel
    /// at the genesis frontier (C-8, §5.1 steps 4-5).
    pub fn complete(self, group_info: &[u8], ratchet_tree: &[u8]) -> Result<Adapter<P, C>, String> {
        // §5.1 step 4 in memory: nothing is written unless the group validates.
        let frontier = self.validate(group_info, ratchet_tree)?;

        let GenesisPending {
            provider,
            clock,
            dir,
            group,
            root,
            root_key,
            seed,
            apf,
            founder_certificate,
            acc_context,
            ..
        } = self;
        let acc = AccContext::decode(&acc_context)?;
        let paths = AdapterPaths::new(&dir);
        let mut claimed = Claimed::default();
        let result = (|| {
            let mut key_file = claimed.claim(&paths.key, true)?;
            claimed.claim(&paths.authority, false)?;
            claimed.claim(&paths.adapter, false)?;
            claimed.claim(&paths.sequencer, false)?;
            key_file
                .write_all(&seed.0)
                .and_then(|()| key_file.sync_all())
                .map_err(|_| "malformed: cannot write apf key file".to_string())?;
            drop(key_file);

            // §5.1 step 5: the kernel starts at the genesis frontier, with the policy
            // the group's acc_context already commits to.
            let mut kernel = Authority::open(&paths.authority)?;
            kernel.execute(
                json!({"command":"init", "group":group, "root":root, "branch":frontier.branch}),
            )?;
            let checkpoint = kernel.execute(json!({"command":"checkpoint"}))?;
            if checkpoint["policy_revision"] != json!(acc.policy_revision)
                || checkpoint["policy_digest"] != json!(hex::encode(&acc.policy_digest))
            {
                return Err("binding_mismatch: genesis policy digest".to_string());
            }

            let founder = CertificateRecord {
                signature_key: root_key.to_vec(),
                subject: root.clone(),
                epoch: frontier.epoch,
                branch: frontier.branch.clone(),
                certificate: founder_certificate,
            };
            let store = init_store(
                &paths.adapter,
                &group,
                apf.public(),
                &root,
                &root_key,
                Some(&founder),
            )?;
            let sequencer = Sequencer::create(
                &paths.sequencer,
                provider.crypto(),
                group_info,
                ratchet_tree,
            )?;
            if sequencer.frontier()? != frontier {
                return Err("binding_mismatch: sequencer frontier".to_string());
            }
            sync_dir(&dir);
            Ok((kernel, store, sequencer))
        })();
        drop(seed);

        match result {
            Ok((kernel, store, sequencer)) => Ok(Adapter {
                provider,
                clock,
                group,
                apf,
                kernel,
                store,
                sequencer: Some(sequencer),
            }),
            Err(err) => {
                claimed.undo();
                Err(err)
            }
        }
    }

    /// §5.1 step 4: builds a throwaway `PublicGroup` in memory and checks the group id,
    /// epoch, ciphersuite, the single root leaf, its key and `authz_incarnation`, the
    /// required capabilities and the exact genesis `acc_context`. Returns the frontier.
    fn validate(&self, group_info: &[u8], ratchet_tree: &[u8]) -> Result<Frontier, String> {
        let mismatch = |detail: &str| format!("binding_mismatch: genesis {detail}");
        let storage = MemoryStorage::default();
        let (public, _) = PublicGroup::from_external(
            self.provider.crypto(),
            &storage,
            parse_ratchet_tree(ratchet_tree)?,
            parse_group_info(group_info)?,
            ProposalStore::new(),
        )
        .map_err(|err| format!("binding_mismatch: group state {err:?}"))?;

        let context = public.group_context();
        if context.group_id().as_slice() != self.group.as_bytes()
            || context.epoch().as_u64() != 0
            || context.ciphersuite() != CIPHERSUITE
        {
            return Err(mismatch("group id, epoch or ciphersuite"));
        }
        let accs = unknown_payloads(context.extensions(), ACC_CONTEXT_EXTENSION_TYPE);
        if accs != [self.acc_context.clone()] {
            return Err(mismatch("acc_context"));
        }
        let required = context
            .required_capabilities()
            .ok_or_else(|| mismatch("required capabilities"))?
            .extension_types();
        if !ADAPTER_EXTENSIONS
            .iter()
            .all(|t| required.contains(&ExtensionType::Unknown(*t)))
        {
            return Err(mismatch("required capabilities"));
        }

        let members: Vec<Member> = public.members().collect();
        let [member] = members.as_slice() else {
            return Err(mismatch("member count"));
        };
        let leaf = public
            .leaf(member.index)
            .ok_or_else(|| mismatch("root leaf"))?;
        if credential_identity(leaf.credential()).as_deref() != Some(self.root.as_bytes())
            || leaf.signature_key().as_slice() != self.root_key.as_slice()
        {
            return Err(mismatch("root credential or key"));
        }
        if !ADAPTER_EXTENSIONS.iter().all(|t| {
            leaf.capabilities()
                .extensions()
                .contains(&ExtensionType::Unknown(*t))
        }) {
            return Err(mismatch("root capabilities"));
        }
        let incarnations = unknown_payloads(leaf.extensions(), AUTHZ_INCARNATION_EXTENSION_TYPE);
        let expected = AuthzIncarnation {
            version: 1,
            subject: self.root.clone(),
            rights: self.rights.clone(),
            admission_cert_hash: Sha256::digest(&self.founder_certificate).to_vec(),
        }
        .encode()?;
        if incarnations != [expected] {
            return Err(mismatch("root authz_incarnation"));
        }
        context_frontier(context)
    }
}
