//! Trusted adapter between authenticated clients, OpenMLS evidence and the APF kernel.
//!
//! Phase 4.1 surface: the APF signing key, client identities, signed requests
//! and the trusted clock (`docs/adapter-contract.md` §4.8, §4.9, §7, §8).
//! The kernel stays key-free; only this adapter calls `Authority::execute`.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::SignatureScheme;
use openmls_traits::{random::OpenMlsRand, signatures::Signer, OpenMlsProvider};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tls_codec::{Serialize as TlsSerialize, VLBytes};

use crate::authority::Authority;

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
/// Kernel commands only the adapter itself may issue (C-3).
const ADAPTER_ONLY: [&str; 5] = ["init", "admit", "repair", "repair_stage", "repair_open"];
/// Kernel commands routed from phase 4.3 on (C-3).
const NOT_YET_ROUTED: [&str; 5] = ["release", "persist", "emit", "consume", "abandon"];

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

            let store = open_store(&paths.adapter, true)?;
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
                    params![group, hex::encode(apf.public())],
                )?;
                store.execute(
                    "INSERT INTO adapter_keys(actor, public_key) VALUES (?1, ?2)",
                    params![root, root_key.as_slice()],
                )?;
                store.execute_batch("COMMIT")
            })();
            if let Err(err) = populate {
                let _ = store.execute_batch("ROLLBACK");
                return Err(db(err));
            }
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

        Ok(Self {
            provider,
            clock,
            group,
            apf,
            kernel,
            store,
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
            Ok((command, kernel_request, registration)) => {
                let outcome = self.kernel.execute(kernel_request);
                (Some(command), outcome.map(|value| (value, registration)))
            }
        };
        let result = (|| -> rusqlite::Result<()> {
            match &outcome {
                Ok((_, registration)) => {
                    if let Some((subject, key)) = registration {
                        self.store.execute(
                            "INSERT INTO adapter_keys(actor, public_key) VALUES (?1, ?2)",
                            params![subject, key.as_slice()],
                        )?;
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

    /// C-4 step 5: parses and checks the body (C-1 to C-3) and builds the kernel request.
    /// Returns the command, the kernel request and the key to register on kernel success.
    #[allow(clippy::type_complexity)]
    fn prepare(
        &mut self,
        actor: &str,
        body: &[u8],
    ) -> Result<(String, Value, Option<(String, [u8; KEY_LEN])>), (Option<String>, String)> {
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
        Ok((command, Value::Object(fields), registration))
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

/// The three adapter files of one directory.
struct AdapterPaths {
    authority: PathBuf,
    adapter: PathBuf,
    key: PathBuf,
}

impl AdapterPaths {
    fn new(dir: &Path) -> Self {
        Self {
            authority: dir.join(AUTHORITY_FILE),
            adapter: dir.join(ADAPTER_FILE),
            key: dir.join(APF_KEY_FILE),
        }
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
