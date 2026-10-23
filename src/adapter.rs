//! Trusted adapter between authenticated clients, OpenMLS evidence and the APF kernel.
//!
//! Phase 4.1 surface: the APF signing key, client identities, signed requests
//! and the trusted clock (`docs/adapter-contract.md` §4.8, §4.9, §7, §8).
//! Phase 4.2 surface: genesis, the public sequencer and admission (§4.10, §5.1, §5.2).
//! Phase 4.3 surface: release certificates, persist, emit, consume receipts and
//! operation ownership (§4.11, §5.3).
//! Phase 4.4a surface: read revocation, the repair plan, repair commits, confirmation
//! and the full-adapter grant rules (§4.12, §5.4, the read part of §5.5).
//! Phase 4.4b surface: rekey offers, update commits and key rotation for current members
//! (C-28, C-29, the non-read part of §5.5).
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
    AccContext, AckKind, AdmissionCertificate, AuthzIncarnation, CanonicalAck, ConsumeReceipt,
    Envelope, FounderCertificate, Frontier, ReleaseCertificate, RepairConfirmation, Right,
    SignedStructure, ACC_CONTEXT_EXTENSION_TYPE, ADMISSION_EXTENSION_TYPE,
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
/// Kernel commands only the adapter itself may issue (C-3, C-7, C-29).
const ADAPTER_ONLY: [&str; 7] = [
    "init",
    "admit",
    "repair",
    "repair_stage",
    "repair_open",
    "rekey",
    "subject_status",
];
/// Content commands routed from phase 4.3 on (C-16); a policy-only adapter (C-8) has no
/// group to bind content to and keeps them unsupported (C-3).
const CONTENT_COMMANDS: [&str; 5] = ["release", "persist", "emit", "consume", "abandon"];
/// Adapter flows `handle` routes in phase 4.2 (C-10); they are not kernel commands.
const CERTIFICATE_FLOW: &str = "admission_certificate";
const SUBMIT_FLOW: &str = "submit_commit";
/// Adapter flows `handle` routes in phase 4.4a (C-20, C-23).
const REPAIR_PLAN_FLOW: &str = "repair_plan";
const CONFIRM_FLOW: &str = "confirm_repair";
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
        // Stores written before phase 4.3 gain the operations table (C-17).
        store.execute_batch(OPERATIONS_TABLE).map_err(db)?;
        // Stores written before phase 4.4a gain the repair tables (C-22, C-23).
        store.execute_batch(REPAIR_TABLES).map_err(db)?;
        // Stores written before phase 4.4b gain the offers table (C-28).
        store.execute_batch(OFFERS_TABLE).map_err(db)?;
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
                let outcome = outcome.map(|value| {
                    let effect = match registration {
                        Some((subject, key)) => Effect::Register(subject, key),
                        // C-17: the allocating actor is recorded with the trace event.
                        None if command == "allocate" => match value["op"].as_str() {
                            Some(op) => Effect::Allocated(op.to_owned(), actor.to_owned()),
                            None => Effect::None,
                        },
                        None => Effect::None,
                    };
                    (value, effect)
                });
                (Some(command), outcome)
            }
            Ok((command, Routed::Content(content))) => {
                let outcome = self.content(actor, content);
                (Some(command), outcome)
            }
            Ok((command, Routed::Certificate(preimage))) => {
                let outcome = self.issue_certificate(actor, &preimage);
                (Some(command), outcome.map(|value| (value, Effect::None)))
            }
            Ok((command, Routed::Offer(offer))) => {
                let outcome = self.check_offer(actor, &offer);
                (
                    Some(command),
                    outcome.map(|()| (json!({"pending": true}), Effect::Offered(offer))),
                )
            }
            Ok((command, Routed::Submit(AckKind::Update, parent, commit))) => {
                let outcome = self.sequence_update(actor, &parent, &commit);
                (
                    Some(command),
                    outcome.map(|(value, record)| (value, Effect::Rekeyed(record))),
                )
            }
            Ok((command, Routed::Submit(AckKind::Repair, parent, commit))) => {
                let outcome = self.sequence_repair(actor, &parent, &commit);
                (
                    Some(command),
                    outcome.map(|(value, record)| (value, Effect::RepairStaged(record))),
                )
            }
            Ok((command, Routed::Submit(_, parent, commit))) => {
                let outcome = self.sequence_commit(actor, &parent, &commit);
                (
                    Some(command),
                    outcome.map(|(value, record)| (value, Effect::Admitted(record))),
                )
            }
            Ok((command, Routed::RepairPlan)) => {
                let outcome = self.repair_plan(actor);
                (Some(command), outcome.map(|value| (value, Effect::None)))
            }
            Ok((command, Routed::Confirm(confirmation))) => {
                let outcome = self.confirm_repair(actor, &confirmation);
                (
                    Some(command),
                    outcome.map(|(value, record)| (value, Effect::Confirmed(record))),
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
                        Effect::Allocated(op, owner) => {
                            self.store.execute(
                                "INSERT INTO adapter_operations(op, actor) VALUES (?1, ?2)",
                                params![op, owner],
                            )?;
                        }
                        Effect::Released(op, certificate) => {
                            self.store.execute(
                                "UPDATE adapter_operations SET certificate = ?2
                                 WHERE op = ?1 AND certificate IS NULL",
                                params![op, certificate],
                            )?;
                        }
                        Effect::Persisted(op, envelope) => {
                            self.store.execute(
                                "UPDATE adapter_operations SET envelope = ?2
                                 WHERE op = ?1 AND envelope IS NULL",
                                params![op, envelope],
                            )?;
                        }
                        Effect::RepairStaged(record) => insert_repair(&self.store, record)?,
                        Effect::Confirmed(record) => insert_confirmation(&self.store, record)?,
                        Effect::Offered(offer) => insert_offer(&self.store, offer)?,
                        Effect::Rekeyed(record) => rotate_key(&self.store, record)?,
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
        // C-10, C-11 step 1, C-20, C-22 step 1 and C-23: adapter flows exist only on a
        // full adapter.
        if [
            CERTIFICATE_FLOW,
            SUBMIT_FLOW,
            REPAIR_PLAN_FLOW,
            CONFIRM_FLOW,
        ]
        .contains(&command.as_str())
        {
            if self.sequencer.is_none() {
                return Err((Some(command), "uninitialized: no group".into()));
            }
            let routed = match command.as_str() {
                CERTIFICATE_FLOW => parse_certificate_body(&fields).map(Routed::Certificate),
                SUBMIT_FLOW => parse_submit_body(&fields)
                    .map(|(kind, parent, commit)| Routed::Submit(kind, parent, commit)),
                REPAIR_PLAN_FLOW => only_fields(&fields, &["command"]).map(|()| Routed::RepairPlan),
                _ => only_fields(&fields, &["command", "confirmation"])
                    .and_then(|()| lower_hex_field(&fields, "confirmation"))
                    .map(Routed::Confirm),
            };
            return routed
                .map(|routed| (command.clone(), routed))
                .map_err(|err| (Some(command), err));
        }
        // C-16 and C-17.
        if CONTENT_COMMANDS.contains(&command.as_str()) {
            if self.sequencer.is_none() {
                return Err((Some(command), "malformed: unsupported command".into()));
            }
            return self
                .parse_content(actor, &command, fields)
                .map(|content| (command.clone(), Routed::Content(content)))
                .map_err(|err| (Some(command), err));
        }
        // C-3.
        if !ROUTED.contains(&command.as_str()) {
            let err = if ADAPTER_ONLY.contains(&command.as_str()) {
                "unauthorized".to_string()
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

        // C-25 as amended by C-28: on a full adapter a grant never reaches the kernel for
        // a current roster member; it becomes a pending rekey offer. For any other subject
        // the adapter, not the worker, sets `fresh_keys`. The evidence is the new
        // KeyPackage certified at the new generation that admission (C-11) later requires.
        if command == "grant" && self.sequencer.is_some() {
            if let Some(subject) = fields.get("subject").and_then(Value::as_str) {
                if self
                    .roster_contains(subject)
                    .map_err(|err| (Some(command.clone()), err))?
                {
                    return parse_offer(actor, subject, &fields)
                        .map(|offer| (command.clone(), Routed::Offer(offer)))
                        .map_err(|err| (Some(command), err));
                }
            }
            fields.insert("fresh_keys".into(), json!(true));
        }

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
    if let Err(err) = store
        .execute_batch(OPERATIONS_TABLE)
        .and_then(|()| store.execute_batch(REPAIR_TABLES))
        .and_then(|()| store.execute_batch(OFFERS_TABLE))
    {
        let _ = store.execute_batch("ROLLBACK");
        return Err(db(err));
    }
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
    /// `submit_commit` of this kind, on this parent frontier, of these commit bytes
    /// (C-10, C-22).
    Submit(AckKind, Frontier, Vec<u8>),
    /// `repair_plan {}` (C-20).
    RepairPlan,
    /// A grant to a current roster member, recorded as a pending rekey offer (C-28).
    Offer(Offer),
    /// `confirm_repair` with these signed confirmation bytes (C-23).
    Confirm(Vec<u8>),
    /// A content command whose body and ownership are already checked (C-16, C-17).
    Content(Content),
}

/// The adapter store change that commits together with a successful request's trace event.
enum Effect {
    None,
    Register(String, [u8; KEY_LEN]),
    Admitted(CertificateRecord),
    /// C-17: `op` was allocated by this actor.
    Allocated(String, String),
    /// C-16: the signed release certificate issued for `op`.
    Released(String, Vec<u8>),
    /// §6: the exact envelope bytes persisted for `op`.
    Persisted(String, Vec<u8>),
    /// C-22 step 7: the pending repair and its committer.
    RepairStaged(RepairRecord),
    /// C-23: an accepted confirmation hash, and the evidence if it opened the fence.
    Confirmed(ConfirmationRecord),
    /// C-28: a pending offer that replaces any older one for its subject.
    Offered(Offer),
    /// C-28 step 7: the subject's rotated key and its cleared offer.
    Rekeyed(RekeyRecord),
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

/// `submit_commit {kind: "admit" | "repair" | "update", parent_epoch, parent_branch,
/// commit}` (C-10, C-22, C-28).
fn parse_submit_body(
    fields: &serde_json::Map<String, Value>,
) -> Result<(AckKind, Frontier, Vec<u8>), String> {
    only_fields(
        fields,
        &["command", "kind", "parent_epoch", "parent_branch", "commit"],
    )?;
    let kind = match fields.get("kind").and_then(Value::as_str) {
        Some("admit") => AckKind::Admit,
        Some("repair") => AckKind::Repair,
        Some("update") => AckKind::Update,
        _ => return Err("malformed: kind".into()),
    };
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
    Ok((kind, Frontier { epoch, branch }, commit))
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
        let (staged, sender) = self.process_commit(crypto, commit, actor, actor_key)?;

        // Step 4: exactly one Add and nothing else, with an UpdatePath.
        let proposals: Vec<&QueuedProposal> = staged.queued_proposals().collect();
        if proposals.len() != 1 || !matches!(proposals[0].proposal(), Proposal::Add(_)) {
            return Err(noncanonical("proposals"));
        }
        check_path_leaf(&staged, &sender)?;
        let key_package = staged
            .add_proposals()
            .next()
            .map(|add| add.add_proposal().key_package().clone())
            .ok_or_else(|| noncanonical("no Add"))?;
        Ok((staged, key_package))
    }

    /// C-11 and C-22 steps 2-3: the commit is a `PublicMessage` commit for this group and
    /// epoch that `PublicGroup::process_message` accepts, and its sender leaf is the
    /// authenticated actor under its registered key. Nothing is merged or written.
    /// Returns the staged commit and the sender's parent-epoch leaf.
    fn process_commit(
        &self,
        crypto: &impl OpenMlsCrypto,
        commit: &[u8],
        actor: &str,
        actor_key: &[u8],
    ) -> Result<(StagedCommit, LeafNode), String> {
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
        let sender = sender.clone();
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(noncanonical("not a commit"));
        };
        Ok((*staged, sender))
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

/// C-11 and C-22 step 4: the commit carries an UpdatePath, and the path leaf keeps the
/// sender's credential, key and extensions, so a commit cannot relabel the committer's
/// own `authz_incarnation`.
fn check_path_leaf(staged: &StagedCommit, sender: &LeafNode) -> Result<(), String> {
    let path_leaf = staged
        .update_path_leaf_node()
        .ok_or_else(|| noncanonical("no UpdatePath"))?;
    if path_leaf.credential() != sender.credential()
        || path_leaf.signature_key() != sender.signature_key()
        || path_leaf.extensions() != sender.extensions()
    {
        return Err(noncanonical("UpdatePath leaf"));
    }
    Ok(())
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

// ---------------------------------------------------------------------------
// Phase 4.3: release certificates, persistence, emission and consumption
// (C-14 to C-17, §5.3)
// ---------------------------------------------------------------------------

/// The operations this adapter routed (C-17): the allocating actor, the signed release
/// certificate (C-16) and the exact persisted envelope (§6). No key material.
const OPERATIONS_TABLE: &str = "CREATE TABLE IF NOT EXISTS adapter_operations (
     op TEXT PRIMARY KEY,
     actor TEXT NOT NULL,
     certificate BLOB,
     envelope BLOB);";

/// Fields of a C-16 `release` body. `revision` is absent on purpose: only the R-3
/// `policy_revision` form is accepted.
const RELEASE_FIELDS: [&str; 9] = [
    "command",
    "op",
    "right",
    "resource",
    "digest",
    "cover",
    "policy_revision",
    "epoch",
    "branch",
];

/// A content command after its body and operation ownership have been checked.
enum Content {
    /// The kernel `release` request (with `actor` and `now`) and the released right.
    Release(Value, String, Right),
    /// `persist`: the operation, the decoded envelope and its exact bytes.
    Persist(String, Envelope, Vec<u8>),
    /// `emit`: the operation and the exact envelope bytes.
    Emit(String, Vec<u8>),
    Consume(String),
    Abandon(String),
}

/// A nonempty operation identifier within the kernel identifier bound.
fn op_field(fields: &serde_json::Map<String, Value>) -> Result<String, String> {
    match fields.get("op") {
        Some(Value::String(op)) if !op.is_empty() && op.len() <= MAX_COMMAND => Ok(op.clone()),
        _ => Err("malformed: op".into()),
    }
}

/// The `envelope` hex field, decoded into its two parts (C-14).
fn envelope_field(fields: &serde_json::Map<String, Value>) -> Result<(Envelope, Vec<u8>), String> {
    let bytes = lower_hex_field(fields, "envelope")?;
    let envelope = Envelope::decode(&bytes).map_err(|_| "malformed: envelope".to_string())?;
    Ok((envelope, bytes))
}

/// `writer_generation` and the sorted `readers` of a cover the kernel accepted (C-14).
/// The kernel has verified that the cover is exactly the writer's `write` singleton plus
/// one `read` singleton per roster reader, so each value is read off once.
fn cover_generations(cover: &Value, actor: &str) -> Result<(u64, Vec<(String, u64)>), String> {
    let malformed = || "malformed: accepted cover".to_string();
    let mut writer = None;
    let mut readers = Vec::new();
    for support in cover.as_array().ok_or_else(malformed)? {
        let [element] = support.as_array().ok_or_else(malformed)?.as_slice() else {
            return Err(malformed());
        };
        let subject = element["subject"].as_str().ok_or_else(malformed)?;
        let generation = element["generation"].as_u64().ok_or_else(malformed)?;
        match element["right"].as_str() {
            Some("write") if subject == actor && writer.is_none() => writer = Some(generation),
            Some("read") => readers.push((subject.to_owned(), generation)),
            _ => return Err(malformed()),
        }
    }
    readers.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    Ok((writer.ok_or_else(malformed)?, readers))
}

impl<P: OpenMlsProvider, C: Clock> Adapter<P, C> {
    /// C-16 body checks (`malformed`), then C-17 ownership (`unauthorized`), before any
    /// kernel call. The caller has already refused `actor` and `now` (C-2).
    fn parse_content(
        &mut self,
        actor: &str,
        command: &str,
        mut fields: serde_json::Map<String, Value>,
    ) -> Result<Content, String> {
        let content = match command {
            "release" => {
                only_fields(&fields, &RELEASE_FIELDS)?;
                let op = op_field(&fields)?;
                let right = match fields.get("right").and_then(Value::as_str) {
                    Some(name @ ("read" | "write")) => {
                        Right::from_name(name).ok_or("malformed: right")?
                    }
                    _ => return Err("malformed: right".into()),
                };
                if !fields.get("policy_revision").is_some_and(Value::is_u64) {
                    return Err("malformed: policy_revision".into());
                }
                fields.insert("actor".into(), json!(actor));
                fields.insert("now".into(), json!(self.clock.now()));
                Content::Release(Value::Object(fields), op, right)
            }
            "persist" | "emit" => {
                only_fields(&fields, &["command", "op", "envelope"])?;
                let op = op_field(&fields)?;
                let (envelope, bytes) = envelope_field(&fields)?;
                if command == "persist" {
                    Content::Persist(op, envelope, bytes)
                } else {
                    Content::Emit(op, bytes)
                }
            }
            "consume" => {
                // The recipient is always the authenticated actor (C-16).
                if fields.contains_key("recipient") {
                    return Err("malformed: recipient".into());
                }
                only_fields(&fields, &["command", "op"])?;
                Content::Consume(op_field(&fields)?)
            }
            "abandon" => {
                only_fields(&fields, &["command", "op"])?;
                Content::Abandon(op_field(&fields)?)
            }
            _ => return Err("malformed: unknown command".into()),
        };
        // C-17: only the allocating actor may act on its operation; any reader consumes.
        let op = match &content {
            Content::Release(_, op, _)
            | Content::Persist(op, _, _)
            | Content::Emit(op, _)
            | Content::Abandon(op) => Some(op),
            Content::Consume(_) => None,
        };
        if let Some(op) = op {
            if self.operation_owner(op)?.as_deref() != Some(actor) {
                return Err("unauthorized".into());
            }
        }
        Ok(content)
    }

    /// C-16: runs one checked content command and returns the response with the store
    /// effect that commits together with its trace event.
    fn content(&mut self, actor: &str, content: Content) -> Result<(Value, Effect), String> {
        let now = self.clock.now();
        match content {
            Content::Release(request, op, right) => {
                let mut response = self.kernel.execute(request.clone())?;
                // §4.5: signed in the same adapter step that observes the committed kernel
                // release. A failure from here on leaves a released operation without a
                // certificate; it can only be abandoned (B2).
                let certificate =
                    self.release_certificate(actor, &op, right, &request, &response)?;
                let signed = certificate.sign(&self.apf)?;
                response["certificate"] = json!(hex::encode(&signed));
                Ok((response, Effect::Released(op, signed)))
            }
            Content::Persist(op, envelope, bytes) => {
                let released = self.check_envelope(&op, &envelope)?;
                let response = self.kernel.execute(json!({
                    "command":"persist", "op":op, "digest":released.digest,
                    "envelope":hex::encode(&bytes), "actor":actor, "now":now,
                }))?;
                Ok((response, Effect::Persisted(op, bytes)))
            }
            Content::Emit(op, bytes) => {
                let response = self.kernel.execute(json!({
                    "command":"emit", "op":op, "envelope":hex::encode(&bytes),
                    "actor":actor, "now":now,
                }))?;
                Ok((response, Effect::None))
            }
            Content::Consume(op) => {
                // Only an operation released through this adapter can have been persisted.
                let certificate = self
                    .stored_certificate(&op)?
                    .ok_or_else(|| "not_persisted".to_string())?;
                let mut response = self.kernel.execute(json!({
                    "command":"consume", "op":op, "recipient":actor, "actor":actor, "now":now,
                }))?;
                // C-15. A failure from here on is a consumed, undelivered message (B5).
                let receipt = ConsumeReceipt {
                    apf_key_id: self.apf_key_id(),
                    group: self.group.clone(),
                    op,
                    recipient: actor.to_owned(),
                    release_certificate_hash: Sha256::digest(&certificate).to_vec(),
                }
                .sign(&self.apf)?;
                response["receipt"] = json!(hex::encode(receipt));
                Ok((response, Effect::None))
            }
            Content::Abandon(op) => {
                let response = self.kernel.execute(json!({
                    "command":"abandon", "op":op, "actor":actor, "now":now,
                }))?;
                Ok((response, Effect::None))
            }
        }
    }

    /// The release certificate TBS for a committed kernel release (§4.5, C-14).
    fn release_certificate(
        &self,
        actor: &str,
        op: &str,
        right: Right,
        request: &Value,
        response: &Value,
    ) -> Result<ReleaseCertificate, String> {
        let malformed = |field: &str| format!("malformed: kernel release {field}");
        let text = |field: &str| {
            response[field]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| malformed(field))
        };
        let number = |field: &str| response[field].as_u64().ok_or_else(|| malformed(field));
        if response["op"] != json!(op) {
            return Err(malformed("op"));
        }
        let invocation = match &response["invocation"] {
            Value::Null => String::new(),
            Value::String(id) => id.clone(),
            _ => return Err(malformed("invocation")),
        };
        let (writer_generation, readers) = cover_generations(&request["cover"], actor)?;
        Ok(ReleaseCertificate {
            apf_key_id: self.apf_key_id(),
            group: self.group.clone(),
            op: op.to_owned(),
            actor: actor.to_owned(),
            right,
            resource: text("resource")?,
            invocation,
            frontier: Frontier {
                epoch: number("epoch")?,
                branch: text("branch")?,
            },
            policy_revision: number("policy_revision")?,
            digest: text("digest")?,
            writer_generation,
            readers,
            kernel_event_hash: text("event_hash")?,
        })
    }

    /// C-16 `persist` envelope checks: the certificate is byte-identical to the one
    /// issued for `op`, and the MLS message is a `PrivateMessage` application message
    /// for this group at the certificate's epoch whose AAD is `SHA-256(certificate)`.
    /// The adapter cannot decrypt; the receiver checks the content (C-18).
    fn check_envelope(&self, op: &str, envelope: &Envelope) -> Result<ReleaseCertificate, String> {
        let mismatch = |detail: &str| format!("binding_mismatch: {detail}");
        let stored = self
            .stored_certificate(op)?
            .ok_or_else(|| "invalid_transition: not released".to_string())?;
        if envelope.certificate != stored {
            return Err(mismatch("certificate"));
        }
        let released =
            ReleaseCertificate::verify(&stored, self.apf.public(), self.provider.crypto())
                .map_err(|_| "corrupt_history: stored release certificate".to_string())?;
        let message = MlsMessageIn::tls_deserialize_exact(&envelope.mls_message)
            .map_err(|_| mismatch("MLS message encoding"))?;
        let MlsMessageBodyIn::PrivateMessage(private) = message.extract() else {
            return Err(mismatch("not a PrivateMessage"));
        };
        if private.group_id().as_slice() != self.group.as_bytes()
            || private.epoch().as_u64() != released.frontier.epoch
            || private.content_type() != ContentType::Application
        {
            return Err(mismatch("MLS group, epoch or content type"));
        }
        if private.aad() != Sha256::digest(&stored).as_slice() {
            return Err(mismatch("AAD"));
        }
        Ok(released)
    }

    /// The allocating actor recorded for `op` (C-17).
    fn operation_owner(&self, op: &str) -> Result<Option<String>, String> {
        self.store
            .query_row(
                "SELECT actor FROM adapter_operations WHERE op = ?1",
                [op],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)
    }

    /// The signed release certificate issued for `op`, if any.
    fn stored_certificate(&self, op: &str) -> Result<Option<Vec<u8>>, String> {
        let row: Option<Option<Vec<u8>>> = self
            .store
            .query_row(
                "SELECT certificate FROM adapter_operations WHERE op = ?1",
                [op],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(row.flatten())
    }
}

// ---------------------------------------------------------------------------
// Phase 4.4a: read revocation, repair plan, repair commits and confirmation
// (C-20 to C-25, §5.4)
// ---------------------------------------------------------------------------

/// Repairs this adapter sequenced (C-22 step 7) and the confirmation hashes it accepted
/// for each (C-23). `evidence` is null while the repair is pending, then `pair` or
/// `single`. No key material and no epoch authenticator: only its hash.
const REPAIR_TABLES: &str = "CREATE TABLE IF NOT EXISTS adapter_repairs (
     branch TEXT PRIMARY KEY,
     epoch TEXT NOT NULL,
     parent_epoch TEXT NOT NULL,
     parent_branch TEXT NOT NULL,
     committer TEXT NOT NULL,
     removed TEXT NOT NULL,
     commit_hash BLOB NOT NULL,
     evidence TEXT);
 CREATE TABLE IF NOT EXISTS adapter_confirmations (
     branch TEXT NOT NULL,
     actor TEXT NOT NULL,
     hash BLOB NOT NULL,
     PRIMARY KEY (branch, actor));";

/// Evidence reported when the fence opens (C-23).
const PAIR: &str = "pair";
const SINGLE: &str = "single";

/// A canonical repair commit and its committer (C-22 step 7).
struct RepairRecord {
    successor: Frontier,
    parent: Frontier,
    committer: String,
    /// JSON array of the removed subjects.
    removed: String,
    commit_hash: Vec<u8>,
}

/// One accepted confirmation (C-23), and the evidence if it opened the fence.
struct ConfirmationRecord {
    branch: String,
    actor: String,
    hash: Vec<u8>,
    evidence: Option<&'static str>,
}

fn insert_repair(store: &Connection, record: &RepairRecord) -> rusqlite::Result<()> {
    store.execute(
        "INSERT INTO adapter_repairs(branch, epoch, parent_epoch, parent_branch, committer,
                                     removed, commit_hash)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            record.successor.branch,
            record.successor.epoch.to_string(),
            record.parent.epoch.to_string(),
            record.parent.branch,
            record.committer,
            record.removed,
            record.commit_hash
        ],
    )?;
    Ok(())
}

/// Stores the actor's hash (an equal repeat is idempotent) and, if the fence opened, the
/// evidence on the repair record.
fn insert_confirmation(store: &Connection, record: &ConfirmationRecord) -> rusqlite::Result<()> {
    store.execute(
        "INSERT INTO adapter_confirmations(branch, actor, hash) VALUES (?1, ?2, ?3)
         ON CONFLICT(branch, actor) DO NOTHING",
        params![record.branch, record.actor, record.hash],
    )?;
    if let Some(evidence) = record.evidence {
        store.execute(
            "UPDATE adapter_repairs SET evidence = ?2 WHERE branch = ?1 AND evidence IS NULL",
            params![record.branch, evidence],
        )?;
    }
    Ok(())
}

/// The C-20 repair plan, derived from one kernel checkpoint.
struct RepairPlan {
    /// Sorted roster members whose read grant is inactive.
    removed: Vec<String>,
    /// The planned `acc_context` payload at the current policy revision and digest.
    acc_context: Vec<u8>,
    policy_revision: u64,
    parent: Frontier,
    roster: Vec<String>,
}

/// The kernel roster of a checkpoint.
fn checkpoint_roster(checkpoint: &Value) -> Result<Vec<String>, String> {
    checkpoint["roster"]
        .as_array()
        .ok_or("malformed: kernel roster")?
        .iter()
        .map(|name| {
            name.as_str()
                .map(str::to_owned)
                .ok_or_else(|| "malformed: kernel roster".to_string())
        })
        .collect()
}

impl<P: OpenMlsProvider, C: Clock> Adapter<P, C> {
    fn kernel_checkpoint(&mut self) -> Result<Value, String> {
        self.kernel.execute(json!({"command":"checkpoint"}))
    }

    /// C-25: whether `subject` is a current roster member.
    fn roster_contains(&mut self, subject: &str) -> Result<bool, String> {
        let checkpoint = self.kernel_checkpoint()?;
        Ok(checkpoint_roster(&checkpoint)?.iter().any(|m| m == subject))
    }

    /// C-20 as amended by C-27: the plan exists whenever the kernel is read-fenced and
    /// the removal set is not empty, whether or not a repair is pending. A stacked plan is
    /// computed at the current kernel frontier, which is the pending repair's successor.
    fn plan_from(&self, checkpoint: &Value) -> Result<RepairPlan, String> {
        if checkpoint["read_fenced"] != json!(true) {
            return Err("invalid_repair: not read-fenced".into());
        }
        let roster = checkpoint_roster(checkpoint)?;
        let grants = checkpoint["grants"]
            .as_array()
            .ok_or("malformed: kernel grants")?;
        let read_active = |subject: &str| {
            grants.iter().any(|g| {
                g["subject"] == json!(subject)
                    && g["right"] == json!("read")
                    && g["active"] == json!(true)
            })
        };
        let mut removed: Vec<String> = roster
            .iter()
            .filter(|member| !read_active(member))
            .cloned()
            .collect();
        removed.sort();
        if removed.is_empty() {
            return Err("invalid_repair: no reader to remove".into());
        }
        let policy_revision = checkpoint["policy_revision"]
            .as_u64()
            .ok_or("malformed: kernel policy_revision")?;
        let policy_digest = checkpoint["policy_digest"]
            .as_str()
            .and_then(|digest| hex::decode(digest).ok())
            .ok_or("malformed: kernel policy_digest")?;
        let acc_context = AccContext {
            version: 1,
            apf_key_id: self.apf_key_id(),
            group: self.group.clone(),
            policy_revision,
            policy_digest,
        }
        .encode()?;
        Ok(RepairPlan {
            removed,
            acc_context,
            policy_revision,
            parent: checkpoint_frontier(checkpoint)?,
            roster,
        })
    }

    /// C-20 `repair_plan {}`, for a current roster member. It changes nothing.
    fn repair_plan(&mut self, actor: &str) -> Result<Value, String> {
        let checkpoint = self.kernel_checkpoint()?;
        if !checkpoint_roster(&checkpoint)?.iter().any(|m| m == actor) {
            return Err("unauthorized: not a roster member".into());
        }
        let plan = self.plan_from(&checkpoint)?;
        Ok(json!({
            "removed": plan.removed,
            "acc_context": hex::encode(&plan.acc_context),
            "policy_revision": plan.policy_revision,
            "parent_epoch": plan.parent.epoch,
            "parent_branch": plan.parent.branch,
        }))
    }

    /// C-22 `submit_commit {kind: "repair"}` with its checks in order. Steps 1-5 change
    /// neither the sequencer nor the kernel on failure: the commit is staged on the
    /// in-memory `PublicGroup` and merged only after kernel `repair_stage` has committed.
    fn sequence_repair(
        &mut self,
        actor: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<(Value, RepairRecord), String> {
        // Step 1 (the group itself was checked in `prepare`).
        let checkpoint = self.kernel_checkpoint()?;
        let current = checkpoint_frontier(&checkpoint)?;
        if *parent != current {
            return Err("stale_frontier".into());
        }
        let plan = self.plan_from(&checkpoint)?;
        let actor_key = self
            .registered_key(actor)?
            .ok_or_else(|| noncanonical("actor key"))?;
        let sequencer = self.sequencer.as_ref().ok_or("uninitialized: no group")?;

        // Steps 2 and 3: OpenMLS accepts the commit and its sender is the actor's leaf
        // under its registered key; the actor is a continuing member (C-21).
        let (staged, sender) =
            sequencer.process_commit(self.provider.crypto(), commit, actor, &actor_key)?;
        if !plan.roster.iter().any(|m| m == actor) || plan.removed.iter().any(|m| m == actor) {
            return Err(noncanonical("committer is not a continuing member"));
        }

        // Step 4: exactly one Remove per leaf of a removed subject, no other Remove,
        // exactly one GroupContextExtensions proposal, nothing else, and an UpdatePath.
        let mut expected = Vec::new();
        for subject in &plan.removed {
            let before = expected.len();
            expected.extend(
                sequencer
                    .group
                    .members()
                    .filter(|member| {
                        credential_identity(&member.credential).as_deref()
                            == Some(subject.as_bytes())
                    })
                    .map(|member| member.index.u32()),
            );
            if expected.len() == before {
                return Err(noncanonical("removed subject has no leaf"));
            }
        }
        expected.sort_unstable();
        let mut removes = Vec::new();
        let (mut extension_proposals, mut others) = (0usize, 0usize);
        for queued in staged.queued_proposals() {
            match queued.proposal() {
                Proposal::Remove(remove) => removes.push(remove.removed().u32()),
                Proposal::GroupContextExtensions(_) => extension_proposals += 1,
                _ => others += 1,
            }
        }
        removes.sort_unstable();
        if removes != expected {
            return Err(noncanonical("Remove set"));
        }
        if extension_proposals != 1 || others != 0 {
            return Err(noncanonical("proposals"));
        }
        // Defense in depth: RFC 9420 §12.4.2 already requires the path for these proposals.
        check_path_leaf(&staged, &sender)?;

        // Step 5: the successor extensions are the parent's with exactly the acc_context
        // replaced by the planned bytes.
        let mut accs = 0;
        let mut planned = Vec::new();
        for extension in sequencer.group.group_context().extensions().iter() {
            match extension {
                Extension::Unknown(t, _) if *t == ACC_CONTEXT_EXTENSION_TYPE => {
                    accs += 1;
                    planned.push(Extension::Unknown(
                        ACC_CONTEXT_EXTENSION_TYPE,
                        UnknownExtension(plan.acc_context.clone()),
                    ));
                }
                other => planned.push(other.clone()),
            }
        }
        if accs != 1 {
            return Err(noncanonical("parent acc_context count"));
        }
        let successor_extensions: Vec<Extension> = staged
            .group_context()
            .extensions()
            .iter()
            .cloned()
            .collect();
        if successor_extensions != planned {
            return Err(noncanonical("successor GroupContext extensions"));
        }

        // Step 6: the kernel CAS; the Remove set and the path are proven above. Kernel
        // errors pass through.
        let successor = context_frontier(staged.group_context())?;
        self.kernel.execute(json!({
            "command":"repair_stage", "parent_branch":current.branch,
            "new_branch":successor.branch, "epoch":successor.epoch,
            "policy_revision":plan.policy_revision, "removed":plan.removed,
            "update_path":true, "durable":true,
        }))?;

        // Step 7. A failure from here on leaves the kernel ahead of the sequencer or the
        // adapter store; see the crash gaps in the phase report.
        self.sequencer
            .as_mut()
            .ok_or("uninitialized: no group")?
            .merge(staged)?;
        let commit_hash = Sha256::digest(commit).to_vec();
        let ack = CanonicalAck {
            apf_key_id: self.apf_key_id(),
            group: self.group.clone(),
            parent: current.clone(),
            successor: successor.clone(),
            commit_hash: commit_hash.clone(),
            kind: AckKind::Repair,
        }
        .sign(&self.apf)?;
        let record = RepairRecord {
            successor: successor.clone(),
            parent: current,
            committer: actor.to_owned(),
            removed: serde_json::to_string(&plan.removed)
                .map_err(|_| "malformed: removed".to_string())?,
            commit_hash,
        };
        Ok((
            json!({"epoch":successor.epoch, "branch":successor.branch, "ack":hex::encode(ack)}),
            record,
        ))
    }

    /// C-23 `confirm_repair {confirmation}`. A rejected confirmation is not stored.
    ///
    /// C-27: only the latest pending repair can be confirmed. A confirmation of a
    /// superseded repair names a frontier that is no longer current (`invalid_repair`),
    /// and hashes are read for the pending branch only, so confirmations stored for a
    /// superseded repair never count.
    ///
    /// The committer's hash is the reference (§5.4 step 5). A non-committer's hash that
    /// differs from it, or any actor's hash that differs from its own earlier one, is
    /// `binding_mismatch`. The fence opens through kernel `repair_open` once the
    /// committer's hash and an equal one from another continuing member are held, or on
    /// the committer's alone when it is the only continuing member.
    fn confirm_repair(
        &mut self,
        actor: &str,
        bytes: &[u8],
    ) -> Result<(Value, ConfirmationRecord), String> {
        let checkpoint = self.kernel_checkpoint()?;
        let pending = checkpoint["repair_pending"]
            .as_str()
            .map(str::to_owned)
            .ok_or("invalid_repair: no pending repair")?;
        let roster = checkpoint_roster(&checkpoint)?;
        if !roster.iter().any(|m| m == actor) {
            return Err("invalid_repair: not a roster member".into());
        }
        let key = self
            .registered_key(actor)?
            .ok_or_else(|| "unauthenticated".to_string())?;
        let confirmation = RepairConfirmation::verify(bytes, &key, self.provider.crypto())
            .map_err(|err| {
                if err.starts_with("unauthenticated") {
                    "unauthenticated".to_string()
                } else {
                    "malformed: confirmation".to_string()
                }
            })?;
        if confirmation.group != self.group {
            return Err("binding_mismatch: confirmation group".into());
        }
        let current = checkpoint_frontier(&checkpoint)?;
        if confirmation.frontier != current || current.branch != pending {
            return Err("invalid_repair: confirmation frontier".into());
        }
        let committer = self
            .repair_committer(&pending)?
            .ok_or("invalid_repair: no repair record")?;
        let stored = self.confirmations(&pending)?;
        let hash = confirmation.epoch_authenticator_hash;
        let stored_hash = |member: &str| {
            stored
                .iter()
                .find(|(who, _)| who == member)
                .map(|(_, h)| h.clone())
        };

        if stored_hash(actor).is_some_and(|own| own != hash) {
            return Err("binding_mismatch: changed confirmation".into());
        }
        let reference = if actor == committer {
            Some(hash.clone())
        } else {
            let reference = stored_hash(&committer);
            if reference.as_ref().is_some_and(|r| *r != hash) {
                return Err("binding_mismatch: epoch_authenticator_hash".into());
            }
            reference
        };
        let evidence = reference.and_then(|reference| {
            let others: Vec<&String> = roster.iter().filter(|m| **m != committer).collect();
            if others.is_empty() && roster.contains(&committer) {
                return Some(SINGLE);
            }
            others
                .iter()
                .any(|member| {
                    if member.as_str() == actor {
                        hash == reference
                    } else {
                        stored_hash(member).is_some_and(|h| h == reference)
                    }
                })
                .then_some(PAIR)
        });
        if evidence.is_some() {
            self.kernel.execute(json!({
                "command":"repair_open", "branch":pending, "confirmed":true,
            }))?;
        }
        Ok((
            json!({"opened": evidence.is_some(), "evidence": evidence}),
            ConfirmationRecord {
                branch: pending,
                actor: actor.to_owned(),
                hash,
                evidence,
            },
        ))
    }

    /// The committer recorded for the repair that produced `branch`.
    fn repair_committer(&self, branch: &str) -> Result<Option<String>, String> {
        self.store
            .query_row(
                "SELECT committer FROM adapter_repairs WHERE branch = ?1",
                [branch],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)
    }

    /// The `(actor, hash)` confirmations accepted for `branch`.
    fn confirmations(&self, branch: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
        let read = || -> rusqlite::Result<Vec<(String, Vec<u8>)>> {
            let mut stmt = self.store.prepare(
                "SELECT actor, hash FROM adapter_confirmations WHERE branch = ?1 ORDER BY actor",
            )?;
            let rows = stmt.query_map([branch], |row| Ok((row.get(0)?, row.get(1)?)))?;
            rows.collect()
        };
        read().map_err(db)
    }
}

// ---------------------------------------------------------------------------
// Phase 4.4b: rekey of a current member (C-28, C-29, R-10, the non-read part of §5.5)
// ---------------------------------------------------------------------------

/// Pending rekey offers (C-28): at most one per subject, a newer one replaces the older.
const OFFERS_TABLE: &str = "CREATE TABLE IF NOT EXISTS adapter_offers (
     subject TEXT PRIMARY KEY,
     right TEXT NOT NULL,
     generation TEXT NOT NULL,
     admin TEXT NOT NULL);";

/// A pending offer to re-authorize `subject` for `right` at `generation`, made by `admin`.
struct Offer {
    subject: String,
    right: Right,
    generation: u64,
    admin: String,
}

/// An accepted update commit (C-28 step 7): the subject's key moves from `old_key` to
/// `new_key` at the `successor` frontier.
struct RekeyRecord {
    subject: String,
    old_key: Vec<u8>,
    new_key: [u8; KEY_LEN],
    successor: Frontier,
}

/// C-28 offer body: `grant {subject, right, generation, fresh_keys?}` to a current member.
/// Read is never offered: it needs re-admission with a new KeyPackage (§5.5). The
/// worker's `fresh_keys` is ignored; the adapter derives it from the update commit.
fn parse_offer(
    actor: &str,
    subject: &str,
    fields: &serde_json::Map<String, Value>,
) -> Result<Offer, String> {
    only_fields(
        fields,
        &["command", "subject", "right", "generation", "fresh_keys"],
    )?;
    let right = match fields.get("right").and_then(Value::as_str) {
        Some(name @ ("write" | "admin" | "admit")) => {
            Right::from_name(name).ok_or("malformed: right")?
        }
        _ => return Err("malformed: right".into()),
    };
    let generation = fields
        .get("generation")
        .and_then(Value::as_u64)
        .ok_or("malformed: generation")?;
    if fields.get("fresh_keys").is_some_and(|v| !v.is_boolean()) {
        return Err("malformed: fresh_keys".into());
    }
    Ok(Offer {
        subject: subject.to_owned(),
        right,
        generation,
        admin: actor.to_owned(),
    })
}

fn insert_offer(store: &Connection, offer: &Offer) -> rusqlite::Result<()> {
    store.execute(
        "INSERT INTO adapter_offers(subject, right, generation, admin) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(subject) DO UPDATE SET
             right = excluded.right, generation = excluded.generation, admin = excluded.admin",
        params![
            offer.subject,
            offer.right.name(),
            offer.generation.to_string(),
            offer.admin
        ],
    )?;
    Ok(())
}

/// C-28 step 7 in the store transaction of the trace event: replaces the subject's
/// registered key, so the old key no longer authenticates; clears the offer; and indexes
/// the subject's retained admission or founder certificate under the new leaf key (§4.3).
fn rotate_key(store: &Connection, record: &RekeyRecord) -> rusqlite::Result<()> {
    let rotated = store.execute(
        "UPDATE adapter_keys SET public_key = ?2 WHERE actor = ?1 AND public_key = ?3",
        params![
            record.subject,
            record.new_key.as_slice(),
            record.old_key.as_slice()
        ],
    )?;
    if rotated != 1 {
        return Err(rusqlite::Error::StatementChangedRows(rotated));
    }
    store.execute(
        "DELETE FROM adapter_offers WHERE subject = ?1",
        [&record.subject],
    )?;
    store.execute(
        "INSERT INTO adapter_certificates(signature_key, subject, epoch, branch, certificate)
         SELECT ?1, subject, ?2, ?3, certificate FROM adapter_certificates
         WHERE signature_key = ?4 AND subject = ?5 ORDER BY id DESC LIMIT 1",
        params![
            record.new_key.as_slice(),
            record.successor.epoch.to_string(),
            record.successor.branch,
            record.old_key.as_slice(),
            record.subject
        ],
    )?;
    Ok(())
}

/// The leaf extensions other than `authz_incarnation`, in order.
fn other_leaf_extensions(leaf: &LeafNode) -> Vec<Extension> {
    leaf.extensions()
        .iter()
        .filter(|extension| {
            !matches!(extension, Extension::Unknown(t, _) if *t == AUTHZ_INCARNATION_EXTENSION_TYPE)
        })
        .cloned()
        .collect()
}

/// The single well-formed `authz_incarnation` of a leaf.
fn single_incarnation(leaf: &LeafNode) -> Result<AuthzIncarnation, String> {
    let incarnations = unknown_payloads(leaf.extensions(), AUTHZ_INCARNATION_EXTENSION_TYPE);
    let [incarnation] = incarnations.as_slice() else {
        return Err(noncanonical("authz_incarnation count"));
    };
    AuthzIncarnation::decode(incarnation).map_err(|_| noncanonical("authz_incarnation encoding"))
}

impl<P: OpenMlsProvider, C: Clock> Adapter<P, C> {
    /// C-28 offer checks against the kernel at `now`, read-only: the offering actor holds
    /// an effective `admin`, and the generation follows the `grant` rule with fresh keys
    /// (0 for a new record, otherwise exactly the old generation + 1 on an inactive one).
    /// The kernel repeats both checks at `rekey`, where the authority is final.
    fn check_offer(&mut self, actor: &str, offer: &Offer) -> Result<(), String> {
        let now = self.clock.now();
        if self
            .kernel_status(actor, now)?
            .effective_generation(Right::Admin)
            .is_none()
        {
            return Err("unauthorized".into());
        }
        let status = self.kernel_status(&offer.subject, now)?;
        let valid = match status.rights.iter().find(|r| r.right == offer.right) {
            None => offer.generation == 0,
            Some(record) => {
                !record.active && record.generation.checked_add(1) == Some(offer.generation)
            }
        };
        if !valid {
            return Err("invalid_generation".into());
        }
        Ok(())
    }

    /// The pending offer for `subject`, if any.
    fn pending_offer(&self, subject: &str) -> Result<Option<Offer>, String> {
        let row: Option<(String, String, String)> = self
            .store
            .query_row(
                "SELECT right, generation, admin FROM adapter_offers WHERE subject = ?1",
                [subject],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(db)?;
        row.map(|(right, generation, admin)| {
            Ok(Offer {
                subject: subject.to_owned(),
                right: Right::from_name(&right).ok_or("malformed: stored offer right")?,
                generation: generation
                    .parse()
                    .map_err(|_| "malformed: stored offer generation".to_string())?,
                admin,
            })
        })
        .transpose()
    }

    /// Whether `key` was ever a leaf signature key of this group: every founder,
    /// admission and rekey leaf key is indexed in `adapter_certificates`.
    fn key_retired(&self, key: &[u8; KEY_LEN]) -> Result<bool, String> {
        let found: Option<i64> = self
            .store
            .query_row(
                "SELECT 1 FROM adapter_certificates WHERE signature_key = ?1",
                [key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(db)?;
        Ok(found.is_some())
    }

    /// C-28 `submit_commit {kind: "update"}` with its checks in order. Steps 1-5 change
    /// neither the sequencer, the kernel nor the key registry on failure: the commit is
    /// staged on the in-memory `PublicGroup`, merged only after kernel `rekey` has
    /// committed, and the key is rotated with the trace event (`rotate_key`).
    fn sequence_update(
        &mut self,
        actor: &str,
        parent: &Frontier,
        commit: &[u8],
    ) -> Result<(Value, RekeyRecord), String> {
        let now = self.clock.now();
        // Step 1 (the group itself was checked in `prepare`).
        let checkpoint = self.kernel_checkpoint()?;
        let current = checkpoint_frontier(&checkpoint)?;
        if *parent != current {
            return Err("stale_frontier".into());
        }
        if checkpoint["read_fenced"] != json!(false) || !checkpoint["repair_pending"].is_null() {
            return Err("read_fenced".into());
        }
        let offer = self
            .pending_offer(actor)?
            .ok_or("unauthorized: no pending offer")?;
        let actor_key = self
            .registered_key(actor)?
            .ok_or_else(|| noncanonical("actor key"))?;
        let mut expected_rights: Vec<(Right, u64)> = self
            .kernel_status(actor, now)?
            .active_rights()
            .into_iter()
            .filter(|(right, _)| *right != offer.right)
            .collect();
        expected_rights.push((offer.right, offer.generation));
        expected_rights.sort();
        let sequencer = self.sequencer.as_ref().ok_or("uninitialized: no group")?;

        // Steps 2 and 3: OpenMLS accepts the commit, and its sender is the actor's leaf
        // under its registered key.
        let (staged, sender) =
            sequencer.process_commit(self.provider.crypto(), commit, actor, &actor_key)?;

        // Step 4: no proposals, and an UpdatePath.
        if staged.queued_proposals().next().is_some() {
            return Err(noncanonical("proposals"));
        }
        let path_leaf = staged
            .update_path_leaf_node()
            .ok_or_else(|| noncanonical("no UpdatePath"))?;

        // Step 5: the path leaf keeps the credential, carries a key never registered or
        // used as a leaf key, declares the adapter extensions, and carries exactly the
        // re-authorized incarnation. Other leaf extensions are unchanged.
        if credential_identity(path_leaf.credential()).as_deref() != Some(actor.as_bytes()) {
            return Err(noncanonical("UpdatePath leaf credential"));
        }
        let new_key = parse_public_key(path_leaf.signature_key().as_slice())
            .ok_or_else(|| noncanonical("UpdatePath leaf signature key"))?;
        if new_key.as_slice() == sender.signature_key().as_slice()
            || self.key_registered(&new_key)?
            || self.key_retired(&new_key)?
        {
            return Err(noncanonical("signature key is not new"));
        }
        if !ADAPTER_EXTENSIONS.iter().all(|t| {
            path_leaf
                .capabilities()
                .extensions()
                .contains(&ExtensionType::Unknown(*t))
        }) {
            return Err(noncanonical("UpdatePath leaf capabilities"));
        }
        let previous = single_incarnation(&sender)?;
        let incarnation = single_incarnation(path_leaf)?;
        if incarnation.version != 1
            || incarnation.subject != actor
            || incarnation.rights != expected_rights
            || incarnation.admission_cert_hash != previous.admission_cert_hash
        {
            return Err(noncanonical("authz_incarnation"));
        }
        if other_leaf_extensions(path_leaf) != other_leaf_extensions(&sender) {
            return Err(noncanonical("UpdatePath leaf extensions"));
        }
        let parent_accs = sequencer.acc_payloads();
        let successor_accs = unknown_payloads(
            staged.group_context().extensions(),
            ACC_CONTEXT_EXTENSION_TYPE,
        );
        if parent_accs.len() != 1 || successor_accs != parent_accs {
            return Err(noncanonical("acc_context changed"));
        }

        // Step 6: the kernel applies the offered grant with fresh keys, proven above, and
        // advances the frontier by CAS. Its errors pass through; the offer stays pending.
        let successor = context_frontier(staged.group_context())?;
        self.kernel.execute(json!({
            "command":"rekey", "actor":offer.admin, "subject":actor,
            "right":offer.right.name(), "generation":offer.generation,
            "parent_branch":current.branch, "new_branch":successor.branch,
            "epoch":successor.epoch, "now":now,
        }))?;

        // Step 7. A failure from here on leaves the kernel ahead of the sequencer or the
        // key registry; see the crash gaps in the phase report.
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
            kind: AckKind::Update,
        }
        .sign(&self.apf)?;
        let record = RekeyRecord {
            subject: actor.to_owned(),
            old_key: actor_key,
            new_key,
            successor: successor.clone(),
        };
        Ok((
            json!({"epoch":successor.epoch, "branch":successor.branch, "ack":hex::encode(ack)}),
            record,
        ))
    }
}
