//! `att-node agent`: one agent's trust sidecar.
//!
//! The sidecar is the only holder of the agent's keys. It owns one agent-trust
//! `ClientEndpoint` (an OpenMLS member), signs every request to the APF with the
//! agent's registered key, and talks to the untrusted relay. The application (any
//! agent framework, in any language) never sees keys or MLS: it uses the small
//! application API below. That API is the integration seam of the testbed.
//!
//! Application API (`ATT_APP_TOKEN`):
//! - `POST /app/send {payload_hex | text, content_type?, op?, invocation?}` → `{op, recipients, epoch}`
//! - `GET  /app/inbox?after=N` → delivered messages
//! - `GET  /app/status`
//!
//! Control API (`ATT_CONTROL_TOKEN`), used by the control plane:
//! - `GET  /control/status`
//! - `POST /control/genesis` (root only, `ATT_BOOTSTRAP_TOKEN`)
//! - `POST /control/delegate {subject, subject_key, rights, resources?, ttl_secs?, depth?}`
//! - `POST /control/request {body}` (any routed APF command, signed by this agent)
//! - `POST /control/join`, `POST /control/add {subject}`, `POST /control/repair`
//! - `POST /control/rekey {right, generation}`, `POST /control/sync`
//! - `POST /control/adversary {retain}`
//!
//! Persistence: with `ATT_DATA_DIR` the sidecar keeps its identity (`identity.json`,
//! mode 0600), its MLS state (`mls-N.sqlite`, agent-trust `durable_provider`) and its
//! bookkeeping (`state.json`: sequence, log cursor, inbox, ...) on disk, and a restart
//! resumes as the same member through `ClientEndpoint::load` (contract C-33). The
//! request sequence is written before each request is sent, so a restart never reuses
//! one. A restart while joining returns to candidate: the published KeyPackage is
//! abandoned.
//!
//! A background thread polls the relay: it applies acked commits in log order,
//! joins from a Welcome, confirms repairs, and runs receive → consume → deliver for
//! every envelope in the agent's mailbox (adapter contract §5.3).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_trust::adapter::ClientIdentity;
use agent_trust::client::{ClientEndpoint, JoinCandidate, PendingDelivery, PreparedJoin};
use agent_trust::entropy::{DurableLabProvider, EntropyConfig, LabEntropy};
use agent_trust::adapter::SignedRequest;
use agent_trust::wire::{
    operation_digest, CanonicalAck, Envelope, Frontier, ReleaseCertificate, Right, SignedStructure,
};
use openmls::prelude::{MlsMessageIn, ProcessedMessageContent};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use serde_json::{json, Map, Value};
use tls_codec::Deserialize;

use crate::config::{self, error_code, hex_field, str_field};
use crate::http::{self, Client, Request, Response};

const ROLE: &str = "agent";
/// The root's generation-0 rights created by kernel `init`, in right-code order.
const ROOT_RIGHTS: [(Right, u64); 4] = [
    (Right::Read, 0),
    (Right::Write, 0),
    (Right::Admin, 0),
    (Right::Admit, 0),
];
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";
/// Kept events per log (rejections, errors).
const LOG_LIMIT: usize = 512;
/// Envelopes from a future epoch kept until this member catches up.
const FUTURE_LIMIT: usize = 1024;

type Prov = DurableLabProvider;
type Endpoint = ClientEndpoint<Prov>;

struct Config {
    name: String,
    group: String,
    apf_url: String,
    apf: Client,
    relay: Client,
    control_token: Option<String>,
    app_token: Option<String>,
    bootstrap_token: Option<String>,
    pinned_apf_key: Option<Vec<u8>>,
    poll: Duration,
}

/// The agent's membership state.
enum Membership {
    /// An identity whose public key the APF may register at `delegate`.
    Candidate(ClientIdentity, Prov),
    /// A finalized KeyPackage is published; waiting for a Welcome.
    Joining(Box<JoinCandidate<Prov>>),
    Member(Box<Endpoint>),
    /// Removed by a repair commit that this agent applied.
    Removed(Box<Endpoint>),
    /// Transient while a flow moves the state.
    Busy,
}

struct Agent {
    cfg: Config,
    entropy: LabEntropy,
    /// The registered request key (the leaf signature key once admitted).
    signer: SignatureKeyPair,
    public_key: Vec<u8>,
    sequence: u64,
    apf_public: Option<Vec<u8>>,
    membership: Membership,
    /// The next handshake log index to process.
    cursor: u64,
    /// Adversary mode: stop applying commits and keep the current epoch's keys.
    retain: bool,
    next_op: u64,
    polls: u64,
    inbox: Vec<Value>,
    rejections: Vec<Value>,
    adversary: Vec<Value>,
    errors: Vec<Value>,
    confirmations: Vec<Value>,
    /// Persistence directory and the number of the current MLS storage file.
    data_dir: PathBuf,
    storage: u64,
    /// Last written `state.json` and identity public key, to skip identical writes.
    saved_state: String,
    saved_identity: Vec<u8>,
    restarts: u64,
    /// Decrypted envelopes whose consumption failed in transport (the APF was
    /// unreachable): retried every poll, so an APF outage delays delivery, not loses it.
    waiting: Vec<(String, String, PendingDelivery)>,
    /// Envelopes released at an epoch this member has not reached yet (their commit is
    /// late on the relay): kept until the member catches up.
    future: Vec<Value>,
    /// Handshake entries skipped as stale or invalid.
    skipped_entries: u64,
    /// Resolved handshake indices above the cursor. The cursor moves only over a
    /// contiguous run, so an entry the relay hides is fetched again once it appears.
    resolved: std::collections::BTreeSet<u64>,
}

pub fn run() -> Result<(), String> {
    let name = config::required("ATT_NAME")?;
    let cfg = Config {
        group: config::required("ATT_GROUP")?,
        apf_url: config::required("ATT_APF_URL")?,
        apf: Client::new(&config::required("ATT_APF_URL")?, None),
        relay: Client::new(&config::required("ATT_RELAY_URL")?, None),
        control_token: config::optional("ATT_CONTROL_TOKEN"),
        app_token: config::optional("ATT_APP_TOKEN"),
        bootstrap_token: config::optional("ATT_BOOTSTRAP_TOKEN"),
        pinned_apf_key: match config::optional("ATT_APF_PUBLIC_KEY") {
            Some(text) => Some(hex::decode(text).map_err(|_| "ATT_APF_PUBLIC_KEY is not hex")?),
            None => None,
        },
        poll: Duration::from_millis(config::number("ATT_POLL_MS", 100)?),
        name: name.clone(),
    };
    let listen = config::or_default("ATT_LISTEN", "0.0.0.0:7300");
    // C-40: the agent's keys and MLS randomness come from one selected source.
    let entropy = EntropyConfig::from_env()
        .and_then(|cfg| cfg.connect())
        .map_err(|err| format!("entropy_unavailable: {err}"))?;
    let data_dir = match config::optional("ATT_DATA_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => std::env::temp_dir().join(format!("att-agent-{name}-{}", std::process::id())),
    };
    std::fs::create_dir_all(&data_dir).map_err(|err| format!("data dir: {err}"))?;
    let mut agent = if data_dir.join(STATE_FILE).is_file() {
        Agent::restore(cfg, entropy, data_dir)?
    } else {
        Agent::fresh(cfg, entropy, data_dir)?
    };
    agent.save()?;
    config::log(
        ROLE,
        "listening",
        json!({ "name": name, "listen": listen, "public_key": hex::encode(&agent.public_key),
                "entropy": agent.entropy.label() }),
    );
    let poll = agent.cfg.poll;
    let shared = Arc::new(Mutex::new(agent));
    let poller = Arc::clone(&shared);
    std::thread::spawn(move || loop {
        if let Ok(mut agent) = poller.lock() {
            agent.poll_once();
        }
        std::thread::sleep(poll);
    });
    http::serve(&listen, 4, move |request| {
        let Ok(mut agent) = shared.lock() else {
            return Response::status(500, "crashed: lock poisoned");
        };
        agent.route(request)
    })
}

/// The outcome of one handshake entry for this member.
enum Entry {
    Applied,
    /// Stale, already applied, or not addressed to this member.
    Skipped,
    /// Its parent is a later frontier: an earlier commit is missing.
    Future,
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

const STATE_FILE: &str = "state.json";
const IDENTITY_FILE: &str = "identity.json";

/// Writes `bytes` to `path` atomically (temporary file, then rename), owner-only.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&tmp).map_err(|err| format!("persist: {err}"))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| format!("persist: {err}"))?;
    std::fs::rename(&tmp, path).map_err(|err| format!("persist: {err}"))
}

fn push_limited(log: &mut Vec<Value>, value: Value) {
    if log.len() >= LOG_LIMIT {
        log.remove(0);
    }
    log.push(value);
}

impl Agent {
    // -----------------------------------------------------------------------
    // Persistence
    // -----------------------------------------------------------------------

    fn blank(cfg: Config, entropy: LabEntropy, data_dir: PathBuf, signer: SignatureKeyPair, membership: Membership) -> Self {
        Agent {
            public_key: signer.public().to_vec(),
            signer,
            membership,
            cfg,
            entropy,
            sequence: 0,
            apf_public: None,
            cursor: 0,
            retain: false,
            next_op: 0,
            polls: 0,
            inbox: Vec::new(),
            rejections: Vec::new(),
            adversary: Vec::new(),
            errors: Vec::new(),
            confirmations: Vec::new(),
            data_dir,
            storage: 1,
            saved_state: String::new(),
            saved_identity: Vec::new(),
            restarts: 0,
            waiting: Vec::new(),
            future: Vec::new(),
            skipped_entries: 0,
            resolved: std::collections::BTreeSet::new(),
        }
    }

    fn storage_path(data_dir: &Path, storage: u64) -> PathBuf {
        data_dir.join(format!("mls-{storage}.sqlite"))
    }

    /// A new agent: a new identity drawn from the selected source (C-6).
    fn fresh(cfg: Config, entropy: LabEntropy, data_dir: PathBuf) -> Result<Self, String> {
        let provider = entropy.durable_provider(&Self::storage_path(&data_dir, 1))?;
        let identity = ClientIdentity::generate(provider.rand())?;
        let signer = identity.signer().clone();
        Ok(Self::blank(cfg, entropy, data_dir, signer, Membership::Candidate(identity, provider)))
    }

    /// A restarted agent: its stored identity, MLS state and bookkeeping.
    fn restore(cfg: Config, entropy: LabEntropy, data_dir: PathBuf) -> Result<Self, String> {
        let state: Value = std::fs::read(data_dir.join(STATE_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or("corrupt: state.json")?;
        let pair: SignatureKeyPair = std::fs::read(data_dir.join(IDENTITY_FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .ok_or("corrupt: identity.json")?;
        let identity = ClientIdentity::restore(pair)?;
        let signer = identity.signer().clone();
        let storage = state["storage"].as_u64().unwrap_or(1);
        let provider = entropy.durable_provider(&Self::storage_path(&data_dir, storage))?;
        let apf_public = state["apf_public"].as_str().and_then(|key| hex::decode(key).ok());
        let membership = match (state["membership"].as_str(), &apf_public) {
            (Some(label @ ("member" | "removed")), Some(apf)) => {
                let endpoint = ClientEndpoint::load(&cfg.group, &cfg.name, identity, provider, apf, None, None)?;
                if label == "member" {
                    Membership::Member(Box::new(endpoint))
                } else {
                    Membership::Removed(Box::new(endpoint))
                }
            }
            _ => Membership::Candidate(identity, provider),
        };
        let mut agent = Self::blank(cfg, entropy, data_dir, signer, membership);
        let list = |key: &str| state[key].as_array().cloned().unwrap_or_default();
        agent.sequence = state["sequence"].as_u64().unwrap_or(0);
        agent.cursor = state["cursor"].as_u64().unwrap_or(0);
        agent.retain = state["retain"].as_bool().unwrap_or(false);
        agent.next_op = state["next_op"].as_u64().unwrap_or(0);
        agent.apf_public = apf_public;
        agent.storage = storage;
        agent.inbox = list("inbox");
        agent.rejections = list("rejections");
        agent.adversary = list("adversary");
        agent.errors = list("errors");
        agent.confirmations = list("confirmations");
        agent.future = list("future");
        agent.restarts = state["restarts"].as_u64().unwrap_or(0) + 1;
        agent.saved_identity = agent.public_key.clone();
        config::log(ROLE, "restored", json!({
            "name": agent.cfg.name, "membership": agent.membership_label(),
            "sequence": agent.sequence, "cursor": agent.cursor, "restarts": agent.restarts,
        }));
        Ok(agent)
    }

    fn membership_label(&self) -> &'static str {
        match &self.membership {
            Membership::Candidate(..) => "candidate",
            Membership::Joining(_) => "joining",
            Membership::Member(_) => "member",
            Membership::Removed(_) => "removed",
            Membership::Busy => "busy",
        }
    }

    /// Writes the identity (when it changed) and the bookkeeping (when it changed).
    fn save(&mut self) -> Result<(), String> {
        if self.saved_identity != self.public_key {
            let bytes = serde_json::to_vec(&self.signer).map_err(|_| "persist: identity")?;
            write_private(&self.data_dir.join(IDENTITY_FILE), &bytes)?;
            self.saved_identity = self.public_key.clone();
        }
        let membership = match self.membership_label() {
            // A flow in progress keeps the last stable label; joining restarts as candidate.
            "busy" | "joining" => "candidate",
            label => label,
        };
        let state = json!({
            "membership": membership,
            "sequence": self.sequence,
            "cursor": self.cursor,
            "retain": self.retain,
            "next_op": self.next_op,
            "storage": self.storage,
            "apf_public": self.apf_public.as_ref().map(hex::encode),
            "inbox": self.inbox,
            "rejections": self.rejections,
            "adversary": self.adversary,
            "errors": self.errors,
            "confirmations": self.confirmations,
            "restarts": self.restarts,
            "future": self.future,
        })
        .to_string();
        if state != self.saved_state {
            write_private(&self.data_dir.join(STATE_FILE), state.as_bytes())?;
            self.saved_state = state;
        }
        Ok(())
    }

    /// A provider on a new storage file, for a candidate whose old storage holds the
    /// keys of a dropped KeyPackage.
    fn new_provider(&mut self) -> Result<Prov, String> {
        self.storage += 1;
        self.entropy
            .durable_provider(&Self::storage_path(&self.data_dir, self.storage))
    }

    // -----------------------------------------------------------------------
    // Routing
    // -----------------------------------------------------------------------

    fn route(&mut self, request: &Request) -> Response {
        let failures = self.entropy.failures();
        let mut response = self.dispatch(request);
        // A step that fails while the source refuses draws is `entropy_unavailable`, also
        // where OpenMLS reports the refusal as another error (agent-trust C-40).
        if let (Some(before), Some(after)) = (failures, self.entropy.failures()) {
            if after > before && response.body.get("error").is_some() {
                response = Response::outcome(Err("entropy_unavailable".into()));
            }
        }
        if let Err(error) = self.save() {
            config::log(ROLE, "persist_error", json!({ "name": self.cfg.name, "error": error }));
        }
        response
    }

    fn dispatch(&mut self, request: &Request) -> Response {
        let segments = request.segments();
        let body = &request.body;
        match segments.as_slice() {
            ["healthz"] => Response::json(json!({ "ok": "agent" })),
            ["app", action] => {
                if !http::authorized(request, &self.cfg.app_token) {
                    return Response::status(401, "unauthenticated: app token");
                }
                // Under mutual TLS the application presents `<name>-app` (or is attctl).
                let app = format!("{}-app", self.cfg.name);
                if !request.peer_is(&[app.as_str(), "attctl"]) {
                    return Response::forbidden_peer();
                }
                match (request.method.as_str(), *action) {
                    ("POST", "send") => Response::outcome(self.send(body)),
                    ("GET", "inbox") => {
                        let after = request.query_u64("after").unwrap_or(0) as usize;
                        Response::outcome(Ok(Value::Array(
                            self.inbox.iter().skip(after).cloned().collect(),
                        )))
                    }
                    ("GET", "status") => Response::outcome(Ok(self.status())),
                    _ => Response::not_found(),
                }
            }
            ["control", action] => {
                if !http::authorized(request, &self.cfg.control_token) {
                    return Response::status(401, "unauthenticated: control token");
                }
                if !request.peer_is(&["attctl"]) {
                    return Response::forbidden_peer();
                }
                let result = match (request.method.as_str(), *action) {
                    ("GET", "status") => Ok(self.status()),
                    ("GET", "entropy") => Ok(self.entropy.report()),
                    ("POST", "genesis") => self.genesis(),
                    ("POST", "delegate") => self.delegate(body),
                    ("POST", "request") => self.signed_body(body),
                    ("POST", "join") => self.join(),
                    ("POST", "add") => self.add(body),
                    ("POST", "repair") => self.repair(),
                    ("POST", "rekey") => self.rekey(body),
                    ("POST", "sync") => self.catch_up().map(|()| self.status()),
                    ("POST", "adversary") => self.set_adversary(body),
                    _ => return Response::not_found(),
                };
                if let Err(error) = &result {
                    config::log(
                        ROLE,
                        "control_error",
                        json!({ "name": self.cfg.name, "action": action, "error": error }),
                    );
                }
                Response::outcome(result)
            }
            _ => Response::not_found(),
        }
    }

    fn status(&self) -> Value {
        let (membership, frontier) = match &self.membership {
            Membership::Candidate(..) => ("candidate", None),
            Membership::Joining(_) => ("joining", None),
            Membership::Member(endpoint) => ("member", endpoint.frontier().ok()),
            Membership::Removed(_) => ("removed", None),
            Membership::Busy => ("busy", None),
        };
        json!({
            "name": self.cfg.name,
            "group": self.cfg.group,
            "public_key": hex::encode(&self.public_key),
            "membership": membership,
            "epoch": frontier.as_ref().map(|f| f.epoch),
            "branch": frontier.as_ref().map(|f| f.branch.clone()),
            "cursor": self.cursor,
            "retain": self.retain,
            "polls": self.polls,
            "sequence": self.sequence,
            "inbox": self.inbox.len(),
            "rejections": self.rejections,
            "adversary": self.adversary,
            "confirmations": self.confirmations,
            "errors": self.errors,
            "entropy": self.entropy.report(),
            "restarts": self.restarts,
            "waiting": self.waiting.iter().map(|(op, _, _)| op.clone()).collect::<Vec<_>>(),
            "future": self.future.len(),
            "skipped_entries": self.skipped_entries,
        })
    }

    // -----------------------------------------------------------------------
    // APF access
    // -----------------------------------------------------------------------

    /// Signs `body` with the registered key at the next sequence and sends it (§4.8).
    fn request(&mut self, body: Value) -> Result<Value, String> {
        self.sequence += 1;
        // Write-ahead: a restart must never reuse a sequence the APF may have consumed.
        self.save()?;
        let signed = SignedRequest::sign(
            &self.cfg.group,
            &self.cfg.name,
            self.sequence,
            &body,
            &self.signer,
        )?;
        let wire = json!({
            "actor": signed.actor, "sequence": signed.sequence,
            "body": hex::encode(&signed.body), "signature": hex::encode(&signed.signature),
        });
        self.cfg.apf.call("POST", "/v1/request", Some(&wire))
    }

    fn signed_body(&mut self, body: &Value) -> Result<Value, String> {
        let inner = body.get("body").cloned().ok_or("malformed: body")?;
        self.request(inner)
    }

    fn apf_state(&self) -> Result<Value, String> {
        self.cfg.apf.call("GET", "/v1/state", None)
    }

    /// The APF public key: pinned by configuration, learned at genesis, or fetched once
    /// from `/v1/info` (trust on first use; documented in docs/architecture.md).
    fn apf_key(&mut self) -> Result<Vec<u8>, String> {
        if let Some(key) = &self.apf_public {
            return Ok(key.clone());
        }
        let info = self.cfg.apf.call("GET", "/v1/info", None)?;
        let key = hex_field(&info, "apf_public_key")
            .map_err(|_| "uninitialized: the APF has no key yet".to_string())?;
        if let Some(pinned) = &self.cfg.pinned_apf_key {
            if *pinned != key {
                return Err("binding_mismatch: APF key differs from the pinned key".into());
            }
        }
        self.apf_public = Some(key.clone());
        Ok(key)
    }

    fn endpoint_mut(&mut self) -> Result<&mut Endpoint, String> {
        match &mut self.membership {
            Membership::Member(endpoint) => Ok(endpoint),
            _ => Err(format!("not_ready: {} is not a member", self.cfg.name)),
        }
    }

    fn publish_handshake(&self, entry: Value) -> Result<u64, String> {
        let path = format!("/v1/groups/{}/handshake", self.cfg.group);
        let response = self.cfg.relay.call("POST", &path, Some(&entry))?;
        response["index"]
            .as_u64()
            .ok_or_else(|| "transport: relay index".to_string())
    }

    /// Submits a staged commit; a refused commit is discarded at the client (§5.2).
    fn submit(&mut self, kind: &str, parent: &Frontier, commit: &[u8]) -> Result<(Frontier, Vec<u8>), String> {
        let body = json!({
            "command": "submit_commit", "kind": kind, "parent_epoch": parent.epoch,
            "parent_branch": parent.branch, "commit": hex::encode(commit)
        });
        match self.request(body) {
            Ok(response) => Ok((
                Frontier {
                    epoch: response["epoch"].as_u64().ok_or("malformed: ack epoch")?,
                    branch: str_field(&response, "branch")?.to_owned(),
                },
                hex_field(&response, "ack")?,
            )),
            Err(error) => {
                if let Ok(endpoint) = self.endpoint_mut() {
                    let _ = endpoint.discard_pending();
                }
                Err(error)
            }
        }
    }

    // -----------------------------------------------------------------------
    // Control flows
    // -----------------------------------------------------------------------

    /// §5.1: the root founds the group with the APF.
    fn genesis(&mut self) -> Result<Value, String> {
        let Membership::Candidate(..) = &self.membership else {
            return Err("invalid_transition: not a fresh candidate".into());
        };
        let bootstrap = Client::new(&self.cfg.apf_url, self.cfg.bootstrap_token.clone());
        let begun = bootstrap.call(
            "POST",
            "/v1/genesis/begin",
            Some(&json!({
                "group": self.cfg.group, "root": self.cfg.name,
                "root_key": hex::encode(&self.public_key)
            })),
        )?;
        let apf_public = hex_field(&begun, "apf_public_key")?;
        if let Some(pinned) = &self.cfg.pinned_apf_key {
            if *pinned != apf_public {
                return Err("binding_mismatch: APF key differs from the pinned key".into());
            }
        }
        let Membership::Candidate(identity, provider) =
            std::mem::replace(&mut self.membership, Membership::Busy)
        else {
            unreachable!("checked above")
        };
        let endpoint = match ClientEndpoint::found(
            &self.cfg.group,
            &self.cfg.name,
            &ROOT_RIGHTS,
            identity,
            provider,
            &hex_field(&begun, "founder_certificate")?,
            &hex_field(&begun, "acc_context")?,
            &apf_public,
        ) {
            Ok(endpoint) => endpoint,
            Err(error) => {
                // The identity is consumed; the agent must be restarted to retry.
                self.membership = Membership::Busy;
                return Err(error);
            }
        };
        let completed = bootstrap.call(
            "POST",
            "/v1/genesis/complete",
            Some(&json!({
                "group_info": hex::encode(endpoint.export_group_info()?),
                "ratchet_tree": hex::encode(endpoint.export_ratchet_tree()?),
            })),
        )?;
        self.apf_public = Some(apf_public);
        self.membership = Membership::Member(Box::new(endpoint));
        self.cursor = self.handshake_len()?;
        Ok(completed)
    }

    fn handshake_len(&self) -> Result<u64, String> {
        let path = format!("/v1/groups/{}/handshake?after=0", self.cfg.group);
        let entries = self.cfg.relay.call("GET", &path, None)?;
        Ok(entries.as_array().map(|a| a.len() as u64).unwrap_or(0))
    }

    /// C-1: the parent submits the child's public key, never the child's secret.
    fn delegate(&mut self, body: &Value) -> Result<Value, String> {
        let ttl = body.get("ttl_secs").and_then(Value::as_u64).unwrap_or(30 * 24 * 3600);
        let resources = body
            .get("resources")
            .cloned()
            .unwrap_or_else(|| json!([self.cfg.group]));
        let request = json!({
            "command": "delegate",
            "subject": str_field(body, "subject")?,
            "rights": body.get("rights").cloned().ok_or("malformed: rights")?,
            "resources": resources,
            "expires_at": config::unix_now() + ttl,
            "not_before": 0,
            "depth": body.get("depth").and_then(Value::as_u64).unwrap_or(4),
            "subject_key": str_field(body, "subject_key")?,
        });
        self.request(request)
    }

    /// §5.2 steps 1 to 3: prepare, obtain the admission certificate, publish the KeyPackage.
    fn join(&mut self) -> Result<Value, String> {
        let Membership::Candidate(..) = &self.membership else {
            return Err("invalid_transition: not a candidate".into());
        };
        let apf_public = self.apf_key()?;
        let rights = active_rights(&self.apf_state()?, &self.cfg.name)?;
        let Membership::Candidate(identity, provider) =
            std::mem::replace(&mut self.membership, Membership::Busy)
        else {
            unreachable!("checked above")
        };
        let prepared = match PreparedJoin::try_prepare(
            &self.cfg.group,
            &self.cfg.name,
            &rights,
            identity,
            provider,
            &apf_public,
        ) {
            Ok(prepared) => prepared,
            Err(unprepared) => {
                self.membership = Membership::Candidate(unprepared.identity, unprepared.provider);
                return Err(unprepared.error);
            }
        };
        let certificate = match self
            .request(json!({
                "command": "admission_certificate",
                "key_package_preimage": hex::encode(prepared.preimage())
            }))
            .and_then(|response| hex_field(&response, "certificate"))
        {
            Ok(certificate) => certificate,
            Err(error) => {
                let (identity, provider) = prepared.abandon();
                self.membership = Membership::Candidate(identity, provider);
                return Err(error);
            }
        };
        let candidate = prepared.finalize(&certificate)?;
        let path = format!("/v1/keypackages/{}", self.cfg.name);
        if let Err(error) = self.cfg.relay.call(
            "PUT",
            &path,
            Some(&json!({ "key_package": hex::encode(candidate.key_package()) })),
        ) {
            // The provider holds the KeyPackage's private keys; start a fresh one (C-40).
            let (identity, _) = candidate.abandon();
            let provider = self.new_provider()?;
            self.membership = Membership::Candidate(identity, provider);
            return Err(error);
        }
        self.membership = Membership::Joining(Box::new(candidate));
        Ok(json!({ "subject": self.cfg.name, "rights": rights_json(&rights), "published": true }))
    }

    /// §5.2 steps 4 to 7: stage the Add, submit it, merge it, publish commit and Welcome.
    fn add(&mut self, body: &Value) -> Result<Value, String> {
        let subject = str_field(body, "subject")?.to_owned();
        self.catch_up()?;
        let path = format!("/v1/keypackages/{subject}");
        let key_package = hex_field(&self.cfg.relay.call("GET", &path, None)?, "key_package")?;
        let staged = self.endpoint_mut()?.stage_add(&key_package)?;
        let (frontier, ack) = self.submit("admit", &staged.parent, &staged.commit)?;
        self.endpoint_mut()?.apply_ack(&staged.commit, &ack)?;
        let index = self.publish_handshake(json!({
            "kind": "admit", "committer": self.cfg.name, "joiner": subject,
            "commit": hex::encode(&staged.commit), "ack": hex::encode(&ack),
            "welcome": hex::encode(&staged.welcome),
        }))?;
        self.cursor = index + 1;
        Ok(json!({ "subject": subject, "epoch": frontier.epoch, "branch": frontier.branch, "index": index }))
    }

    /// §5.4 and C-20 to C-23: plan, stage, submit, merge, publish, confirm.
    fn repair(&mut self) -> Result<Value, String> {
        self.catch_up()?;
        let plan = self.request(json!({ "command": "repair_plan" }))?;
        let removed: Vec<String> = plan["removed"]
            .as_array()
            .ok_or("malformed: repair plan removed")?
            .iter()
            .filter_map(|name| name.as_str().map(str::to_owned))
            .collect();
        let acc_context = hex_field(&plan, "acc_context")?;
        let staged = self.endpoint_mut()?.stage_repair(&removed, &acc_context)?;
        let (frontier, ack) = self.submit("repair", &staged.parent, &staged.commit)?;
        self.endpoint_mut()?.apply_ack(&staged.commit, &ack)?;
        let index = self.publish_handshake(json!({
            "kind": "repair", "committer": self.cfg.name, "removed": removed,
            "commit": hex::encode(&staged.commit), "ack": hex::encode(&ack),
        }))?;
        self.cursor = index + 1;
        let confirmed = self.confirm()?;
        Ok(json!({
            "removed": removed, "epoch": frontier.epoch, "branch": frontier.branch,
            "index": index, "opened": confirmed["opened"], "evidence": confirmed["evidence"],
        }))
    }

    fn confirm(&mut self) -> Result<Value, String> {
        let confirmation = self.endpoint_mut()?.confirmation()?;
        let response = self.request(json!({
            "command": "confirm_repair", "confirmation": hex::encode(confirmation)
        }));
        let record = match &response {
            Ok(value) => json!({ "outcome": "ok", "response": value }),
            Err(error) => json!({ "outcome": error_code(error) }),
        };
        push_limited(&mut self.confirmations, record);
        response
    }

    /// C-28: after the root's offer, install a new signature key and incarnation.
    fn rekey(&mut self, body: &Value) -> Result<Value, String> {
        let right_name = str_field(body, "right")?.to_owned();
        let right = Right::from_name(&right_name).ok_or("malformed: right")?;
        let generation = body
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or("malformed: generation")?;
        self.catch_up()?;
        let mut rights: Vec<(Right, u64)> = active_rights(&self.apf_state()?, &self.cfg.name)?
            .into_iter()
            .filter(|(held, _)| *held != right)
            .collect();
        rights.push((right, generation));
        rights.sort();
        let new_identity = ClientIdentity::generate(&self.entropy.rand())?;
        let new_signer = new_identity.signer().clone();
        let new_public = new_identity.public_key().to_vec();
        let staged = self.endpoint_mut()?.stage_rekey(new_identity, &rights)?;
        let (frontier, ack) = self.submit("update", &staged.parent, &staged.commit)?;
        // C-28 step 7: the APF replaced the registered key in the same step.
        self.signer = new_signer;
        self.public_key = new_public;
        self.endpoint_mut()?.apply_ack(&staged.commit, &ack)?;
        let index = self.publish_handshake(json!({
            "kind": "update", "committer": self.cfg.name,
            "commit": hex::encode(&staged.commit), "ack": hex::encode(&ack),
        }))?;
        self.cursor = index + 1;
        Ok(json!({
            "right": right_name, "generation": generation, "epoch": frontier.epoch,
            "branch": frontier.branch, "public_key": hex::encode(&self.public_key),
        }))
    }

    fn set_adversary(&mut self, body: &Value) -> Result<Value, String> {
        self.retain = body
            .get("retain")
            .and_then(Value::as_bool)
            .ok_or("malformed: retain")?;
        config::log(ROLE, "adversary", json!({ "name": self.cfg.name, "retain": self.retain }));
        Ok(json!({ "retain": self.retain }))
    }

    // -----------------------------------------------------------------------
    // Application flow (§5.3)
    // -----------------------------------------------------------------------

    fn send(&mut self, body: &Value) -> Result<Value, String> {
        let payload = match (body.get("payload_hex"), body.get("text")) {
            (Some(Value::String(hex_text)), None) => {
                hex::decode(hex_text).map_err(|_| "malformed: payload_hex")?
            }
            (None, Some(Value::String(text))) => text.as_bytes().to_vec(),
            _ => return Err("malformed: give exactly one of payload_hex or text".into()),
        };
        let content_type = body
            .get("content_type")
            .and_then(Value::as_str)
            .unwrap_or(DEFAULT_CONTENT_TYPE)
            .as_bytes()
            .to_vec();
        let op = match body.get("op").and_then(Value::as_str) {
            Some(op) => op.to_owned(),
            None => {
                self.next_op += 1;
                format!("{}-{:06}", self.cfg.name, self.next_op)
            }
        };
        self.catch_up()?;
        let apf_public = self.apf_key()?;
        let from = self.cfg.name.clone();
        self.endpoint_mut()?;

        // An operation on behalf of another agent is bound to an APF invocation at
        // allocation; the APF bounds it by the origin's and this executor's authority.
        let mut allocate = json!({ "command": "allocate", "op": op });
        if let Some(invocation) = body.get("invocation").and_then(Value::as_str) {
            allocate["invocation"] = json!(invocation);
        }
        self.request(allocate)?;
        let state = self.apf_state()?;
        let frontier = Frontier {
            epoch: state["epoch"].as_u64().ok_or("malformed: APF epoch")?,
            branch: str_field(&state, "branch")?.to_owned(),
        };
        if self.endpoint_mut()?.frontier()? != frontier {
            return Err("not_ready: the local frontier differs from the APF frontier".into());
        }
        let policy_revision = state["policy_revision"]
            .as_u64()
            .ok_or("malformed: APF policy_revision")?;
        // The writer singleton plus every roster reader singleton (C-14).
        let mut cover = vec![json!([{
            "subject": from, "right": "write",
            "generation": generation_of(&state, &from, "write").unwrap_or(0)
        }])];
        for reader in roster_of(&state)? {
            let generation = generation_of(&state, &reader, "read").unwrap_or(0);
            cover.push(json!([{ "subject": reader, "right": "read", "generation": generation }]));
        }
        let digest = operation_digest(&op, &self.cfg.group, &content_type, &payload, &frontier, policy_revision)?;
        let released = self.request(json!({
            "command": "release", "op": op, "right": "write", "digest": digest, "cover": cover,
            "policy_revision": policy_revision, "epoch": frontier.epoch, "branch": frontier.branch
        }))?;
        let certificate = hex_field(&released, "certificate")?;
        let verifier = openmls_rust_crypto::RustCrypto::default();
        let released = ReleaseCertificate::verify(&certificate, &apf_public, &verifier)?;
        let envelope = match self.endpoint_mut()?.protect(&certificate, &content_type, &payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                // Barrier B2: a released operation that was never protected is abandoned
                // at the APF and its id is never reused.
                let _ = self.request(json!({ "command": "abandon", "op": op }));
                return Err(error);
            }
        };
        let envelope_hex = hex::encode(&envelope);
        self.request(json!({ "command": "persist", "op": op, "envelope": envelope_hex }))?;
        self.request(json!({ "command": "emit", "op": op, "envelope": envelope_hex }))?;
        let recipients: Vec<String> = released
            .readers
            .iter()
            .map(|(reader, _)| reader.clone())
            .filter(|reader| *reader != from)
            .collect();
        for to in &recipients {
            self.cfg.relay.call(
                "POST",
                &format!("/v1/mailbox/{to}"),
                Some(&json!({ "from": from, "op": op, "envelope": envelope_hex })),
            )?;
        }
        Ok(json!({ "op": op, "recipients": recipients, "epoch": frontier.epoch, "sent_ms": unix_ms() }))
    }

    // -----------------------------------------------------------------------
    // Background processing
    // -----------------------------------------------------------------------

    fn poll_once(&mut self) {
        if let Err(error) = self.catch_up() {
            self.note_error("sync", &error);
        }
        self.polls += 1;
        if let Err(error) = self.save() {
            self.note_error("persist", &error);
        }
    }

    /// Drains the mailbox at the current epoch, applies the handshake log, then drains
    /// the envelopes that waited for the commits just applied. Messages already queued
    /// for the current epoch are processed before the next commit: after it they could
    /// no longer be delivered (the conservative profile binds delivery to the release
    /// frontier, §5.3).
    fn catch_up(&mut self) -> Result<(), String> {
        let drained = self.drain_mailbox();
        self.sync()?;
        if !self.future.is_empty() {
            self.drain_mailbox()?;
        }
        drained
    }

    fn note_error(&mut self, stage: &str, error: &str) {
        // A relay or APF that is not up yet is normal during bring-up.
        if error.starts_with("transport") || error.starts_with("uninitialized") {
            return;
        }
        push_limited(&mut self.errors, json!({ "stage": stage, "error": error }));
    }

    /// Applies the handshake log. The relay is untrusted, so its order and its index
    /// numbers only say where to look: an entry applies only if its APF-signed ack names
    /// this member's current frontier as parent (§4.6). An entry whose ack names an older
    /// parent, or that does not verify, is skipped; one whose ack names a newer parent
    /// means a commit is missing, and processing waits for it.
    fn sync(&mut self) -> Result<(), String> {
        if self.retain {
            return Ok(());
        }
        if !matches!(self.membership, Membership::Member(_) | Membership::Joining(_)) {
            return Ok(());
        }
        let path = format!(
            "/v1/groups/{}/handshake?after={}&reader={}",
            self.cfg.group, self.cursor, self.cfg.name
        );
        let mut entries = self.cfg.relay.call("GET", &path, None)?.as_array().cloned().unwrap_or_default();
        entries.sort_by_key(|entry| entry["index"].as_u64().unwrap_or(u64::MAX));
        for entry in entries {
            let Some(index) = entry["index"].as_u64() else { continue };
            if index < self.cursor || self.resolved.contains(&index) {
                continue;
            }
            match self.apply_entry(&entry) {
                Ok(Entry::Applied) => {}
                Ok(Entry::Skipped) => self.skipped_entries += 1,
                Ok(Entry::Future) => break,
                Err(error) => {
                    self.skipped_entries += 1;
                    push_limited(
                        &mut self.errors,
                        json!({ "stage": "handshake", "index": index, "error": error }),
                    );
                }
            }
            self.resolved.insert(index);
            while self.resolved.remove(&self.cursor) {
                self.cursor += 1;
            }
        }
        Ok(())
    }

    fn apply_entry(&mut self, entry: &Value) -> Result<Entry, String> {
        let ack_bytes = hex_field(entry, "ack")?;
        let apf_public = self.apf_key()?;
        let verifier = openmls_rust_crypto::RustCrypto::default();
        let ack = CanonicalAck::verify(&ack_bytes, &apf_public, &verifier)?;
        let kind = entry["kind"].as_str().unwrap_or_default();
        if let Membership::Joining(_) = &self.membership {
            if entry["joiner"].as_str() != Some(self.cfg.name.as_str()) {
                return Ok(Entry::Skipped);
            }
            let welcome = hex_field(entry, "welcome")?;
            let Membership::Joining(candidate) =
                std::mem::replace(&mut self.membership, Membership::Busy)
            else {
                unreachable!("checked above")
            };
            return match candidate.join(&welcome, &ack_bytes) {
                Ok(endpoint) => {
                    self.membership = Membership::Member(Box::new(endpoint));
                    config::log(ROLE, "joined", json!({ "name": self.cfg.name }));
                    Ok(Entry::Applied)
                }
                Err(error) => {
                    // The KeyPackage is spent either way; go back to a fresh candidate.
                    let identity = ClientIdentity::generate(&self.entropy.rand())?;
                    let provider = self.new_provider()?;
                    self.signer = identity.signer().clone();
                    self.public_key = identity.public_key().to_vec();
                    self.membership = Membership::Candidate(identity, provider);
                    Err(error)
                }
            };
        }
        let own = self.endpoint_mut()?.frontier()?;
        if ack.parent.epoch < own.epoch {
            // Already applied (for example this member's own commit), or a replay.
            return Ok(Entry::Skipped);
        }
        if ack.parent.epoch > own.epoch {
            return Ok(Entry::Future);
        }
        if ack.parent.branch != own.branch {
            return Err("binding_mismatch: the ack forks from this member's frontier".into());
        }
        let commit = hex_field(entry, "commit")?;
        let endpoint = self.endpoint_mut()?;
        endpoint.apply_ack(&commit, &ack_bytes)?;
        // A removed member that applies the repair ack becomes inactive (C-24, C-26).
        let active = endpoint.confirmation().is_ok();
        if !active {
            if let Membership::Member(endpoint) = std::mem::replace(&mut self.membership, Membership::Busy) {
                self.membership = Membership::Removed(endpoint);
            }
            config::log(ROLE, "removed", json!({ "name": self.cfg.name }));
            return Ok(Entry::Applied);
        }
        if kind == "repair" {
            // Every continuing member confirms; the APF opens the fence on a match (C-23).
            let _ = self.confirm();
        }
        Ok(Entry::Applied)
    }

    fn drain_mailbox(&mut self) -> Result<(), String> {
        if matches!(self.membership, Membership::Candidate(..) | Membership::Joining(_) | Membership::Busy) {
            return Ok(());
        }
        // 1. Consumptions that failed in transport.
        for (op, from, pending) in std::mem::take(&mut self.waiting) {
            self.finish(op, from, pending);
        }
        // 2. Envelopes from an epoch this member has now reached.
        let mut messages = std::mem::take(&mut self.future);
        // 3. New envelopes, leased by the relay until acknowledged.
        let path = format!("/v1/mailbox/{}", self.cfg.name);
        let fetched = self.cfg.relay.call("GET", &path, None)?.as_array().cloned().unwrap_or_default();
        let ids: Vec<u64> = fetched.iter().filter_map(|m| m["relay_id"].as_u64()).collect();
        messages.extend(fetched);
        self.process_messages(messages);
        // Acknowledge only after the outcome is on disk: a crash before this point makes
        // the relay retransmit the batch (at-least-once transport).
        self.save()?;
        if !ids.is_empty() {
            self.cfg.relay.call("POST", &format!("{path}/ack"), Some(&json!({ "ids": ids })))?;
        }
        Ok(())
    }

    fn process_messages(&mut self, messages: Vec<Value>) {
        for message in messages {
            let op = message["op"].as_str().unwrap_or_default().to_owned();
            let from = message["from"].as_str().unwrap_or_default().to_owned();
            let Ok(envelope) = hex_field(&message, "envelope") else {
                self.reject(&op, &from, "malformed: envelope");
                continue;
            };
            if self.retain || matches!(self.membership, Membership::Removed(_)) {
                self.adversary_attempt(&op, &from, &envelope, &message);
                continue;
            }
            if self.is_future(&envelope) {
                if self.future.len() < FUTURE_LIMIT {
                    self.future.push(message);
                } else {
                    self.reject(&op, &from, "not_ready: future buffer full");
                }
                continue;
            }
            match self.endpoint_mut().and_then(|endpoint| endpoint.receive(&envelope)) {
                Ok(pending) if pending.op() == op => self.finish(op, from, pending),
                Ok(_) => self.reject(&op, &from, "binding_mismatch: operation"),
                Err(error) => self.reject(&op, &from, &error),
            }
        }
    }

    /// True when the envelope's certificate verifies and names a later epoch than this
    /// member's: its commit has not reached this member yet.
    fn is_future(&mut self, envelope: &[u8]) -> bool {
        let Some(apf_public) = self.apf_public.clone() else { return false };
        let Ok(own) = self.endpoint_mut().and_then(|endpoint| endpoint.frontier()) else {
            return false;
        };
        let verifier = openmls_rust_crypto::RustCrypto::default();
        Envelope::decode(envelope)
            .ok()
            .and_then(|envelope| ReleaseCertificate::verify(&envelope.certificate, &apf_public, &verifier).ok())
            .is_some_and(|certificate| certificate.frontier.epoch > own.epoch)
    }

    /// Consume at the APF, then deliver under the receipt (§5.3 step 7, C-15).
    fn finish(&mut self, op: String, from: String, pending: PendingDelivery) {
        let actor = pending.actor().to_owned();
        let receipt = match self
            .request(json!({ "command": "consume", "op": op }))
            .and_then(|response| hex_field(&response, "receipt"))
        {
            Ok(receipt) => receipt,
            Err(error) if error.starts_with("transport") => {
                self.waiting.push((op, from, pending));
                return;
            }
            Err(error) => return self.reject(&op, &from, &error),
        };
        match pending.deliver(&receipt) {
            Ok((content_type, payload)) => {
                config::log(ROLE, "delivered", json!({ "name": self.cfg.name, "op": op }));
                let item = json!({
                    "seq": self.inbox.len(),
                    "op": op,
                    "from": actor,
                    "content_type": String::from_utf8_lossy(&content_type),
                    "payload_hex": hex::encode(&payload),
                    "text": String::from_utf8(payload).ok(),
                    "delivered_ms": unix_ms(),
                });
                self.inbox.push(item);
            }
            Err(error) => self.reject(&op, &from, &error),
        }
    }

    fn reject(&mut self, op: &str, from: &str, error: &str) {
        config::log(ROLE, "rejected", json!({ "name": self.cfg.name, "op": op, "error": error }));
        push_limited(
            &mut self.rejections,
            json!({ "op": op, "from": from, "code": error_code(error), "error": error }),
        );
    }

    /// The retained-key adversary: try to decrypt with raw OpenMLS, bypassing every
    /// agent-trust check, and try to consume at the APF anyway. Both must fail.
    fn adversary_attempt(&mut self, op: &str, from: &str, envelope: &[u8], message: &Value) {
        let mls = match self.raw_decrypt(envelope) {
            Ok(plaintext) => format!("decrypted {} bytes", plaintext.len()),
            Err(error) => format!("refused: {error}"),
        };
        let consume = match self.request(json!({ "command": "consume", "op": op })) {
            Ok(_) => "ok".to_owned(),
            Err(error) => error_code(&error),
        };
        config::log(
            ROLE,
            "adversary_attempt",
            json!({ "name": self.cfg.name, "op": op, "mls": mls, "consume": consume }),
        );
        push_limited(
            &mut self.adversary,
            json!({
                "op": op, "from": from, "tapped_from": message.get("tapped_from"),
                "mls": mls, "decrypted": mls.starts_with("decrypted"), "consume": consume,
            }),
        );
    }

    fn raw_decrypt(&mut self, envelope: &[u8]) -> Result<Vec<u8>, String> {
        let envelope = Envelope::decode(envelope).map_err(|_| "malformed envelope")?;
        let message = MlsMessageIn::tls_deserialize_exact(envelope.mls_message.as_slice())
            .map_err(|_| "malformed MLS message")?
            .try_into_protocol_message()
            .map_err(|_| "not a protocol message")?;
        let endpoint = match &mut self.membership {
            Membership::Member(endpoint) | Membership::Removed(endpoint) => endpoint,
            _ => return Err("no MLS state".into()),
        };
        let (group, provider, _) = endpoint.mls_parts_mut();
        let processed = group
            .process_message(provider, message)
            .map_err(|err| format!("{err:?}").chars().take(160).collect::<String>())?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app) => Ok(app.into_bytes()),
            _ => Err("not an application message".into()),
        }
    }
}


// ---------------------------------------------------------------------------
// Policy view helpers
// ---------------------------------------------------------------------------

fn roster_of(state: &Value) -> Result<Vec<String>, String> {
    state["roster"]
        .as_array()
        .map(|roster| roster.iter().filter_map(|n| n.as_str().map(str::to_owned)).collect())
        .ok_or_else(|| "malformed: APF roster".to_string())
}

fn grants(state: &Value) -> Vec<Map<String, Value>> {
    state["grants"]
        .as_array()
        .map(|grants| grants.iter().filter_map(|g| g.as_object().cloned()).collect())
        .unwrap_or_default()
}

fn generation_of(state: &Value, subject: &str, right: &str) -> Option<u64> {
    grants(state)
        .into_iter()
        .find(|g| g.get("subject").and_then(Value::as_str) == Some(subject)
            && g.get("right").and_then(Value::as_str) == Some(right))
        .and_then(|g| g.get("generation").and_then(Value::as_u64))
}

/// The subject's active rights and generations, in right-code order.
fn active_rights(state: &Value, subject: &str) -> Result<Vec<(Right, u64)>, String> {
    let mut rights = Vec::new();
    for grant in grants(state) {
        if grant.get("subject").and_then(Value::as_str) != Some(subject)
            || grant.get("active").and_then(Value::as_bool) != Some(true)
        {
            continue;
        }
        let right = grant
            .get("right")
            .and_then(Value::as_str)
            .and_then(Right::from_name)
            .ok_or("malformed: APF right")?;
        let generation = grant
            .get("generation")
            .and_then(Value::as_u64)
            .ok_or("malformed: APF generation")?;
        rights.push((right, generation));
    }
    rights.sort();
    Ok(rights)
}

fn rights_json(rights: &[(Right, u64)]) -> Value {
    Value::Array(
        rights
            .iter()
            .map(|(right, generation)| json!({ "right": right.name(), "generation": generation }))
            .collect(),
    )
}
