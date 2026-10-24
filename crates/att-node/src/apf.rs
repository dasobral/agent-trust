//! `att-node apf`: the APF authority as a network service.
//!
//! It owns one agent-trust `Adapter` (APF signing key, APF kernel, OpenMLS public
//! sequencer) in `ATT_STATE_DIR`. The service adds no authorization logic of its own:
//! every worker request goes through `Adapter::handle`, which authenticates the
//! signature and sequence before the kernel is called (adapter contract §4.8).
//!
//! Endpoints (see docs/protocol.md):
//! - `GET  /healthz`, `GET /v1/info`, `GET /v1/state` (public policy view)
//! - `POST /v1/request` (signed worker request)
//! - `POST /v1/genesis/begin`, `POST /v1/genesis/complete` (bootstrap token)
//! - `GET  /control/{checkpoint,trace,adapter-trace,entropy}` (control token)

use std::path::PathBuf;
use std::sync::Mutex;

use agent_trust::adapter::{Adapter, GenesisPending, SignedRequest, SystemClock, ADAPTER_FILE};
use agent_trust::entropy::{EntropyConfig, LabEntropy, LabProvider};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::config::{self, hex_field, str_field};
use crate::http::{self, Request, Response};

const ROLE: &str = "apf";

enum Phase {
    /// No group yet.
    Waiting,
    /// `begin_genesis` done; waiting for the root's GroupInfo and ratchet tree.
    Pending(Box<GenesisPending<LabProvider, SystemClock>>),
    Ready(Box<Adapter<LabProvider, SystemClock>>),
}

struct Apf {
    dir: PathBuf,
    group: String,
    root: String,
    control_token: Option<String>,
    bootstrap_token: Option<String>,
    entropy: LabEntropy,
    phase: Mutex<Phase>,
    /// `(kernel history length before the request, handling time in µs, command)` of
    /// recent worker requests, for scale measurements (`GET /control/metrics`).
    samples: Mutex<Vec<(u64, u64, String)>>,
}

const SAMPLE_LIMIT: usize = 20_000;

pub fn run() -> Result<(), String> {
    let dir = PathBuf::from(config::required("ATT_STATE_DIR")?);
    let group = config::required("ATT_GROUP")?;
    let root = config::required("ATT_ROOT")?;
    let listen = config::or_default("ATT_LISTEN", "0.0.0.0:7000");
    // C-40: one source, chosen before any request; no fallback.
    let entropy = EntropyConfig::from_env()
        .and_then(|cfg| cfg.connect())
        .map_err(|err| format!("entropy_unavailable: {err}"))?;
    std::fs::create_dir_all(&dir).map_err(|err| format!("state dir: {err}"))?;
    let phase = if dir.join(ADAPTER_FILE).is_file() {
        match Adapter::open(&dir, entropy.provider(), SystemClock) {
            Ok(adapter) => Phase::Ready(Box::new(adapter)),
            Err(err) if err.starts_with("uninitialized") => Phase::Waiting,
            Err(err) => return Err(format!("cannot open adapter state: {err}")),
        }
    } else {
        Phase::Waiting
    };
    let apf = Apf {
        dir,
        group,
        root,
        control_token: config::optional("ATT_CONTROL_TOKEN"),
        bootstrap_token: config::optional("ATT_BOOTSTRAP_TOKEN"),
        entropy,
        phase: Mutex::new(phase),
        samples: Mutex::new(Vec::new()),
    };
    config::log(
        ROLE,
        "listening",
        json!({ "listen": listen, "group": apf.group, "entropy": apf.entropy.label() }),
    );
    http::serve(&listen, 8, move |request| apf.route(request))
}

impl Apf {
    fn route(&self, request: &Request) -> Response {
        let segments = request.segments();
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["healthz"]) => Response::json(json!({ "ok": "apf" })),
            ("GET", ["v1", "info"]) => Response::outcome(self.info()),
            ("GET", ["v1", "state"]) => {
                Response::outcome(self.with_adapter(|_| public_state(&self.dir)))
            }
            ("POST", ["v1", "request"]) => {
                // Under mutual TLS, a request signed by an actor must come from that actor.
                let actor = request.body.get("actor").and_then(Value::as_str).unwrap_or_default();
                if !request.peer_is(&[actor]) {
                    return Response::forbidden_peer();
                }
                Response::outcome(self.request(&request.body))
            }
            ("POST", ["v1", "genesis", step]) => {
                if !http::authorized(request, &self.bootstrap_token) {
                    return Response::status(401, "unauthenticated: bootstrap token");
                }
                if !request.peer_is(&[self.root.as_str()]) {
                    return Response::forbidden_peer();
                }
                match *step {
                    "begin" => Response::outcome(self.begin(&request.body)),
                    "complete" => Response::outcome(self.complete(&request.body)),
                    _ => Response::not_found(),
                }
            }
            ("GET", ["control", what]) => {
                if !http::authorized(request, &self.control_token) {
                    return Response::status(401, "unauthenticated: control token");
                }
                if !request.peer_is(&["attctl"]) {
                    return Response::forbidden_peer();
                }
                match *what {
                    "checkpoint" => Response::outcome(self.with_adapter(|a| a.checkpoint())),
                    "adapter-trace" => {
                        Response::outcome(self.with_adapter(|a| Ok(Value::Array(a.trace()))))
                    }
                    "trace" => Response::outcome(self.trace()),
                    "entropy" => Response::json(json!({ "ok": self.entropy.report() })),
                    "metrics" => Response::outcome(self.metrics()),
                    _ => Response::not_found(),
                }
            }
            _ => Response::not_found(),
        }
    }

    fn with_adapter(
        &self,
        f: impl FnOnce(&mut Adapter<LabProvider, SystemClock>) -> Result<Value, String>,
    ) -> Result<Value, String> {
        let mut phase = self.phase.lock().map_err(|_| "crashed: lock poisoned")?;
        match &mut *phase {
            Phase::Ready(adapter) => f(adapter),
            _ => Err("uninitialized: no group".into()),
        }
    }

    fn info(&self) -> Result<Value, String> {
        let phase = self.phase.lock().map_err(|_| "crashed: lock poisoned")?;
        let (state, key) = match &*phase {
            Phase::Waiting => ("waiting", None),
            Phase::Pending(pending) => ("pending", Some(pending.apf_public_key().to_vec())),
            Phase::Ready(adapter) => ("ready", Some(adapter.apf_public_key().to_vec())),
        };
        Ok(json!({
            "group": self.group,
            "root": self.root,
            "state": state,
            "apf_public_key": key.as_ref().map(hex::encode),
            "apf_key_id": key.as_ref().map(|key| hex::encode(Sha256::digest(key))),
            "entropy": self.entropy.label(),
        }))
    }

    /// `{actor, sequence, body (hex of the exact signed JSON bytes), signature (hex)}`.
    fn request(&self, body: &Value) -> Result<Value, String> {
        let request = SignedRequest {
            actor: str_field(body, "actor")?.to_owned(),
            sequence: body
                .get("sequence")
                .and_then(Value::as_u64)
                .ok_or("malformed: sequence")?,
            body: hex_field(body, "body")?,
            signature: hex_field(body, "signature")?,
        };
        let command = serde_json::from_slice::<Value>(&request.body)
            .ok()
            .and_then(|b| b.get("command").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_default();
        // History length and handling time are measured under the lock, so they exclude
        // the wait for other requests.
        let mut history = 0;
        let mut micros = 0;
        let result = self.with_adapter(|adapter| {
            history = history_length(&self.dir).unwrap_or(0);
            let begin = std::time::Instant::now();
            let result = adapter.handle(&request);
            micros = begin.elapsed().as_micros() as u64;
            result
        });
        if let Ok(mut samples) = self.samples.lock() {
            if samples.len() >= SAMPLE_LIMIT {
                samples.remove(0);
            }
            samples.push((history, micros, command.clone()));
        }
        config::log(
            ROLE,
            "request",
            json!({
                "actor": request.actor, "sequence": request.sequence, "command": command,
                "outcome": match &result { Ok(_) => "ok".to_owned(), Err(e) => config::error_code(e) },
                "us": micros, "history": history,
            }),
        );
        result
    }

    fn metrics(&self) -> Result<Value, String> {
        let samples = self.samples.lock().map_err(|_| "crashed: lock poisoned")?;
        Ok(json!({
            "requests": samples.len(),
            "samples": samples.iter().map(|(h, us, c)| json!([h, us, c])).collect::<Vec<_>>(),
        }))
    }

    /// `{group, root, root_key}` from the root agent: §5.1 steps 1 and 2.
    fn begin(&self, body: &Value) -> Result<Value, String> {
        let group = str_field(body, "group")?;
        let root = str_field(body, "root")?;
        if group != self.group || root != self.root {
            return Err("unauthorized: group or root differs from the APF configuration".into());
        }
        let root_key = hex_field(body, "root_key")?;
        let mut phase = self.phase.lock().map_err(|_| "crashed: lock poisoned")?;
        if matches!(&*phase, Phase::Ready(_)) {
            return Err("already_initialized: the APF already has a group".into());
        }
        let pending = Adapter::begin_genesis(
            &self.dir,
            group,
            root,
            &root_key,
            self.entropy.provider(),
            SystemClock,
        )?;
        let response = json!({
            "apf_public_key": hex::encode(pending.apf_public_key()),
            "founder_certificate": hex::encode(pending.founder_certificate()),
            "acc_context": hex::encode(pending.acc_context()),
        });
        *phase = Phase::Pending(Box::new(pending));
        config::log(ROLE, "genesis_begin", json!({ "group": group, "root": root }));
        Ok(response)
    }

    /// `{group_info, ratchet_tree}`: §5.1 steps 4 and 5.
    fn complete(&self, body: &Value) -> Result<Value, String> {
        let group_info = hex_field(body, "group_info")?;
        let ratchet_tree = hex_field(body, "ratchet_tree")?;
        let mut phase = self.phase.lock().map_err(|_| "crashed: lock poisoned")?;
        let Phase::Pending(pending) = std::mem::replace(&mut *phase, Phase::Waiting) else {
            return Err("invalid_transition: no pending genesis".into());
        };
        let mut adapter = pending.complete(&group_info, &ratchet_tree)?;
        let frontier = adapter.frontier()?;
        *phase = Phase::Ready(Box::new(adapter));
        config::log(ROLE, "genesis_complete", json!({ "epoch": frontier.epoch }));
        Ok(json!({ "epoch": frontier.epoch, "branch": frontier.branch }))
    }

    /// The C-37 v2 trace of the adapter directory. The lock keeps writers out meanwhile.
    fn trace(&self) -> Result<Value, String> {
        let _phase = self.phase.lock().map_err(|_| "crashed: lock poisoned")?;
        Ok(json!({ "trace": agent_trust::lab::export_v2_trace(&self.dir)? }))
    }
}

/// Number of kernel history events, read from the kernel file (0 before genesis).
fn history_length(dir: &std::path::Path) -> Result<u64, String> {
    let connection = rusqlite::Connection::open_with_flags(
        dir.join(agent_trust::adapter::AUTHORITY_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| err.to_string())?;
    connection
        .query_row("SELECT COUNT(*) FROM authority_events", [], |row| row.get::<_, i64>(0))
        .map(|count| count as u64)
        .map_err(|err| err.to_string())
}

/// The public policy view: what a member needs to build a release cover and digest.
/// It is advisory. The kernel re-checks every value at `release` and `consume`.
///
/// It reads the kernel's current state row (`authority_meta`, key `state`), not
/// `checkpoint`, which loads the whole hash-chained history and makes every send cost
/// time proportional to the history (finding F-8).
fn public_state(dir: &std::path::Path) -> Result<Value, String> {
    let connection = rusqlite::Connection::open_with_flags(
        dir.join(agent_trust::adapter::AUTHORITY_FILE),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|err| format!("uninitialized: kernel state: {err}"))?;
    let raw: String = connection
        .query_row("SELECT v FROM authority_meta WHERE k='state'", [], |row| row.get(0))
        .map_err(|err| format!("uninitialized: kernel state: {err}"))?;
    let state: Value = serde_json::from_str(&raw).map_err(|_| "corrupt: kernel state")?;
    let mut view = serde_json::Map::new();
    for key in [
        "group",
        "epoch",
        "branch",
        "policy_revision",
        "read_fenced",
        "repair_pending",
        "roster",
        "grants",
    ] {
        view.insert(key.to_owned(), state.get(key).cloned().unwrap_or(Value::Null));
    }
    Ok(Value::Object(view))
}
