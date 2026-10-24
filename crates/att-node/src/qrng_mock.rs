//! `att-node qrng-mock`: a QRNG Open API server for the testbed.
//!
//! **This is a mock. Its bytes come from the OS RNG, not from a quantum source.**
//! It exists so that every node draws its keys and MLS randomness through the real
//! openmls-qrand HTTP client (`AGENT_TRUST_ENTROPY_SOURCE=qrng`), over the network,
//! exactly as it would against Quside Entropy Core. Pointing
//! `AGENT_TRUST_QRNG_BASE_URL` at a real endpoint replaces it with no code change.
//!
//! Endpoints: `GET /capabilities`, `POST /entropy`, `GET /healthtest`;
//! control: `POST /control/outage {available}`, `GET /control/stats`.

use std::collections::BTreeMap;
use std::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use crate::config;
use crate::http::{self, Response};

const ROLE: &str = "qrng-mock";
const MAX_BLOCK: usize = 1024;

#[derive(Default)]
struct State {
    available: bool,
    requests: u64,
    bytes: u64,
    refused: u64,
    /// Bytes served per client address.
    clients: BTreeMap<String, u64>,
}

pub fn run() -> Result<(), String> {
    let listen = config::or_default("ATT_LISTEN", "0.0.0.0:7200");
    let token = config::optional("ATT_CONTROL_TOKEN");
    let state = Mutex::new(State {
        available: true,
        ..State::default()
    });
    config::log(ROLE, "listening", json!({ "listen": listen, "mock": true }));
    http::serve(&listen, 8, move |request| {
        let segments = request.segments();
        if segments.first() == Some(&"control") && !http::authorized(request, &token) {
            return Response::status(401, "unauthenticated: control token");
        }
        let Ok(mut state) = state.lock() else {
            return Response::status(500, "crashed: lock poisoned");
        };
        match (request.method.as_str(), segments.as_slice()) {
            ("GET", ["healthz"]) => Response::json(json!({ "ok": "qrng-mock" })),
            ("GET", ["capabilities"]) => Response::json(json!({
                "entropy": {
                    "min_block_size": 1, "max_block_size": MAX_BLOCK,
                    "min_block_count": 1, "max_block_count": 1,
                    "entropy_types": ["raw"],
                },
                "source_count": 1,
                "extensions": [{ "mock": true, "origin": "os-rng" }],
            })),
            ("GET", ["healthtest"]) => {
                if state.available {
                    Response::json(json!({ "test_result": [], "extensions": [{ "mock": true }] }))
                } else {
                    Response::status(503, "unavailable")
                }
            }
            ("POST", ["entropy"]) => entropy(&mut state, &request.body, &request.remote),
            ("POST", ["control", "outage"]) => {
                let available = request.body.get("available").and_then(Value::as_bool);
                match available {
                    Some(available) => {
                        state.available = available;
                        config::log(ROLE, "outage", json!({ "available": available }));
                        Response::outcome(Ok(json!({ "available": available })))
                    }
                    None => Response::outcome(Err("malformed: available".into())),
                }
            }
            ("GET", ["control", "stats"]) => Response::outcome(Ok(json!({
                "mock": true, "available": state.available, "requests": state.requests,
                "bytes": state.bytes, "refused": state.refused, "clients": state.clients,
            }))),
            _ => Response::not_found(),
        }
    })
}

fn entropy(state: &mut State, body: &Value, remote: &str) -> Response {
    state.requests += 1;
    if !state.available {
        state.refused += 1;
        return Response::status(503, "entropy unavailable");
    }
    let size = body.get("block_size").and_then(Value::as_u64).unwrap_or(0) as usize;
    let count = body.get("block_count").and_then(Value::as_u64).unwrap_or(1) as usize;
    if size == 0 || size > MAX_BLOCK || count != 1 {
        return Response::status(422, "invalid request");
    }
    let mut block = vec![0u8; size];
    if getrandom::getrandom(&mut block).is_err() {
        state.refused += 1;
        return Response::status(503, "entropy unavailable");
    }
    state.bytes += size as u64;
    *state.clients.entry(remote.to_owned()).or_default() += size as u64;
    Response::json(json!({ "entropy": [STANDARD.encode(&block)] }))
}
