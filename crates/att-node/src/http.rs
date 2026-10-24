//! Minimal synchronous HTTP layer shared by every service.
//!
//! Server: `tiny_http` with a fixed pool of worker threads. Client: `ureq`.
//! Every body is JSON. Protocol outcomes are HTTP 200 with `{"ok": ...}` or
//! `{"error": "<code>: <detail>"}`, the same convention as the agent-trust lab.
//! Transport problems (unknown path, bad JSON, missing token) use 4xx statuses.

use std::collections::BTreeMap;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

/// Maximum accepted request body (8 MiB): envelopes and commits are well below it.
const MAX_BODY: usize = 8 * 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub bearer: Option<String>,
    pub remote: String,
    pub body: Value,
}

impl Request {
    /// The path split into non-empty segments.
    pub fn segments(&self) -> Vec<&str> {
        self.path.split('/').filter(|s| !s.is_empty()).collect()
    }

    pub fn query_u64(&self, key: &str) -> Option<u64> {
        self.query.get(key).and_then(|value| value.parse().ok())
    }
}

pub struct Response {
    pub status: u16,
    pub body: Value,
}

impl Response {
    pub fn json(body: Value) -> Self {
        Self { status: 200, body }
    }

    /// `{"ok": value}` or `{"error": message}`, both with status 200.
    pub fn outcome(result: Result<Value, String>) -> Self {
        match result {
            Ok(value) => Self::json(json!({ "ok": value })),
            Err(error) => Self::json(json!({ "error": error })),
        }
    }

    pub fn status(status: u16, message: &str) -> Self {
        Self {
            status,
            body: json!({ "error": message }),
        }
    }

    pub fn not_found() -> Self {
        Self::status(404, "not_found")
    }
}

/// Checks `Authorization: Bearer <token>` when a token is configured.
pub fn authorized(request: &Request, token: &Option<String>) -> bool {
    match token {
        None => true,
        Some(expected) => request.bearer.as_deref() == Some(expected.as_str()),
    }
}

/// Serves `handler` on `addr` with `workers` threads. Never returns on success.
pub fn serve<H>(addr: &str, workers: usize, handler: H) -> Result<(), String>
where
    H: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let server = Arc::new(
        tiny_http::Server::http(addr).map_err(|err| format!("cannot listen on {addr}: {err}"))?,
    );
    let handler = Arc::new(handler);
    let mut threads = Vec::new();
    for _ in 0..workers.max(1) {
        let server = Arc::clone(&server);
        let handler = Arc::clone(&handler);
        threads.push(std::thread::spawn(move || loop {
            let Ok(mut raw) = server.recv() else { continue };
            let response = match parse(&mut raw) {
                Ok(request) => handler(&request),
                Err(response) => response,
            };
            let body = serde_json::to_vec(&response.body).unwrap_or_default();
            let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("static header");
            let reply = tiny_http::Response::from_data(body)
                .with_status_code(response.status)
                .with_header(header);
            let _ = raw.respond(reply);
        }));
    }
    for thread in threads {
        let _ = thread.join();
    }
    Ok(())
}

fn parse(raw: &mut tiny_http::Request) -> Result<Request, Response> {
    let url = raw.url().to_owned();
    let (path, query_text) = match url.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (url, String::new()),
    };
    let query = query_text
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    let bearer = raw
        .headers()
        .iter()
        .find(|header| header.field.equiv("Authorization"))
        .and_then(|header| header.value.as_str().strip_prefix("Bearer ").map(str::to_owned));
    let remote = raw
        .remote_addr()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_default();
    let mut bytes = Vec::new();
    raw.as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Response::status(400, "malformed: body"))?;
    if bytes.len() > MAX_BODY {
        return Err(Response::status(413, "malformed: body too large"));
    }
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|_| Response::status(400, "malformed: JSON"))?
    };
    Ok(Request {
        method: raw.method().as_str().to_owned(),
        path,
        query,
        bearer,
        remote,
        body,
    })
}

/// A JSON HTTP client for one base URL, with an optional bearer token.
#[derive(Clone)]
pub struct Client {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str, token: Option<String>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_owned(),
            token,
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    /// The decoded JSON body of any 2xx or 4xx response; `transport:` for anything else.
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let mut request = self.agent.request(method, &format!("{}{}", self.base, path));
        if let Some(token) = &self.token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let result = match body {
            Some(body) => request.send_json(body.clone()),
            None => request.call(),
        };
        let response = match result {
            Ok(response) => response,
            Err(ureq::Error::Status(_, response)) => response,
            Err(err) => return Err(format!("transport: {}", err.kind())),
        };
        response
            .into_json::<Value>()
            .map_err(|_| "transport: response is not JSON".to_string())
    }

    /// Calls an endpoint that answers `{"ok": v}` or `{"error": e}` and unwraps it.
    pub fn call(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let value = self.send(method, path, body)?;
        if let Some(ok) = value.get("ok") {
            return Ok(ok.clone());
        }
        Err(value
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("transport: unexpected response")
            .to_owned())
    }
}
