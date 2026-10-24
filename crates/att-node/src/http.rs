//! Minimal synchronous HTTP/1.1 layer shared by every service, over plain TCP or
//! mutual TLS (see `tls`).
//!
//! Server: an accept loop hands each connection to a fixed pool of worker threads; one
//! request per connection (`Connection: close`). Client: `ureq`, with the deployment's
//! client certificate when TLS is configured.
//!
//! Every body is JSON. Protocol outcomes are HTTP 200 with `{"ok": ...}` or
//! `{"error": "<code>: <detail>"}`, the same convention as the agent-trust lab.
//! Transport problems (unknown path, bad JSON, missing token or peer) use 4xx statuses.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use crate::tls;

/// Maximum accepted request body (8 MiB): envelopes and commits are well below it.
const MAX_BODY: usize = 8 * 1024 * 1024;
/// Maximum size of the request line and headers.
const MAX_HEAD: usize = 64 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Request {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub bearer: Option<String>,
    pub remote: String,
    /// The verified client certificate's common name under mutual TLS.
    pub peer: Option<String>,
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

    /// Under mutual TLS, whether the peer is one of `names`. Without TLS there is no
    /// transport identity, and the check passes (tokens and signatures still apply).
    pub fn peer_is(&self, names: &[&str]) -> bool {
        if !tls::enabled() {
            return true;
        }
        self.peer
            .as_deref()
            .is_some_and(|peer| names.contains(&peer))
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

    pub fn forbidden_peer() -> Self {
        Self::status(403, "unauthenticated: transport identity")
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
    let listener =
        TcpListener::bind(addr).map_err(|err| format!("cannot listen on {addr}: {err}"))?;
    let handler = Arc::new(handler);
    let (sender, receiver) = mpsc::channel::<TcpStream>();
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..workers.max(1) {
        let receiver = Arc::clone(&receiver);
        let handler = Arc::clone(&handler);
        std::thread::spawn(move || loop {
            let stream = match receiver.lock().map(|r| r.recv()) {
                Ok(Ok(stream)) => stream,
                _ => return,
            };
            let _ = serve_connection(stream, handler.as_ref());
        });
    }
    for stream in listener.incoming().flatten() {
        if sender.send(stream).is_err() {
            break;
        }
    }
    Ok(())
}

fn serve_connection<H>(stream: TcpStream, handler: &H) -> Result<(), String>
where
    H: Fn(&Request) -> Response,
{
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let remote = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    match tls::get() {
        None => exchange(stream, remote, None, handler),
        Some(tls) => {
            let connection = rustls::ServerConnection::new(Arc::clone(&tls.server))
                .map_err(|e| e.to_string())?;
            let mut stream = rustls::StreamOwned::new(connection, stream);
            // Complete the handshake to learn the verified peer.
            while stream.conn.is_handshaking() {
                stream
                    .conn
                    .complete_io(&mut stream.sock)
                    .map_err(|e| format!("TLS handshake: {e}"))?;
            }
            let peer = stream
                .conn
                .peer_certificates()
                .and_then(|certs| certs.first())
                .and_then(tls::common_name);
            exchange(stream, remote, peer, handler)
        }
    }
}

fn exchange<S, H>(
    stream: S,
    remote: String,
    peer: Option<String>,
    handler: &H,
) -> Result<(), String>
where
    S: Read + Write,
    H: Fn(&Request) -> Response,
{
    let mut reader = BufReader::new(stream);
    let response = match parse(&mut reader, remote, peer) {
        Ok(request) => handler(&request),
        Err(response) => response,
    };
    let body = serde_json::to_vec(&response.body).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        reason(response.status),
        body.len()
    );
    let stream = reader.get_mut();
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&body))
        .and_then(|()| stream.flush())
        .map_err(|e| e.to_string())
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        413 => "Payload Too Large",
        _ => "Error",
    }
}

fn parse<R: BufRead>(
    reader: &mut R,
    remote: String,
    peer: Option<String>,
) -> Result<Request, Response> {
    let bad = |message: &str| Response::status(400, message);
    let mut head_size = 0;
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|_| bad("malformed: request line"))?;
    head_size += line.len();
    let mut parts = line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Err(bad("malformed: request line"));
    };
    let (method, target) = (method.to_owned(), target.to_owned());
    let mut length = 0usize;
    let mut bearer = None;
    loop {
        let mut header = String::new();
        reader
            .read_line(&mut header)
            .map_err(|_| bad("malformed: header"))?;
        head_size += header.len();
        if head_size > MAX_HEAD {
            return Err(bad("malformed: header too large"));
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let Some((name, value)) = header.split_once(':') else {
            return Err(bad("malformed: header"));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            length = value
                .parse()
                .map_err(|_| bad("malformed: content-length"))?;
        } else if name.eq_ignore_ascii_case("authorization") {
            bearer = value.strip_prefix("Bearer ").map(str::to_owned);
        }
    }
    if length > MAX_BODY {
        return Err(Response::status(413, "malformed: body too large"));
    }
    let mut bytes = vec![0u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|_| bad("malformed: body"))?;
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).map_err(|_| bad("malformed: JSON"))?
    };
    let (path, query_text) = match target.split_once('?') {
        Some((path, query)) => (path.to_owned(), query.to_owned()),
        None => (target, String::new()),
    };
    let query = query_text
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect();
    Ok(Request {
        method,
        path,
        query,
        bearer,
        remote,
        peer,
        body,
    })
}

/// A JSON HTTP client for one base URL, with an optional bearer token. An `https://`
/// base uses the deployment's client certificate (mutual TLS).
#[derive(Clone)]
pub struct Client {
    base: String,
    token: Option<String>,
    agent: ureq::Agent,
}

impl Client {
    pub fn new(base: &str, token: Option<String>) -> Self {
        let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(30));
        if let Some(tls) = tls::get() {
            builder = builder.tls_config(Arc::clone(&tls.client));
        }
        Self {
            base: base.trim_end_matches('/').to_owned(),
            token,
            agent: builder.build(),
        }
    }

    /// The decoded JSON body of any 2xx or 4xx response; `transport:` for anything else.
    fn send(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let mut request = self
            .agent
            .request(method, &format!("{}{}", self.base, path));
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

/// `att-node probe URL`: exits 0 when `GET URL` answers `{"ok": ...}` (a readiness
/// probe that also works under mutual TLS).
pub fn run_probe(url: &str) -> Result<(), String> {
    let (base, path) = match url
        .find("://")
        .and_then(|i| url[i + 3..].find('/').map(|j| i + 3 + j))
    {
        Some(split) => (&url[..split], &url[split..]),
        None => (url, "/healthz"),
    };
    Client::new(base, None).call("GET", path, None).map(|_| ())
}
