//! Test-only fake QRNG Open API server (`GET /capabilities`, `POST /entropy`).
//!
//! Served bytes are a deterministic SHA-256 counter stream. They are distinct
//! per block so MLS key-uniqueness checks behave as with real entropy, but they
//! are not random and must never back a non-test laboratory.
#![allow(dead_code)]

use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
    time::Duration,
};

use base64::{engine::general_purpose::STANDARD, Engine};
use openmls_qrand::{ApiAuth, QrngClient, QrngConfig, TransportMode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Default)]
struct FakeState {
    unavailable: bool,
    entropy_posts: usize,
    served_blocks: Vec<Vec<u8>>,
    authorization_headers: Vec<Option<String>>,
    counter: u64,
}

/// Minimal QRNG Open API: `GET /capabilities` and `POST /entropy`. Served bytes
/// are a SHA-256 counter stream: test-only and deliberately non-random, but
/// distinct per block so MLS key-uniqueness checks behave as with real entropy.
pub struct FakeQrng {
    server: Arc<tiny_http::Server>,
    state: Arc<Mutex<FakeState>>,
    thread: Option<JoinHandle<()>>,
}

impl FakeQrng {
    pub fn start() -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind fake QRNG"));
        let state = Arc::new(Mutex::new(FakeState::default()));
        let thread = {
            let server = server.clone();
            let state = state.clone();
            std::thread::spawn(move || {
                for mut request in server.incoming_requests() {
                    let mut body = String::new();
                    let _ = request.as_reader().read_to_string(&mut body);
                    let authorization = request
                        .headers()
                        .iter()
                        .find(|header| header.field.equiv("Authorization"))
                        .map(|header| header.value.to_string());
                    state
                        .lock()
                        .expect("fake state")
                        .authorization_headers
                        .push(authorization);
                    let (status, payload) = respond(&state, request.method(), request.url(), &body);
                    let header = tiny_http::Header::from_bytes("Content-Type", "application/json")
                        .expect("static header");
                    let _ = request.respond(
                        tiny_http::Response::from_string(payload.to_string())
                            .with_status_code(status)
                            .with_header(header),
                    );
                }
            })
        };
        Self {
            server,
            state,
            thread: Some(thread),
        }
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.server.server_addr())
    }

    pub fn client(&self) -> Arc<QrngClient> {
        let base_url = self.base_url();
        Arc::new(
            QrngClient::connect(QrngConfig {
                base_url: base_url.parse().expect("fake QRNG URL"),
                transport: TransportMode::PlainHttp,
                auth: ApiAuth::None,
                entropy_type: None,
                request_timeout: Duration::from_secs(5),
                health_poll_interval: None,
            })
            .expect("connect to fake QRNG"),
        )
    }

    pub fn set_unavailable(&self, unavailable: bool) {
        self.state.lock().expect("fake state").unavailable = unavailable;
    }

    pub fn entropy_posts(&self) -> usize {
        self.state.lock().expect("fake state").entropy_posts
    }

    pub fn served_blocks(&self) -> Vec<Vec<u8>> {
        self.state.lock().expect("fake state").served_blocks.clone()
    }

    pub fn authorization_headers(&self) -> Vec<Option<String>> {
        self.state
            .lock()
            .expect("fake state")
            .authorization_headers
            .clone()
    }
}

impl Drop for FakeQrng {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(
    state: &Mutex<FakeState>,
    method: &tiny_http::Method,
    url: &str,
    body: &str,
) -> (u16, Value) {
    let mut state = state.lock().expect("fake state");
    match (method, url) {
        (tiny_http::Method::Get, "/capabilities") => (
            200,
            json!({"entropy": {"min_block_size": 1, "max_block_size": 1024,
                               "min_block_count": 1, "max_block_count": 1}}),
        ),
        (tiny_http::Method::Post, "/entropy") => {
            if state.unavailable {
                return (503, json!({"detail": "entropy unavailable"}));
            }
            let request: Value = serde_json::from_str(body).unwrap_or(Value::Null);
            let Some(size) = request["block_size"].as_u64() else {
                return (422, json!({"detail": "block_size required"}));
            };
            let mut block = Vec::with_capacity(size as usize);
            while block.len() < size as usize {
                state.counter += 1;
                block.extend_from_slice(&Sha256::digest(state.counter.to_be_bytes()));
            }
            block.truncate(size as usize);
            state.entropy_posts += 1;
            state.served_blocks.push(block.clone());
            (200, json!({"entropy": [STANDARD.encode(&block)]}))
        }
        _ => (404, json!({"detail": "not found"})),
    }
}
