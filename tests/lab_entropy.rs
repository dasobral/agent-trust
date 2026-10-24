//! C-40 contract tests: lab entropy selection (`docs/adapter-contract.md` §8.1).
//!
//! The lab selects one entropy source at startup, from a TOML file or environment
//! variables: `os` (default), `mock` (openmls-qrand `MockEntropy`, a seeded stream that is
//! NOT random) or `qrng` (a QRNG Open API endpoint). Every provider and every identity
//! key the lab creates draws from that source. Errors fail closed and never name the
//! endpoint. Secrets are never read from the file.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, TcpListener};
use std::path::Path;
use std::thread;
use std::time::Duration;

use agent_trust::adapter::ClientIdentity;
use agent_trust::entropy::{EntropyConfig, QrngAuth, QrngSettings, QrngTransport};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use serde_json::json;
use tiny_http::{Header, Response, Server};

const CONFIG_ENV: &str = "AGENT_TRUST_ENTROPY_CONFIG";
const SOURCE_ENV: &str = "AGENT_TRUST_ENTROPY_SOURCE";

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn parse(text: &str) -> Result<EntropyConfig, String> {
    EntropyConfig::parse(text, Path::new("base"))
}

fn plain(base_url: &str) -> EntropyConfig {
    EntropyConfig::Qrng(QrngSettings {
        base_url: base_url.into(),
        transport: QrngTransport::PlainHttp,
        auth: QrngAuth::None,
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
    })
}

/// A loopback port with nothing listening on it.
fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind a loopback port");
    listener.local_addr().expect("local address").port()
}

// ---------------------------------------------------------------------------
// Configuration file
// ---------------------------------------------------------------------------

#[test]
fn file_selects_each_source() {
    assert_eq!(parse(r#"source = "os""#), Ok(EntropyConfig::Os));
    assert_eq!(
        parse("source = \"mock\"\n[mock]\nseed = 42\n"),
        Ok(EntropyConfig::Mock { seed: 42 })
    );
    assert_eq!(
        parse(r#"source = "mock""#),
        Ok(EntropyConfig::Mock { seed: 0 }),
        "the mock seed defaults to 0"
    );
    assert_eq!(
        parse(
            r#"
            source = "qrng"
            [qrng]
            base_url = "http://127.0.0.1:8002"
            transport = "plain-http"
            "#
        ),
        Ok(plain("http://127.0.0.1:8002"))
    );
    // Switching sources is a one-line change: other sections are kept but unused.
    assert_eq!(
        parse(
            r#"
            source = "os"
            [mock]
            seed = 3
            [qrng]
            base_url = "http://127.0.0.1:8002"
            transport = "plain-http"
            "#
        ),
        Ok(EntropyConfig::Os)
    );
    for (config, label) in [
        (EntropyConfig::Os, "os"),
        (EntropyConfig::Mock { seed: 1 }, "mock"),
        (plain("http://127.0.0.1:8002"), "qrng"),
    ] {
        assert_eq!(config.label(), label);
    }
}

#[test]
fn file_paths_resolve_relative_to_the_file_and_auth_names_a_variable() {
    let config = parse(
        r#"
        source = "qrng"
        [qrng]
        base_url = "https://entropy.example.net"
        transport = "mtls"
        ca_cert_pem = "certs/ca.pem"
        client_cert_pem = "certs/client.crt"
        client_key_pem = "certs/client.key"
        auth = "x-api-key"
        auth_secret_env = "QRNG_API_KEY"
        entropy_type = "raw"
        request_timeout_ms = 2500
        "#,
    );
    assert_eq!(
        config,
        Ok(EntropyConfig::Qrng(QrngSettings {
            base_url: "https://entropy.example.net".into(),
            transport: QrngTransport::MutualTls {
                ca_cert_pem: Path::new("base").join("certs/ca.pem"),
                client_cert_pem: Path::new("base").join("certs/client.crt"),
                client_key_pem: Path::new("base").join("certs/client.key"),
            },
            auth: QrngAuth::XApiKey {
                secret_env: "QRNG_API_KEY".into()
            },
            entropy_type: Some("raw".into()),
            request_timeout: Duration::from_millis(2500),
        }))
    );
}

#[test]
fn invalid_files_are_rejected() {
    let qrng = |body: &str| format!("source = \"qrng\"\n[qrng]\n{body}");
    let cases = [
        // A literal secret must not be accepted in the file.
        qrng("base_url = \"http://127.0.0.1:8002\"\ntransport = \"plain-http\"\ntoken = \"s3cret\""),
        "source = \"qrng\"".to_owned(),
        "source = \"urandom\"".to_owned(),
        "seed = 1".to_owned(),
        "source = \"mock\"\n[mock]\nseed = -1".to_owned(),
        "source = \"mock\"\n[mock]\nseed = 1\nbytes = \"00\"".to_owned(),
        qrng("base_url = \"https://entropy.example.net\"\ntransport = \"plain-http\""),
        qrng("base_url = \"http://entropy.example.net\"\ntransport = \"tls\""),
        qrng("base_url = \"http://127.0.0.1:8002/?x=1\"\ntransport = \"plain-http\""),
        qrng("base_url = \"not a url\"\ntransport = \"plain-http\""),
        qrng("base_url = \"http://127.0.0.1:8002\"\ntransport = \"plain-http\"\nca_cert_pem = \"ca.pem\""),
        qrng("base_url = \"https://e.example\"\ntransport = \"tls\"\nclient_key_pem = \"k.pem\""),
        qrng("base_url = \"https://e.example\"\ntransport = \"mtls\"\nca_cert_pem = \"ca.pem\""),
        qrng("base_url = \"http://127.0.0.1:8002\"\ntransport = \"plain-http\"\nauth = \"bearer\""),
        qrng("base_url = \"http://127.0.0.1:8002\"\ntransport = \"plain-http\"\nauth_secret_env = \"T\""),
        qrng("base_url = \"http://127.0.0.1:8002\"\ntransport = \"plain-http\"\nrequest_timeout_ms = 0"),
    ];
    for case in cases {
        assert!(parse(&case).is_err(), "accepted an invalid file:\n{case}");
    }
}

#[test]
fn config_file_is_loaded_from_the_environment() {
    let dir = tempfile::tempdir().expect("temporary directory");
    let path = dir.path().join("entropy.toml");
    std::fs::write(&path, "source = \"mock\"\n[mock]\nseed = 7\n").expect("write the config");
    let path = path.to_str().expect("utf-8 path");
    assert_eq!(
        EntropyConfig::from_env_with(env(&[(CONFIG_ENV, path)])),
        Ok(EntropyConfig::Mock { seed: 7 })
    );
    let missing = dir.path().join("missing.toml");
    assert!(EntropyConfig::from_env_with(env(&[(
        CONFIG_ENV,
        missing.to_str().expect("utf-8 path")
    )]))
    .is_err());
}

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

#[test]
fn environment_selects_the_source() {
    let select = |pairs: &[(&str, &str)]| EntropyConfig::from_env_with(env(pairs));
    assert_eq!(select(&[]), Ok(EntropyConfig::Os), "nothing set selects os");
    assert_eq!(select(&[(SOURCE_ENV, "os")]), Ok(EntropyConfig::Os));
    assert_eq!(
        select(&[(SOURCE_ENV, "mock")]),
        Ok(EntropyConfig::Mock { seed: 0 })
    );
    assert_eq!(
        select(&[(SOURCE_ENV, "mock"), ("AGENT_TRUST_MOCK_SEED", "9")]),
        Ok(EntropyConfig::Mock { seed: 9 })
    );
    assert_eq!(
        select(&[
            (SOURCE_ENV, "qrng"),
            ("AGENT_TRUST_QRNG_BASE_URL", "http://127.0.0.1:8002")
        ]),
        Ok(plain("http://127.0.0.1:8002"))
    );
    // The QRNG variables are those of the live gate (`tests/adapter_entropy.rs`).
    assert_eq!(
        select(&[
            (SOURCE_ENV, "qrng"),
            ("AGENT_TRUST_QRNG_BASE_URL", "https://entropy.example.net"),
            ("AGENT_TRUST_QRNG_CA_PEM", "ca.pem"),
            ("AGENT_TRUST_QRNG_CLIENT_CERT_PEM", "client.crt"),
            ("AGENT_TRUST_QRNG_CLIENT_KEY_PEM", "client.key"),
            ("AGENT_TRUST_QRNG_BEARER_TOKEN", "not-a-real-token"),
            ("AGENT_TRUST_QRNG_ENTROPY_TYPE", "raw"),
        ]),
        Ok(EntropyConfig::Qrng(QrngSettings {
            base_url: "https://entropy.example.net".into(),
            transport: QrngTransport::MutualTls {
                ca_cert_pem: "ca.pem".into(),
                client_cert_pem: "client.crt".into(),
                client_key_pem: "client.key".into(),
            },
            auth: QrngAuth::Bearer {
                secret_env: "AGENT_TRUST_QRNG_BEARER_TOKEN".into()
            },
            entropy_type: Some("raw".into()),
            request_timeout: Duration::from_secs(5),
        }))
    );
    assert_eq!(
        select(&[
            (SOURCE_ENV, "qrng"),
            ("AGENT_TRUST_QRNG_BASE_URL", "https://entropy.example.net"),
            ("AGENT_TRUST_QRNG_API_KEY", "not-a-real-key"),
        ]),
        Ok(EntropyConfig::Qrng(QrngSettings {
            base_url: "https://entropy.example.net".into(),
            transport: QrngTransport::Tls { ca_cert_pem: None },
            auth: QrngAuth::XApiKey {
                secret_env: "AGENT_TRUST_QRNG_API_KEY".into()
            },
            entropy_type: None,
            request_timeout: Duration::from_secs(5),
        }))
    );
}

#[test]
fn ambiguous_or_incomplete_environments_are_rejected() {
    let select = |pairs: &[(&str, &str)]| EntropyConfig::from_env_with(env(pairs));
    let url = ("AGENT_TRUST_QRNG_BASE_URL", "https://entropy.example.net");
    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![(SOURCE_ENV, "urandom")],
        vec![(SOURCE_ENV, "")],
        vec![(SOURCE_ENV, "mock"), (CONFIG_ENV, "entropy.toml")],
        vec![(SOURCE_ENV, "mock"), ("AGENT_TRUST_MOCK_SEED", "seven")],
        vec![(SOURCE_ENV, "qrng")],
        vec![
            (SOURCE_ENV, "qrng"),
            ("AGENT_TRUST_QRNG_BASE_URL", "not a url"),
        ],
        vec![
            (SOURCE_ENV, "qrng"),
            url,
            ("AGENT_TRUST_QRNG_BEARER_TOKEN", "t"),
            ("AGENT_TRUST_QRNG_API_KEY", "k"),
        ],
        vec![
            (SOURCE_ENV, "qrng"),
            url,
            ("AGENT_TRUST_QRNG_CLIENT_CERT_PEM", "c.pem"),
        ],
        vec![
            (SOURCE_ENV, "qrng"),
            ("AGENT_TRUST_QRNG_BASE_URL", "http://127.0.0.1:8002"),
            ("AGENT_TRUST_QRNG_CA_PEM", "ca.pem"),
        ],
    ];
    for case in cases {
        assert!(
            select(&case).is_err(),
            "accepted an invalid environment: {case:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The selected source
// ---------------------------------------------------------------------------

#[test]
fn os_source_reports_os_and_has_no_outage_control() {
    let lab = EntropyConfig::Os.connect_with(env(&[])).expect("os source");
    assert_eq!(lab.label(), "os");
    assert_eq!(lab.report(), json!({ "source": "os" }));
    ClientIdentity::generate(&lab.rand()).expect("os identity");
    let error = lab
        .set_available(false)
        .expect_err("os has no outage control");
    assert!(error.starts_with("unsupported"), "{error}");
}

#[test]
fn mock_source_drives_every_lab_draw_from_one_seeded_stream() {
    let lab = EntropyConfig::Mock { seed: 5 }
        .connect_with(env(&[]))
        .expect("mock source");
    assert_eq!(lab.label(), "mock");
    // Connecting seeds the lab crypto provider: 32 bytes of entropy and a 32-byte nonce.
    assert_eq!(
        lab.report(),
        json!({ "source": "mock", "requests": 2, "bytes": 64, "failures": 0 })
    );

    // Identity keys: one 32-byte draw each, from the same stream for rand() and provider().
    let first = ClientIdentity::generate(&lab.rand()).expect("identity from rand()");
    let provider = lab.provider();
    let second = ClientIdentity::generate(provider.rand()).expect("identity from provider()");
    assert_eq!(
        lab.report(),
        json!({ "source": "mock", "requests": 4, "bytes": 128, "failures": 0 })
    );
    assert_ne!(first.public_key(), second.public_key());

    // Clones share the stream; the same seed replays it; another seed does not.
    let clone = lab.clone();
    clone.rand().random_vec(3).expect("draw through a clone");
    assert_eq!(lab.report()["requests"], 5);
    let replay = EntropyConfig::Mock { seed: 5 }
        .connect_with(env(&[]))
        .expect("mock source");
    assert_eq!(
        ClientIdentity::generate(&replay.rand())
            .expect("replayed identity")
            .public_key(),
        first.public_key()
    );
    let other = EntropyConfig::Mock { seed: 6 }
        .connect_with(env(&[]))
        .expect("mock source");
    assert_ne!(
        ClientIdentity::generate(&other.rand())
            .expect("other identity")
            .public_key(),
        first.public_key()
    );
}

#[test]
fn mock_outage_fails_closed_and_recovers() {
    let lab = EntropyConfig::Mock { seed: 1 }
        .connect_with(env(&[]))
        .expect("mock source");
    let reference = EntropyConfig::Mock { seed: 1 }
        .connect_with(env(&[]))
        .expect("mock source");

    lab.set_available(false).expect("mock outage control");
    let error = ClientIdentity::generate(&lab.rand())
        .err()
        .expect("no entropy, no identity");
    assert_eq!(error, "entropy_unavailable");
    assert!(lab.provider().rand().random_vec(16).is_err());
    // The two successful requests are the seeding of the lab crypto provider at connect.
    assert_eq!(
        lab.report(),
        json!({ "source": "mock", "requests": 2, "bytes": 64, "failures": 2 })
    );

    lab.set_available(true).expect("mock outage control");
    assert_eq!(
        ClientIdentity::generate(&lab.rand())
            .expect("identity after restore")
            .public_key(),
        ClientIdentity::generate(&reference.rand())
            .expect("reference")
            .public_key(),
        "a refused draw consumes nothing and is replaced by nothing"
    );
}

#[test]
fn unreachable_qrng_fails_closed_without_naming_the_endpoint() {
    let port = closed_port();
    let error = plain(&format!("http://127.0.0.1:{port}"))
        .connect_with(env(&[]))
        .err()
        .expect("an unreachable QRNG must not connect");
    assert!(error.contains("QRNG"), "{error}");
    assert!(
        !error.contains(&port.to_string()),
        "the error names the endpoint: {error}"
    );
    assert!(
        !error.contains("127.0.0.1"),
        "the error names the endpoint: {error}"
    );
}

#[test]
fn qrng_secret_is_read_only_from_the_named_variable() {
    let config = EntropyConfig::Qrng(QrngSettings {
        base_url: format!("http://127.0.0.1:{}", closed_port()),
        transport: QrngTransport::PlainHttp,
        auth: QrngAuth::Bearer {
            secret_env: "LAB_TEST_QRNG_TOKEN".into(),
        },
        entropy_type: None,
        request_timeout: Duration::from_secs(5),
    });
    let error = config
        .connect_with(env(&[]))
        .err()
        .expect("a missing secret must not connect");
    assert!(error.contains("LAB_TEST_QRNG_TOKEN"), "{error}");
    // With the secret present, the failure is the unreachable endpoint, and the secret
    // value never appears in the error.
    let error = config
        .connect_with(env(&[("LAB_TEST_QRNG_TOKEN", "not-a-real-token")]))
        .err()
        .expect("an unreachable QRNG must not connect");
    assert!(!error.contains("LAB_TEST_QRNG_TOKEN"), "{error}");
    assert!(!error.contains("not-a-real-token"), "{error}");
}

/// A QRNG that answers `/capabilities` and the two draws that seed the lab crypto
/// provider at connect, and then disappears.
fn vanishing_qrng() -> (String, u16) {
    let server = Server::http((Ipv4Addr::LOCALHOST, 0)).expect("loopback test server");
    let port = server.server_addr().to_ip().expect("ip address").port();
    thread::spawn(move || {
        let capabilities = json!({"entropy": {"min_block_size": 1, "max_block_size": 1024,
                                              "min_block_count": 1, "max_block_count": 1}});
        // Two fixed 32-byte blocks (0x00..0x1f and 0x20..0x3f), base64-encoded.
        let seed_draws = [
            json!({"entropy": ["AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="]}),
            json!({"entropy": ["ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8="]}),
        ];
        for body in std::iter::once(capabilities).chain(seed_draws) {
            let Ok(request) = server.recv() else { return };
            let header = Header::from_bytes("Content-Type", "application/json").expect("header");
            let _ = request.respond(Response::from_string(body.to_string()).with_header(header));
        }
        // The server is dropped here: the port closes.
    });
    (format!("http://127.0.0.1:{port}"), port)
}

#[test]
fn qrng_outage_mid_session_fails_closed_without_naming_the_endpoint() {
    let (url, port) = vanishing_qrng();
    let lab = plain(&url)
        .connect_with(env(&[]))
        .expect("connect to the test QRNG");
    assert_eq!(lab.label(), "qrng");
    thread::sleep(Duration::from_millis(100));

    let error = lab
        .rand()
        .random_vec(32)
        .expect_err("a vanished QRNG must fail the draw");
    let shown = format!("{error} {error:?}");
    assert!(
        !shown.contains(&port.to_string()),
        "the error names the endpoint: {shown}"
    );
    assert!(
        !shown.contains("127.0.0.1"),
        "the error names the endpoint: {shown}"
    );
    assert_eq!(
        ClientIdentity::generate(&lab.rand())
            .err()
            .expect("no identity without entropy"),
        "entropy_unavailable"
    );
    let report = lab.report();
    assert_eq!(report["source"], "qrng");
    // The two successful requests seeded the lab crypto provider at connect.
    assert_eq!(report["requests"], 2);
    assert_eq!(report["failures"], 2);
}

#[test]
fn example_config_file_parses() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/entropy.example.toml");
    assert_eq!(
        EntropyConfig::load(&path),
        Ok(EntropyConfig::Mock { seed: 0 })
    );
}
