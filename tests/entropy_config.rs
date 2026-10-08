//! Configuration contract for selecting the laboratory entropy source.
//!
//! The same laboratory must switch between the OS source, the development fake
//! QRNG server, and a real Entropy Core endpoint through configuration only.
//! Secrets are referenced by environment-variable name, never stored in the file.

mod common;

use std::{collections::BTreeMap, path::Path, time::Duration};

use agent_trust::entropy::{EntropyConfig, QrngAuth, QrngSettings, QrngTransport};
use agent_trust::mls::{EntropySource, MlsLab};
use common::FakeQrng;

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: BTreeMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

fn parse(text: &str) -> Result<EntropyConfig, String> {
    EntropyConfig::parse(text, Path::new("/etc/agent-trust"))
}

#[test]
fn qrng_file_selects_plain_http_with_defaults() {
    let config = parse(
        r#"
        source = "qrng"
        [qrng]
        base_url = "http://127.0.0.1:8002"
        transport = "plain-http"
        "#,
    )
    .expect("valid QRNG configuration");

    assert_eq!(config.label(), "qrng");
    assert_eq!(
        config,
        EntropyConfig::Qrng(QrngSettings {
            base_url: "http://127.0.0.1:8002".into(),
            transport: QrngTransport::PlainHttp,
            auth: QrngAuth::None,
            entropy_type: None,
            request_timeout: Duration::from_secs(5),
        })
    );
}

#[test]
fn os_file_selects_os_source_even_with_a_qrng_section() {
    // Switching back to the OS source is a one-line change.
    let config = parse(
        r#"
        source = "os"
        [qrng]
        base_url = "http://127.0.0.1:8002"
        transport = "plain-http"
        "#,
    )
    .expect("valid OS configuration");

    assert_eq!(config, EntropyConfig::Os);
    assert_eq!(config.label(), "os");
}

#[test]
fn mtls_paths_resolve_relative_to_the_config_file_and_auth_names_an_env_var() {
    let config = parse(
        r#"
        source = "qrng"
        [qrng]
        base_url = "https://entropy.example.net"
        transport = "mtls"
        ca_cert_pem = "certs/ca.pem"
        client_cert_pem = "/abs/client.crt"
        client_key_pem = "certs/client.key"
        auth = "x-api-key"
        auth_secret_env = "QRNG_API_KEY"
        entropy_type = "raw"
        request_timeout_ms = 2500
        "#,
    )
    .expect("valid mTLS configuration");

    assert_eq!(
        config,
        EntropyConfig::Qrng(QrngSettings {
            base_url: "https://entropy.example.net".into(),
            transport: QrngTransport::MutualTls {
                ca_cert_pem: "/etc/agent-trust/certs/ca.pem".into(),
                client_cert_pem: "/abs/client.crt".into(),
                client_key_pem: "/etc/agent-trust/certs/client.key".into(),
            },
            auth: QrngAuth::XApiKey {
                secret_env: "QRNG_API_KEY".into()
            },
            entropy_type: Some("raw".into()),
            request_timeout: Duration::from_millis(2500),
        })
    );
}

#[test]
fn invalid_configurations_are_rejected() {
    let cases = [
        // A literal secret field must not be accepted in the file.
        r#"source = "qrng"
           [qrng]
           base_url = "http://127.0.0.1:8002"
           transport = "plain-http"
           token = "s3cret""#,
        r#"source = "qrng""#,
        r#"source = "dev-null""#,
        r#"source = "qrng"
           [qrng]
           base_url = "https://entropy.example.net"
           transport = "plain-http""#,
        r#"source = "qrng"
           [qrng]
           base_url = "https://entropy.example.net"
           transport = "mtls"
           ca_cert_pem = "ca.pem""#,
        r#"source = "qrng"
           [qrng]
           base_url = "http://127.0.0.1:8002"
           transport = "plain-http"
           auth = "bearer""#,
        r#"source = "qrng"
           [qrng]
           base_url = "http://127.0.0.1:8002"
           transport = "plain-http"
           request_timeout_ms = 0"#,
        "source = ",
    ];
    for case in cases {
        assert!(parse(case).is_err(), "must reject:\n{case}");
    }
}

#[test]
fn environment_selects_the_source() {
    assert_eq!(
        EntropyConfig::from_env_with(env(&[])).expect("no variables"),
        EntropyConfig::Os
    );

    let by_url =
        EntropyConfig::from_env_with(env(&[("AGENT_TRUST_QRNG_BASE_URL", "http://127.0.0.1:9")]))
            .expect("base URL variable");
    let EntropyConfig::Qrng(settings) = by_url else {
        panic!("base URL variable must select QRNG");
    };
    assert_eq!(settings.base_url, "http://127.0.0.1:9");
    assert_eq!(settings.transport, QrngTransport::PlainHttp);

    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("entropy.toml");
    std::fs::write(
        &path,
        "source = \"qrng\"\n[qrng]\nbase_url = \"http://127.0.0.1:7\"\ntransport = \"plain-http\"\n",
    )
    .expect("write config");
    let by_file = EntropyConfig::from_env_with(env(&[(
        "AGENT_TRUST_ENTROPY_CONFIG",
        path.to_str().expect("utf-8 path"),
    )]))
    .expect("config file variable");
    assert_eq!(by_file.label(), "qrng");

    assert!(
        EntropyConfig::from_env_with(env(&[
            (
                "AGENT_TRUST_ENTROPY_CONFIG",
                path.to_str().expect("utf-8 path")
            ),
            ("AGENT_TRUST_QRNG_BASE_URL", "http://127.0.0.1:9"),
        ]))
        .is_err(),
        "ambiguous environment must be rejected"
    );
    assert!(
        EntropyConfig::from_env_with(env(&[(
            "AGENT_TRUST_ENTROPY_CONFIG",
            "/nonexistent/x.toml"
        )]))
        .is_err(),
        "a missing config file must not fall back to the OS source"
    );
}

#[test]
fn configured_fake_qrng_drives_the_laboratory_and_receives_the_env_secret() {
    let qrng = FakeQrng::start();
    let config = parse(&format!(
        "source = \"qrng\"\n[qrng]\nbase_url = \"{}\"\ntransport = \"plain-http\"\n\
         auth = \"bearer\"\nauth_secret_env = \"LAB_QRNG_TOKEN\"\n",
        qrng.base_url()
    ))
    .expect("valid configuration");

    assert!(
        config.connect_with(env(&[])).is_err(),
        "an unset secret variable must fail closed"
    );

    let source = config
        .connect_with(env(&[("LAB_QRNG_TOKEN", "s3cret")]))
        .expect("connect with secret");
    assert!(matches!(source, EntropySource::Qrng(_)));
    let mut lab = MlsLab::with_entropy(source).expect("configured lab");
    lab.add_member("bob").expect("bob joins");
    assert!(qrng.entropy_posts() > 0);
    let headers = qrng.authorization_headers();
    assert!(!headers.is_empty());
    assert!(headers
        .iter()
        .all(|header| header.as_deref() == Some("Bearer s3cret")));

    assert!(matches!(
        EntropyConfig::Os.connect_with(env(&[])).expect("OS source"),
        EntropySource::Os
    ));
}
