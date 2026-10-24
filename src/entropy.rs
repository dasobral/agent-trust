//! Lab entropy selection (`docs/adapter-contract.md` C-40, §8.1).
//!
//! The lab draws every provider rand and every identity key from one source, selected at
//! startup by a TOML file or by environment variables:
//!
//! - `os` (the default): the OS-seeded RustCrypto rand;
//! - `mock`: openmls-qrand `MockEntropy`, a seeded in-process stream that is **NOT
//!   random**, for development and tests;
//! - `qrng`: a QRNG Open API endpoint through openmls-qrand `QrngClient`.
//!
//! ```toml
//! source = "mock"            # "os" | "mock" | "qrng"
//! [mock]
//! seed = 42                  # optional, default 0
//! [qrng]
//! base_url = "http://127.0.0.1:8002"
//! transport = "plain-http"   # "plain-http" | "tls" | "mtls"
//! # ca_cert_pem / client_cert_pem / client_key_pem: paths relative to this file
//! auth = "none"              # "none" | "bearer" | "x-api-key"
//! # auth_secret_env = "QRNG_API_KEY"   (the secret is read from this variable)
//! # entropy_type = "raw"
//! request_timeout_ms = 5000
//! ```
//!
//! Without a file, `AGENT_TRUST_ENTROPY_SOURCE` selects the source. `mock` reads
//! `AGENT_TRUST_MOCK_SEED`; `qrng` reads the `AGENT_TRUST_QRNG_*` variables of the live
//! gate in `tests/adapter_entropy.rs`. The file never holds a secret: unknown fields are
//! rejected, and an API secret is read at connect time from a named variable.
//!
//! Every error fails closed: nothing falls back to another source. No error names the
//! endpoint, because evidence files record lab output.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use openmls_qrand::{
    ApiAuth, EntropyBackend, MockEntropy, QrngClient, QrngConfig, QrngError, QrngRand,
    TransportMode,
};
use openmls_rust_crypto::{MemoryStorage, RandError, RustCrypto};
use openmls_traits::random::OpenMlsRand;
use openmls_traits::OpenMlsProvider;
use serde::Deserialize;
use serde_json::{json, Value};

/// Path of an entropy configuration file.
pub const CONFIG_ENV: &str = "AGENT_TRUST_ENTROPY_CONFIG";
/// `os`, `mock` or `qrng`, when no file is given.
pub const SOURCE_ENV: &str = "AGENT_TRUST_ENTROPY_SOURCE";
/// The `MockEntropy` seed (u64) for `AGENT_TRUST_ENTROPY_SOURCE=mock`.
pub const MOCK_SEED_ENV: &str = "AGENT_TRUST_MOCK_SEED";
const QRNG_BASE_URL_ENV: &str = "AGENT_TRUST_QRNG_BASE_URL";
const QRNG_CA_PEM_ENV: &str = "AGENT_TRUST_QRNG_CA_PEM";
const QRNG_CLIENT_CERT_PEM_ENV: &str = "AGENT_TRUST_QRNG_CLIENT_CERT_PEM";
const QRNG_CLIENT_KEY_PEM_ENV: &str = "AGENT_TRUST_QRNG_CLIENT_KEY_PEM";
const QRNG_BEARER_TOKEN_ENV: &str = "AGENT_TRUST_QRNG_BEARER_TOKEN";
const QRNG_API_KEY_ENV: &str = "AGENT_TRUST_QRNG_API_KEY";
const QRNG_ENTROPY_TYPE_ENV: &str = "AGENT_TRUST_QRNG_ENTROPY_TYPE";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntropyConfig {
    Os,
    Mock { seed: u64 },
    Qrng(QrngSettings),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QrngSettings {
    pub base_url: String,
    pub transport: QrngTransport,
    pub auth: QrngAuth,
    pub entropy_type: Option<String>,
    pub request_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrngTransport {
    PlainHttp,
    Tls {
        ca_cert_pem: Option<PathBuf>,
    },
    MutualTls {
        ca_cert_pem: PathBuf,
        client_cert_pem: PathBuf,
        client_key_pem: PathBuf,
    },
}

/// API authentication. Only the name of the variable that holds the secret is kept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QrngAuth {
    None,
    Bearer { secret_env: String },
    XApiKey { secret_env: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    source: SourceKind,
    mock: Option<FileMock>,
    qrng: Option<FileQrng>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SourceKind {
    Os,
    Mock,
    Qrng,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileMock {
    #[serde(default)]
    seed: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileQrng {
    base_url: String,
    transport: TransportKind,
    ca_cert_pem: Option<PathBuf>,
    client_cert_pem: Option<PathBuf>,
    client_key_pem: Option<PathBuf>,
    #[serde(default)]
    auth: AuthKind,
    auth_secret_env: Option<String>,
    entropy_type: Option<String>,
    request_timeout_ms: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransportKind {
    PlainHttp,
    Tls,
    Mtls,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum AuthKind {
    #[default]
    None,
    Bearer,
    XApiKey,
}

impl EntropyConfig {
    /// Parses a TOML file body. Relative certificate paths resolve against `base_dir`.
    pub fn parse(text: &str, base_dir: &Path) -> Result<Self, String> {
        // Only the message: toml's rendering quotes the offending line, which can hold
        // the endpoint.
        let file: FileConfig = toml::from_str(text)
            .map_err(|err| format!("invalid entropy config: {}", err.message().trim()))?;
        match file.source {
            SourceKind::Os => Ok(Self::Os),
            SourceKind::Mock => Ok(Self::Mock {
                seed: file.mock.map_or(0, |mock| mock.seed),
            }),
            SourceKind::Qrng => {
                let qrng = file
                    .qrng
                    .ok_or("invalid entropy config: source = \"qrng\" needs a [qrng] section")?;
                let settings = QrngSettings::from_file(qrng, base_dir)?;
                settings.check()?;
                Ok(Self::Qrng(settings))
            }
        }
    }

    /// Reads and parses a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("cannot read the entropy config file: {}", err.kind()))?;
        Self::parse(&text, path.parent().unwrap_or(Path::new(".")))
    }

    /// Selects the source from `AGENT_TRUST_ENTROPY_CONFIG` or `AGENT_TRUST_ENTROPY_SOURCE`
    /// (at most one); with neither, `os`.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        match (lookup(CONFIG_ENV), lookup(SOURCE_ENV)) {
            (Some(_), Some(_)) => Err(format!("set only one of {CONFIG_ENV} and {SOURCE_ENV}")),
            (Some(path), None) => Self::load(Path::new(&path)),
            (None, None) => Ok(Self::Os),
            (None, Some(source)) => match source.as_str() {
                "os" => Ok(Self::Os),
                "mock" => {
                    let seed = match lookup(MOCK_SEED_ENV) {
                        None => 0,
                        Some(seed) => seed
                            .parse()
                            .map_err(|_| format!("{MOCK_SEED_ENV} must be an unsigned integer"))?,
                    };
                    Ok(Self::Mock { seed })
                }
                "qrng" => {
                    let settings = QrngSettings::from_env(&lookup)?;
                    settings.check()?;
                    Ok(Self::Qrng(settings))
                }
                _ => Err(format!("{SOURCE_ENV} must be os, mock or qrng")),
            },
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Mock { .. } => "mock",
            Self::Qrng(_) => "qrng",
        }
    }

    /// Builds the selected source. A QRNG is contacted here (`GET /capabilities`), and an
    /// API secret is read through `lookup`.
    pub fn connect_with(
        &self,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<LabEntropy, String> {
        match self {
            Self::Os => Ok(LabEntropy::os()),
            Self::Mock { seed } => {
                let mock = Arc::new(MockEntropy::new(*seed));
                Ok(LabEntropy {
                    label: "mock",
                    backend: Some(Arc::clone(&mock) as Arc<dyn EntropyBackend>),
                    mock: Some(mock),
                })
            }
            Self::Qrng(settings) => {
                let secret = |name: &String| {
                    lookup(name)
                        .filter(|value| !value.is_empty())
                        .ok_or_else(|| format!("the QRNG secret variable {name} is not set"))
                };
                let auth = match &settings.auth {
                    QrngAuth::None => ApiAuth::None,
                    QrngAuth::Bearer { secret_env } => ApiAuth::Bearer(secret(secret_env)?),
                    QrngAuth::XApiKey { secret_env } => ApiAuth::XApiKey(secret(secret_env)?),
                };
                let client = QrngClient::connect(settings.qrng_config(auth)?)
                    .map_err(|err| format!("QRNG connect failed: {}", qrng_error_category(&err)))?;
                Ok(LabEntropy {
                    label: "qrng",
                    backend: Some(Arc::new(client)),
                    mock: None,
                })
            }
        }
    }

    pub fn connect(&self) -> Result<LabEntropy, String> {
        self.connect_with(|name| std::env::var(name).ok())
    }
}

impl QrngSettings {
    fn from_file(file: FileQrng, base_dir: &Path) -> Result<Self, String> {
        let resolve = |path: PathBuf| {
            if path.is_absolute() {
                path
            } else {
                base_dir.join(path)
            }
        };
        let required = |path: Option<PathBuf>, field: &str| {
            path.map(resolve).ok_or_else(|| {
                format!("invalid entropy config: transport = \"mtls\" needs {field}")
            })
        };
        let transport = match file.transport {
            TransportKind::PlainHttp => {
                if file.ca_cert_pem.is_some()
                    || file.client_cert_pem.is_some()
                    || file.client_key_pem.is_some()
                {
                    return Err("invalid entropy config: plain-http takes no certificate".into());
                }
                QrngTransport::PlainHttp
            }
            TransportKind::Tls => {
                if file.client_cert_pem.is_some() || file.client_key_pem.is_some() {
                    return Err(
                        "invalid entropy config: a client certificate needs transport = \"mtls\""
                            .into(),
                    );
                }
                QrngTransport::Tls {
                    ca_cert_pem: file.ca_cert_pem.map(resolve),
                }
            }
            TransportKind::Mtls => QrngTransport::MutualTls {
                ca_cert_pem: required(file.ca_cert_pem, "ca_cert_pem")?,
                client_cert_pem: required(file.client_cert_pem, "client_cert_pem")?,
                client_key_pem: required(file.client_key_pem, "client_key_pem")?,
            },
        };
        let auth = match (file.auth, file.auth_secret_env) {
            (AuthKind::None, None) => QrngAuth::None,
            (AuthKind::Bearer, Some(secret_env)) => QrngAuth::Bearer { secret_env },
            (AuthKind::XApiKey, Some(secret_env)) => QrngAuth::XApiKey { secret_env },
            (AuthKind::None, Some(_)) => {
                return Err("invalid entropy config: auth_secret_env needs an auth kind".into())
            }
            (_, None) => {
                return Err(
                    "invalid entropy config: API authentication needs auth_secret_env".into(),
                )
            }
        };
        let request_timeout = match file.request_timeout_ms {
            None => DEFAULT_TIMEOUT,
            Some(0) => return Err("invalid entropy config: request_timeout_ms must be > 0".into()),
            Some(ms) => Duration::from_millis(ms),
        };
        Ok(Self {
            base_url: file.base_url,
            transport,
            auth,
            entropy_type: file.entropy_type,
            request_timeout,
        })
    }

    /// The live-gate variables: TLS when the URL is `https://` (mTLS with all three
    /// paths), plain HTTP otherwise; at most one of bearer token and API key.
    fn from_env(lookup: &impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let var = |name: &str| lookup(name).filter(|value| !value.is_empty());
        let base_url = var(QRNG_BASE_URL_ENV)
            .ok_or_else(|| format!("{SOURCE_ENV}=qrng needs {QRNG_BASE_URL_ENV}"))?;
        let ca = var(QRNG_CA_PEM_ENV).map(PathBuf::from);
        let cert = var(QRNG_CLIENT_CERT_PEM_ENV).map(PathBuf::from);
        let key = var(QRNG_CLIENT_KEY_PEM_ENV).map(PathBuf::from);
        let transport = if base_url.starts_with("https://") {
            match (ca, cert, key) {
                (Some(ca_cert_pem), Some(client_cert_pem), Some(client_key_pem)) => {
                    QrngTransport::MutualTls {
                        ca_cert_pem,
                        client_cert_pem,
                        client_key_pem,
                    }
                }
                (ca_cert_pem, None, None) => QrngTransport::Tls { ca_cert_pem },
                _ => return Err("QRNG mTLS needs the CA, client certificate and client key".into()),
            }
        } else if ca.is_some() || cert.is_some() || key.is_some() {
            return Err("QRNG certificates need an https:// base URL".into());
        } else {
            QrngTransport::PlainHttp
        };
        let auth = match (var(QRNG_BEARER_TOKEN_ENV), var(QRNG_API_KEY_ENV)) {
            (None, None) => QrngAuth::None,
            (Some(_), None) => QrngAuth::Bearer {
                secret_env: QRNG_BEARER_TOKEN_ENV.into(),
            },
            (None, Some(_)) => QrngAuth::XApiKey {
                secret_env: QRNG_API_KEY_ENV.into(),
            },
            (Some(_), Some(_)) => {
                return Err(format!(
                    "set at most one of {QRNG_BEARER_TOKEN_ENV} and {QRNG_API_KEY_ENV}"
                ))
            }
        };
        Ok(Self {
            base_url,
            transport,
            auth,
            entropy_type: var(QRNG_ENTROPY_TYPE_ENV),
            request_timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Static checks. TLS material is read only at connect time.
    fn check(&self) -> Result<(), String> {
        let url = url::Url::parse(&self.base_url)
            .map_err(|err| format!("invalid QRNG base URL: {err}"))?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err("the QRNG base URL must not have a query or fragment".into());
        }
        let expected = match self.transport {
            QrngTransport::PlainHttp => "http",
            QrngTransport::Tls { .. } | QrngTransport::MutualTls { .. } => "https",
        };
        if url.scheme() != expected {
            return Err(format!(
                "this QRNG transport needs a {expected}:// base URL"
            ));
        }
        Ok(())
    }

    fn qrng_config(&self, auth: ApiAuth) -> Result<QrngConfig, String> {
        self.check()?;
        let transport = match &self.transport {
            QrngTransport::PlainHttp => TransportMode::PlainHttp,
            QrngTransport::Tls { ca_cert_pem } => TransportMode::Tls {
                ca_cert_pem: ca_cert_pem.clone(),
            },
            QrngTransport::MutualTls {
                ca_cert_pem,
                client_cert_pem,
                client_key_pem,
            } => TransportMode::MutualTls {
                ca_cert_pem: ca_cert_pem.clone(),
                client_cert_pem: client_cert_pem.clone(),
                client_key_pem: client_key_pem.clone(),
            },
        };
        Ok(QrngConfig {
            base_url: self
                .base_url
                .parse()
                .map_err(|_| "invalid QRNG base URL".to_string())?,
            transport,
            auth,
            entropy_type: self.entropy_type.clone(),
            request_timeout: self.request_timeout,
            health_poll_interval: None,
        })
    }
}

/// The variant of a QRNG error, without its payload: payloads can carry the endpoint URL
/// or a file path.
fn qrng_error_category(err: &QrngError) -> &'static str {
    match err {
        QrngError::InvalidConfig(_) => "invalid configuration",
        QrngError::TlsMaterial(_) => "TLS material",
        QrngError::Transport(_) => "transport",
        QrngError::InvalidRequest => "invalid request",
        QrngError::EntropyUnavailable => "entropy unavailable",
        QrngError::HealthUnavailable => "health unavailable",
        QrngError::HttpStatus(_) => "HTTP status",
        QrngError::Protocol(_) => "protocol",
        QrngError::Base64(_) => "base64",
        QrngError::UnsupportedEntropyType => "unsupported entropy type",
        QrngError::HealthUnsupported => "health unsupported",
    }
}

/// The selected source. Clones share one backend, so one stream feeds the whole lab.
#[derive(Clone)]
pub struct LabEntropy {
    label: &'static str,
    /// `None` for `os`.
    backend: Option<Arc<dyn EntropyBackend>>,
    /// The same backend as `backend` when the source is `mock`, for the outage control.
    mock: Option<Arc<MockEntropy>>,
}

impl LabEntropy {
    /// The default source: the OS-seeded RustCrypto rand.
    pub fn os() -> Self {
        Self {
            label: "os",
            backend: None,
            mock: None,
        }
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    /// A rand over the selected source.
    pub fn rand(&self) -> LabRand {
        match &self.backend {
            None => LabRand::Os(Box::default()),
            Some(backend) => LabRand::Backend(QrngRand::new(Arc::clone(backend))),
        }
    }

    /// A new provider: RustCrypto crypto, memory storage and a rand over the selected
    /// source.
    pub fn provider(&self) -> LabProvider {
        LabProvider {
            crypto: RustCrypto::default(),
            storage: MemoryStorage::default(),
            rand: self.rand(),
        }
    }

    /// `{source}` for `os`; `{source, requests, bytes, failures}` otherwise.
    pub fn report(&self) -> Value {
        match &self.backend {
            None => json!({ "source": self.label }),
            Some(backend) => {
                let metrics = backend.metrics_snapshot();
                json!({
                    "source": self.label,
                    "requests": metrics.entropy_requests_total,
                    "bytes": metrics.entropy_bytes_total,
                    "failures": metrics.entropy_failures_total,
                })
            }
        }
    }

    /// Simulates a mock outage or its end. Only the `mock` source has this control.
    pub fn set_available(&self, available: bool) -> Result<(), String> {
        let mock = self
            .mock
            .as_ref()
            .ok_or("unsupported: entropy_outage needs the mock entropy source")?;
        mock.set_available(available);
        Ok(())
    }
}

/// The lab's `OpenMlsRand`: the OS-seeded RustCrypto rand or the selected backend.
pub enum LabRand {
    /// Boxed: RustCrypto holds its RNG state inline.
    Os(Box<RustCrypto>),
    Backend(QrngRand<dyn EntropyBackend>),
}

/// A rand failure. A backend failure keeps only its category (see `qrng_error_category`).
#[derive(Debug)]
pub enum LabRandError {
    Os(RandError),
    Backend(&'static str),
}

impl std::fmt::Display for LabRandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Os(err) => write!(f, "OS rand failed: {err}"),
            Self::Backend(category) => write!(f, "entropy backend failed: {category}"),
        }
    }
}

impl std::error::Error for LabRandError {}

impl OpenMlsRand for LabRand {
    type Error = LabRandError;

    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        match self {
            Self::Os(rand) => rand.random_array().map_err(LabRandError::Os),
            Self::Backend(rand) => rand
                .random_array()
                .map_err(|err| LabRandError::Backend(qrng_error_category(&err))),
        }
    }

    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::Os(rand) => rand.random_vec(len).map_err(LabRandError::Os),
            Self::Backend(rand) => rand
                .random_vec(len)
                .map_err(|err| LabRandError::Backend(qrng_error_category(&err))),
        }
    }
}

/// The lab's provider: RustCrypto crypto, memory storage and a [`LabRand`].
pub struct LabProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
    rand: LabRand,
}

impl OpenMlsProvider for LabProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = LabRand;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.rand
    }
}
