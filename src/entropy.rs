//! Entropy-source configuration for the MLS laboratory.
//!
//! The source is selected by a TOML file or by environment variables, so the
//! same build can move from the OS source to a development fake QRNG server or a
//! real Entropy Core endpoint without code changes:
//!
//! ```toml
//! source = "qrng"            # "os" | "qrng"
//! [qrng]
//! base_url = "http://127.0.0.1:8002"
//! transport = "plain-http"   # "plain-http" | "tls" | "mtls"
//! # ca_cert_pem / client_cert_pem / client_key_pem: paths relative to this file
//! auth = "none"              # "none" | "bearer" | "x-api-key"
//! # auth_secret_env = "QRNG_API_KEY"  (secret is read from this variable)
//! # entropy_type = "raw"
//! request_timeout_ms = 5000
//! ```
//!
//! Secrets are never stored in the file: unknown fields are rejected and the
//! credential is read at connect time from the named environment variable.
//! Every error is fail-closed; nothing falls back to the OS source.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use openmls_qrand::{ApiAuth, QrngClient, QrngConfig, TransportMode};
use serde::Deserialize;

use crate::mls::EntropySource;

/// Path of an entropy configuration file.
pub const CONFIG_ENV: &str = "AGENT_TRUST_ENTROPY_CONFIG";
/// Shorthand: a QRNG base URL with default settings (`http://` = plain HTTP,
/// `https://` = TLS with webpki roots, no API authentication).
pub const BASE_URL_ENV: &str = "AGENT_TRUST_QRNG_BASE_URL";

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntropyConfig {
    Os,
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

/// API authentication. Only the name of the environment variable holding the
/// secret is configured.
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
    qrng: Option<FileQrng>,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SourceKind {
    Os,
    Qrng,
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
    /// Parses TOML; relative certificate paths resolve against `base_dir`.
    pub fn parse(text: &str, base_dir: &Path) -> Result<Self, String> {
        let file: FileConfig =
            toml::from_str(text).map_err(|e| format!("invalid entropy config: {e}"))?;
        match file.source {
            SourceKind::Os => Ok(Self::Os),
            SourceKind::Qrng => {
                let qrng = file
                    .qrng
                    .ok_or("source = \"qrng\" requires a [qrng] section")?;
                let settings = QrngSettings::from_file(qrng, base_dir)?;
                settings.check_url()?;
                Ok(Self::Qrng(settings))
            }
        }
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read entropy config {}: {e}", path.display()))?;
        let base_dir = path.parent().unwrap_or(Path::new("."));
        Self::parse(&text, base_dir)
    }

    /// Selects the source from `AGENT_TRUST_ENTROPY_CONFIG` (a file path) or
    /// `AGENT_TRUST_QRNG_BASE_URL`; with neither set, the OS source.
    pub fn from_env_with(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        match (lookup(CONFIG_ENV), lookup(BASE_URL_ENV)) {
            (Some(_), Some(_)) => Err(format!("set only one of {CONFIG_ENV} and {BASE_URL_ENV}")),
            (Some(path), None) => Self::load(Path::new(&path)),
            (None, Some(base_url)) => {
                let transport = if base_url.starts_with("https://") {
                    QrngTransport::Tls { ca_cert_pem: None }
                } else {
                    QrngTransport::PlainHttp
                };
                let settings = QrngSettings {
                    base_url,
                    transport,
                    auth: QrngAuth::None,
                    entropy_type: None,
                    request_timeout: DEFAULT_TIMEOUT,
                };
                settings.check_url()?;
                Ok(Self::Qrng(settings))
            }
            (None, None) => Ok(Self::Os),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Os => "os",
            Self::Qrng(_) => "qrng",
        }
    }

    /// Connects to the configured source, reading any API secret via `lookup`.
    pub fn connect_with(
        &self,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<EntropySource, String> {
        let settings = match self {
            Self::Os => return Ok(EntropySource::Os),
            Self::Qrng(settings) => settings,
        };
        let secret = |name: &String| {
            lookup(name)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| format!("QRNG secret variable {name} is not set"))
        };
        let auth = match &settings.auth {
            QrngAuth::None => ApiAuth::None,
            QrngAuth::Bearer { secret_env } => ApiAuth::Bearer(secret(secret_env)?),
            QrngAuth::XApiKey { secret_env } => ApiAuth::XApiKey(secret(secret_env)?),
        };
        let client = QrngClient::connect(settings.qrng_config(auth)?)
            .map_err(|e| format!("QRNG connect failed: {e}"))?;
        Ok(EntropySource::Qrng(Arc::new(client)))
    }

    pub fn connect(&self) -> Result<EntropySource, String> {
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
            path.map(resolve)
                .ok_or_else(|| format!("transport = \"mtls\" requires {field}"))
        };
        let transport = match file.transport {
            TransportKind::PlainHttp => {
                if file.ca_cert_pem.is_some()
                    || file.client_cert_pem.is_some()
                    || file.client_key_pem.is_some()
                {
                    return Err("plain-http transport takes no certificate paths".into());
                }
                QrngTransport::PlainHttp
            }
            TransportKind::Tls => {
                if file.client_cert_pem.is_some() || file.client_key_pem.is_some() {
                    return Err("client certificates require transport = \"mtls\"".into());
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
            (AuthKind::None, Some(_)) => {
                return Err("auth_secret_env requires auth = \"bearer\" or \"x-api-key\"".into())
            }
            (AuthKind::Bearer, Some(secret_env)) => QrngAuth::Bearer { secret_env },
            (AuthKind::XApiKey, Some(secret_env)) => QrngAuth::XApiKey { secret_env },
            (_, None) => return Err("API authentication requires auth_secret_env".into()),
        };
        let request_timeout = match file.request_timeout_ms {
            None => DEFAULT_TIMEOUT,
            Some(0) => return Err("request_timeout_ms must be greater than zero".into()),
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

    /// Static URL/transport checks; TLS material is read only at connect time.
    fn check_url(&self) -> Result<(), String> {
        let url: url::Url = self
            .base_url
            .parse()
            .map_err(|e| format!("invalid QRNG base_url: {e}"))?;
        if url.query().is_some() || url.fragment().is_some() {
            return Err("QRNG base_url must not contain a query or fragment".into());
        }
        let expected = match self.transport {
            QrngTransport::PlainHttp => "http",
            QrngTransport::Tls { .. } | QrngTransport::MutualTls { .. } => "https",
        };
        if url.scheme() != expected {
            return Err(format!("this transport requires a {expected}:// base_url"));
        }
        Ok(())
    }

    fn qrng_config(&self, auth: ApiAuth) -> Result<QrngConfig, String> {
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
        let config = QrngConfig {
            base_url: self
                .base_url
                .parse()
                .map_err(|e| format!("invalid QRNG base_url: {e}"))?,
            transport,
            auth,
            entropy_type: self.entropy_type.clone(),
            request_timeout: self.request_timeout,
            health_poll_interval: None,
        };
        config
            .validate()
            .map_err(|e| format!("invalid QRNG config: {e}"))?;
        Ok(config)
    }
}
