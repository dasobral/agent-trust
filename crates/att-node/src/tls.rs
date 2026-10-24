//! Mutual TLS between services, and the testbed PKI.
//!
//! With `ATT_TLS_DIR` and `ATT_TLS_NAME` set, a service listens with TLS, requires a
//! client certificate issued by the deployment CA, and presents its own certificate
//! when it calls another service. The peer's certificate common name is its service
//! name, and services use it to bind transport identity to protocol identity (for
//! example: only `bob` may fetch bob's mailbox, and the APF accepts a request signed
//! by `bob` only over a connection from `bob`).
//!
//! Files in `ATT_TLS_DIR`: `ca.crt`, `<name>.crt`, `<name>.key` (PEM). `att-node pki`
//! creates them. Transport keys come from the OS RNG (rcgen over ring): they are not
//! inside the entropy seam of agent-trust, which covers MLS and identity keys only.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};

use crate::config;

pub struct Tls {
    pub server: Arc<ServerConfig>,
    pub client: Arc<ClientConfig>,
}

static TLS: OnceLock<Option<Tls>> = OnceLock::new();

/// The process TLS configuration, loaded once from the environment.
pub fn get() -> &'static Option<Tls> {
    TLS.get_or_init(|| match load() {
        Ok(tls) => tls,
        Err(error) => {
            eprintln!("att-node: TLS configuration: {error}");
            std::process::exit(1)
        }
    })
}

pub fn enabled() -> bool {
    get().is_some()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn load() -> Result<Option<Tls>, String> {
    let (Some(dir), Some(name)) = (
        config::optional("ATT_TLS_DIR"),
        config::optional("ATT_TLS_NAME"),
    ) else {
        return Ok(None);
    };
    let dir = Path::new(&dir);
    let ca = certs(&dir.join("ca.crt"))?;
    let chain = certs(&dir.join(format!("{name}.crt")))?;
    let key = PrivateKeyDer::from_pem_file(dir.join(format!("{name}.key")))
        .map_err(|err| format!("{name}.key: {err}"))?;
    let mut roots = RootCertStore::empty();
    for cert in ca {
        roots.add(cert).map_err(|err| format!("ca.crt: {err}"))?;
    }
    let roots = Arc::new(roots);
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::clone(&roots), provider())
        .build()
        .map_err(|err| format!("client verifier: {err}"))?;
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain.clone(), key.clone_key())
        .map_err(|err| format!("server certificate: {err}"))?;
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|err| err.to_string())?
        .with_root_certificates((*roots).clone())
        .with_client_auth_cert(chain, key)
        .map_err(|err| format!("client certificate: {err}"))?;
    Ok(Some(Tls {
        server: Arc::new(server),
        client: Arc::new(client),
    }))
}

fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(|err| format!("{}: {err}", path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("{}: {err}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{}: no certificate", path.display()));
    }
    Ok(certs)
}

/// The common name of a verified peer certificate.
pub fn common_name(cert: &CertificateDer<'_>) -> Option<String> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let name = parsed
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_owned();
    Some(name)
}

/// `att-node pki --dir DIR --names a,b,... [--namespace NS]`: a CA and one certificate
/// per name (server and client usage), plus `attctl` for the control plane. Each
/// certificate names the service, `localhost`, `127.0.0.1`, and the Kubernetes service
/// names in `NS`.
pub fn run_pki(args: &[String]) -> Result<(), String> {
    let mut dir = None;
    let mut names = Vec::new();
    let mut namespace = None;
    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--dir" => dir = Some(value.clone()),
            "--names" => names = value.split(',').map(str::to_owned).collect(),
            "--namespace" => namespace = Some(value.clone()),
            _ => return Err(format!("unknown pki flag {flag}")),
        }
    }
    let dir = dir.ok_or("pki needs --dir")?;
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    if !names.iter().any(|n| n == "attctl") {
        names.push("attctl".into());
    }

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };
    let ca_key = KeyPair::generate().map_err(|err| err.to_string())?;
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).map_err(|err| err.to_string())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "agent-trust-testbed CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params
        .self_signed(&ca_key)
        .map_err(|err| err.to_string())?;
    write_file(&dir.join("ca.crt"), ca.pem().as_bytes(), 0o644)?;
    write_file(
        &dir.join("ca.key"),
        ca_key.serialize_pem().as_bytes(),
        0o600,
    )?;

    for name in &names {
        let mut sans = vec![name.clone(), "localhost".into(), "127.0.0.1".into()];
        if let Some(ns) = &namespace {
            for suffix in ["", ".svc", ".svc.cluster.local"] {
                sans.push(format!("{name}.{ns}{suffix}"));
            }
        }
        let mut params = CertificateParams::new(sans).map_err(|err| err.to_string())?;
        params
            .distinguished_name
            .push(DnType::CommonName, name.as_str());
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // Strict verifiers (Python 3.13 and later) require the Authority Key Identifier.
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().map_err(|err| err.to_string())?;
        let cert = params
            .signed_by(&key, &ca, &ca_key)
            .map_err(|err| err.to_string())?;
        write_file(
            &dir.join(format!("{name}.crt")),
            cert.pem().as_bytes(),
            0o644,
        )?;
        write_file(
            &dir.join(format!("{name}.key")),
            key.serialize_pem().as_bytes(),
            0o600,
        )?;
    }
    println!("{}", names.join(","));
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|err| format!("{}: {err}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}
