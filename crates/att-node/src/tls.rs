//! Mutual TLS between services, and the testbed PKI, post quantum (finding F-9, PQ-2 and
//! PQ-4).
//!
//! With `ATT_TLS_DIR` and `ATT_TLS_NAME` set, a service listens with TLS 1.3, requires a
//! client certificate, and presents its own certificate when it calls another service.
//!
//! Two certificate authorities:
//!
//! - the **post quantum CA** (ML-DSA-44) issues every identity's main certificate. A
//!   service calls another service only with it, only trusts it, and only offers the
//!   hybrid key exchange `X25519MLKEM768`;
//! - the **classical CA** (ECDSA P-256) exists for clients that cannot do post quantum
//!   TLS yet, such as the control plane on an OpenSSL older than 3.5. A server presents
//!   its classical certificate only to a client that offers no ML-DSA signature scheme,
//!   and accepts a classical client certificate only for the names `attctl` and
//!   `<agent>-app`. A classical certificate that names a service is refused.
//!
//! A peer with a post quantum certificate is accepted only over `X25519MLKEM768`. The
//! peer's certificate common name is its identity; services bind it to protocol identity
//! (for example: only `bob` may fetch bob's mailbox).
//!
//! Files in `ATT_TLS_DIR`: `ca.crt`, `<name>.crt`, `<name>.key` (post quantum) and
//! `classical-ca.crt`, `<name>.classical.crt`, `<name>.classical.key` (classical), PEM.
//! `att-node pki` creates them. Transport keys come from the OS RNG (rcgen over
//! aws-lc-rs): they are not inside the entropy seam of agent-trust, which covers MLS and
//! identity keys only.

use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, NamedGroup, RootCertStore, ServerConfig, SignatureScheme};

use crate::config;

/// The hybrid post quantum key exchange group.
pub const HYBRID_GROUP: NamedGroup = NamedGroup::X25519MLKEM768;
/// OID of ML-DSA-44 (FIPS 204), the post quantum CA's signature algorithm.
const ML_DSA_44_OID: &str = "2.16.840.1.101.3.4.3.17";

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

/// aws-lc-rs with exactly these key exchange groups.
fn provider(groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>) -> Arc<CryptoProvider> {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = groups;
    Arc::new(provider)
}

/// Servers: the hybrid group first, X25519 for classical clients (the control plane).
fn server_provider() -> Arc<CryptoProvider> {
    provider(vec![kx_group::X25519MLKEM768, kx_group::X25519])
}

/// Service clients: the hybrid group only. No downgrade path exists between services.
fn client_provider() -> Arc<CryptoProvider> {
    provider(vec![kx_group::X25519MLKEM768])
}

fn load() -> Result<Option<Tls>, String> {
    let (Some(dir), Some(name)) = (
        config::optional("ATT_TLS_DIR"),
        config::optional("ATT_TLS_NAME"),
    ) else {
        return Ok(None);
    };
    let dir = Path::new(&dir);
    let pq_roots = roots(&dir.join("ca.crt"))?;
    let classical_roots = roots(&dir.join("classical-ca.crt"))?;
    let pq = certified_key(dir, &name)?;
    let classical = certified_key(dir, &format!("{name}.classical"))?;

    // Clients of either CA may connect; `peer_identity` decides what each may claim.
    let mut client_roots = (*pq_roots).clone();
    client_roots
        .roots
        .extend(classical_roots.roots.iter().cloned());
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_roots), server_provider())
            .build()
            .map_err(|err| format!("client verifier: {err}"))?;
    let server = ServerConfig::builder_with_provider(server_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(ByClientSchemes {
            pq: pq.clone(),
            classical,
        }));

    let client = ClientConfig::builder_with_provider(client_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?
        .with_root_certificates(pq_roots)
        .with_client_auth_cert(pq.cert.clone(), private_key(dir, &name)?)
        .map_err(|err| format!("client certificate: {err}"))?;
    Ok(Some(Tls {
        server: Arc::new(server),
        client: Arc::new(client),
    }))
}

/// The client of a transport probe (`att-node probe --tls-dir`): trusts the post
/// quantum CA, presents `name`'s post quantum certificate (no certificate without a
/// name), and offers the hybrid group, or only X25519 with `classical_kx`.
pub fn probe_client(
    dir: &Path,
    name: Option<&str>,
    classical_kx: bool,
) -> Result<ClientConfig, String> {
    let groups = if classical_kx {
        provider(vec![kx_group::X25519])
    } else {
        client_provider()
    };
    let builder = ClientConfig::builder_with_provider(groups)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|err| err.to_string())?
        .with_root_certificates(roots(&dir.join("ca.crt"))?);
    match name {
        None => Ok(builder.with_no_client_auth()),
        Some(name) => {
            let chain = certs(&dir.join(format!("{name}.crt")))?;
            builder
                .with_client_auth_cert(chain, private_key(dir, name)?)
                .map_err(|err| format!("client certificate: {err}"))
        }
    }
}

/// Presents the post quantum certificate to a client that offers ML-DSA-44, and the
/// classical certificate to any other client.
#[derive(Debug)]
struct ByClientSchemes {
    pq: Arc<CertifiedKey>,
    classical: Arc<CertifiedKey>,
}

impl ResolvesServerCert for ByClientSchemes {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if hello
            .signature_schemes()
            .contains(&SignatureScheme::ML_DSA_44)
        {
            Some(Arc::clone(&self.pq))
        } else {
            Some(Arc::clone(&self.classical))
        }
    }
}

fn roots(path: &Path) -> Result<Arc<RootCertStore>, String> {
    let mut store = RootCertStore::empty();
    for cert in certs(path)? {
        store
            .add(cert)
            .map_err(|err| format!("{}: {err}", path.display()))?;
    }
    Ok(Arc::new(store))
}

fn certified_key(dir: &Path, stem: &str) -> Result<Arc<CertifiedKey>, String> {
    let chain = certs(&dir.join(format!("{stem}.crt")))?;
    let key = aws_lc_rs::sign::any_supported_type(&private_key(dir, stem)?)
        .map_err(|err| format!("{stem}.key: {err}"))?;
    let certified = CertifiedKey::new(chain, key);
    certified
        .keys_match()
        .map_err(|err| format!("{stem}: {err}"))?;
    Ok(Arc::new(certified))
}

fn private_key(dir: &Path, stem: &str) -> Result<PrivateKeyDer<'static>, String> {
    PrivateKeyDer::from_pem_file(dir.join(format!("{stem}.key")))
        .map_err(|err| format!("{stem}.key: {err}"))
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

/// What the handshake established about a verified peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerCertificate {
    /// The certificate's common name.
    pub name: String,
    /// Issued by the post quantum CA (signed with ML-DSA-44).
    pub post_quantum: bool,
}

/// The common name and CA kind of a verified peer certificate.
pub fn peer_certificate(cert: &CertificateDer<'_>) -> Option<PeerCertificate> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert.as_ref()).ok()?;
    let name = parsed
        .subject()
        .iter_common_name()
        .next()?
        .as_str()
        .ok()?
        .to_owned();
    let post_quantum = parsed.signature_algorithm.algorithm.to_id_string() == ML_DSA_44_OID;
    Some(PeerCertificate { name, post_quantum })
}

/// Whether a classical certificate may carry `name`: only the control plane and the
/// application identities, never a service.
pub fn classical_name_allowed(name: &str) -> bool {
    name == "attctl" || name.ends_with("-app")
}

/// The identity a connection may act as, or `None`: a post quantum certificate over the
/// hybrid group, or a classical certificate for an allowed name over any group.
pub fn peer_identity(peer: &PeerCertificate, group: Option<NamedGroup>) -> Option<String> {
    let allowed = if peer.post_quantum {
        group == Some(HYBRID_GROUP)
    } else {
        classical_name_allowed(&peer.name)
    };
    allowed.then(|| peer.name.clone())
}

/// A name for a key exchange group in reports, such as `X25519MLKEM768`.
pub fn group_name(group: Option<NamedGroup>) -> String {
    group.map_or_else(|| "none".into(), |group| format!("{group:?}"))
}

// ---------------------------------------------------------------------------
// PKI
// ---------------------------------------------------------------------------

/// `att-node pki --dir DIR --names a,b,... [--namespace NS]`: the post quantum CA and the
/// classical CA, and for every name (plus `attctl`) one certificate from each (server and
/// client usage). Each certificate names the service, `localhost`, `127.0.0.1`, and the
/// Kubernetes service names in `NS`. The CA keys stay in `DIR` (mode 0600), for
/// `att-node pki-issue`; deployments never copy them into a service.
pub fn run_pki(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args, &["--dir", "--names", "--namespace"])?;
    let dir = flags.required("--dir")?;
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).map_err(|err| err.to_string())?;
    let mut names: Vec<String> = flags
        .get("--names")
        .map(|names| names.split(',').map(str::to_owned).collect())
        .unwrap_or_default();
    if !names.iter().any(|n| n == "attctl") {
        names.push("attctl".into());
    }
    let namespace = flags.get("--namespace");

    let pq = new_ca(&rcgen::PKCS_ML_DSA_44, "agent-trust-testbed CA (ML-DSA-44)")?;
    write_ca(dir, "ca", &pq)?;
    let classical = new_ca(
        &rcgen::PKCS_ECDSA_P256_SHA256,
        "agent-trust-testbed classical CA (ECDSA P-256)",
    )?;
    write_ca(dir, "classical-ca", &classical)?;

    for name in &names {
        let issuer = rcgen::Issuer::from_params(&pq.params, &pq.key);
        issue(
            dir,
            name,
            name,
            namespace.as_deref(),
            &rcgen::PKCS_ML_DSA_44,
            &issuer,
        )?;
        let issuer = rcgen::Issuer::from_params(&classical.params, &classical.key);
        issue(
            dir,
            &format!("{name}.classical"),
            name,
            namespace.as_deref(),
            &rcgen::PKCS_ECDSA_P256_SHA256,
            &issuer,
        )?;
    }
    println!("{}", names.join(","));
    Ok(())
}

/// `att-node pki-issue --dir DIR --name NAME --out OUT [--classical]`: one more
/// certificate with common name NAME from the deployment's post quantum CA (or its
/// classical CA), written to `OUT/<NAME>.crt` and `OUT/<NAME>.key`. For negative
/// controls, such as a classical certificate that claims a service name.
pub fn run_pki_issue(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args, &["--dir", "--name", "--out", "--classical"])?;
    let dir = flags.required("--dir")?;
    let name = flags.required("--name")?;
    let out = flags.required("--out")?;
    let classical = flags.has("--classical");
    let (stem, alg) = if classical {
        ("classical-ca", &rcgen::PKCS_ECDSA_P256_SHA256)
    } else {
        ("ca", &rcgen::PKCS_ML_DSA_44)
    };
    let dir = Path::new(&dir);
    let read = |file: String| {
        std::fs::read_to_string(dir.join(&file)).map_err(|err| format!("{file}: {err}"))
    };
    let ca_key = rcgen::KeyPair::from_pem(&read(format!("{stem}.key"))?)
        .map_err(|err| format!("{stem}.key: {err}"))?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(&read(format!("{stem}.crt"))?, ca_key)
        .map_err(|err| format!("{stem}.crt: {err}"))?;
    let out = Path::new(&out);
    std::fs::create_dir_all(out).map_err(|err| err.to_string())?;
    issue(out, &name, &name, None, alg, &issuer)
}

struct Ca {
    params: rcgen::CertificateParams,
    key: rcgen::KeyPair,
    cert: rcgen::Certificate,
}

fn new_ca(alg: &'static rcgen::SignatureAlgorithm, common_name: &str) -> Result<Ca, String> {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
    let key = KeyPair::generate_for(alg).map_err(|err| err.to_string())?;
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|err| err.to_string())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).map_err(|err| err.to_string())?;
    Ok(Ca { params, key, cert })
}

fn write_ca(dir: &Path, stem: &str, ca: &Ca) -> Result<(), String> {
    write_file(
        &dir.join(format!("{stem}.crt")),
        ca.cert.pem().as_bytes(),
        0o644,
    )?;
    write_file(
        &dir.join(format!("{stem}.key")),
        ca.key.serialize_pem().as_bytes(),
        0o600,
    )
}

/// One leaf certificate `<stem>.crt` and key `<stem>.key` with common name `name`.
fn issue(
    dir: &Path,
    stem: &str,
    name: &str,
    namespace: Option<&str>,
    alg: &'static rcgen::SignatureAlgorithm,
    issuer: &rcgen::Issuer<'_, impl rcgen::SigningKey>,
) -> Result<(), String> {
    use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
    let mut sans = vec![name.to_owned(), "localhost".into(), "127.0.0.1".into()];
    if let Some(ns) = namespace {
        for suffix in ["", ".svc", ".svc.cluster.local"] {
            sans.push(format!("{name}.{ns}{suffix}"));
        }
    }
    let mut params = CertificateParams::new(sans).map_err(|err| err.to_string())?;
    params.distinguished_name.push(DnType::CommonName, name);
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // Strict verifiers (Python 3.13 and later) require the Authority Key Identifier.
    params.use_authority_key_identifier_extension = true;
    let key = KeyPair::generate_for(alg).map_err(|err| err.to_string())?;
    let cert = params
        .signed_by(&key, issuer)
        .map_err(|err| err.to_string())?;
    write_file(
        &dir.join(format!("{stem}.crt")),
        cert.pem().as_bytes(),
        0o644,
    )?;
    write_file(
        &dir.join(format!("{stem}.key")),
        key.serialize_pem().as_bytes(),
        0o600,
    )
}

/// `--flag value` pairs, and bare boolean flags.
struct Flags(Vec<(String, Option<String>)>);

impl Flags {
    fn parse(args: &[String], known: &[&str]) -> Result<Self, String> {
        let mut out = Vec::new();
        let mut iter = args.iter().peekable();
        while let Some(flag) = iter.next() {
            if !known.contains(&flag.as_str()) {
                return Err(format!("unknown flag {flag}"));
            }
            let value = match iter.peek() {
                Some(next) if !next.starts_with("--") => iter.next().cloned(),
                _ => None,
            };
            out.push((flag.clone(), value));
        }
        Ok(Self(out))
    }

    fn get(&self, flag: &str) -> Option<String> {
        self.0
            .iter()
            .find(|(name, _)| name == flag)
            .and_then(|(_, value)| value.clone())
    }

    fn has(&self, flag: &str) -> bool {
        self.0.iter().any(|(name, _)| name == flag)
    }

    fn required(&self, flag: &str) -> Result<String, String> {
        self.get(flag)
            .ok_or_else(|| format!("{flag} needs a value"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(name: &str, post_quantum: bool) -> PeerCertificate {
        PeerCertificate {
            name: name.into(),
            post_quantum,
        }
    }

    #[test]
    fn post_quantum_certificates_need_the_hybrid_group() {
        let bob = peer("bob", true);
        assert_eq!(peer_identity(&bob, Some(HYBRID_GROUP)), Some("bob".into()));
        assert_eq!(peer_identity(&bob, Some(NamedGroup::X25519)), None);
        assert_eq!(peer_identity(&bob, None), None);
    }

    #[test]
    fn classical_certificates_only_carry_control_and_application_names() {
        for name in ["attctl", "bob-app"] {
            let classical = peer(name, false);
            assert_eq!(
                peer_identity(&classical, Some(NamedGroup::X25519)),
                Some(name.into())
            );
            assert_eq!(
                peer_identity(&classical, Some(HYBRID_GROUP)),
                Some(name.into())
            );
        }
        for name in ["bob", "apf", "relay", "qrng", "app", "attctl2"] {
            let classical = peer(name, false);
            assert_eq!(
                peer_identity(&classical, Some(NamedGroup::X25519)),
                None,
                "{name}"
            );
            assert_eq!(
                peer_identity(&classical, Some(HYBRID_GROUP)),
                None,
                "{name}"
            );
        }
    }

    #[test]
    fn pki_issues_ml_dsa_and_ecdsa_certificates_that_parse() {
        let dir = std::env::temp_dir().join(format!("att-pki-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        run_pki(&[
            "--dir".into(),
            dir.display().to_string(),
            "--names".into(),
            "apf,bob".into(),
        ])
        .expect("pki");
        for (stem, name, post_quantum) in [
            ("bob", "bob", true),
            ("bob.classical", "bob", false),
            ("attctl", "attctl", true),
            ("attctl.classical", "attctl", false),
        ] {
            let cert = certs(&dir.join(format!("{stem}.crt"))).expect("cert")[0].clone();
            assert_eq!(
                peer_certificate(&cert),
                Some(peer(name, post_quantum)),
                "{stem}"
            );
            certified_key(&dir, stem).expect("key matches certificate");
        }
        run_pki_issue(&[
            "--dir".into(),
            dir.display().to_string(),
            "--name".into(),
            "bob".into(),
            "--out".into(),
            dir.join("negative").display().to_string(),
            "--classical".into(),
        ])
        .expect("pki-issue");
        let cert = certs(&dir.join("negative/bob.crt")).expect("cert")[0].clone();
        assert_eq!(peer_certificate(&cert), Some(peer("bob", false)));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
