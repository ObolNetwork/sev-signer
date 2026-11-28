//! TLS termination inside the guest.
//!
//! The server key is generated on first start and kept in the data directory
//! (the encrypted, measured disk in a TEE deployment), so it never exists
//! outside the guest. Its certificate is bound into attestation evidence; see
//! `tee.rs`.
//!
//! Optional mutual TLS pins client certificates by SHA-256 fingerprint,
//! the same model as Web3Signer's `knownClients` file. An optional third
//! column grants each certificate roles (see [`Role`]); the signing listener
//! tags every request with the client's fingerprint so the API can check them.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme};
use sha2::{Digest, Sha256};

pub struct Material {
    /// Signing listener: requires a pinned client certificate when known
    /// clients are configured.
    pub config: Arc<ServerConfig>,
    /// Public listener (health, attestation): same certificate, no client
    /// authentication.
    pub public_config: Arc<ServerConfig>,
    pub cert_der: Vec<u8>,
    pub cert_pem: String,
    /// Roles per pinned client certificate, when known clients are set.
    pub roles: Option<KnownRoles>,
}

/// What a client certificate may ask the signer to sign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Validator duties: attestations, blocks, aggregation, sync committee,
    /// RANDAO, registrations and Gloas duties.
    Duties,
    /// `VOLUNTARY_EXIT`.
    Exit,
    /// `DEPOSIT` (also needs `--allow-deposits`).
    Deposit,
    /// Keymanager import (`--keymanager-import`): the one-time key import
    /// and cluster lock upload. Grants no signing.
    Import,
}

impl Role {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "duties" => Some(Self::Duties),
            "exit" => Some(Self::Exit),
            "deposit" => Some(Self::Deposit),
            "import" => Some(Self::Import),
            _ => None,
        }
    }

    /// A comma-separated role list, sorted and deduplicated.
    pub fn parse_list(s: &str) -> anyhow::Result<Vec<Self>> {
        let mut roles = s
            .split(',')
            .map(|r| {
                Self::parse(r)
                    .with_context(|| format!("unknown role {r:?} (duties, exit, deposit, import)"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        roles.sort();
        roles.dedup();
        Ok(roles)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Duties => "duties",
            Self::Exit => "exit",
            Self::Deposit => "deposit",
            Self::Import => "import",
        }
    }
}

/// Roles granted to each pinned client certificate, by SHA-256 fingerprint.
#[derive(Clone, Debug, Default)]
pub struct KnownRoles(BTreeMap<[u8; 32], Vec<Role>>);

impl KnownRoles {
    pub fn allows(&self, fingerprint: &[u8; 32], role: Role) -> bool {
        self.0.get(fingerprint).is_some_and(|r| r.contains(&role))
    }
}

/// Reads the roles from a known clients file (the same parsing the TLS
/// verifier uses).
pub fn known_roles(path: &Path) -> anyhow::Result<KnownRoles> {
    Ok(PinnedClients::load(path)?.roles)
}

/// The client certificate fingerprint of a connection on the signing
/// listener (`None` without mutual TLS).
#[derive(Clone, Copy, Debug)]
pub struct ClientFingerprint(pub Option<[u8; 32]>);

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Loads `cert.pem`/`key.pem` from `dir`, generating a self-signed pair for
/// `sans` on first use.
pub fn load_or_generate(
    dir: &Path,
    sans: &[String],
    known_clients: Option<&Path>,
) -> anyhow::Result<Material> {
    std::fs::create_dir_all(dir)?;
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");

    if !cert_path.exists() {
        let ck = rcgen::generate_simple_self_signed(sans.to_vec())
            .context("generating TLS certificate")?;
        let key_pem = ck.signing_key.serialize_pem();
        write_private(&key_path, key_pem.as_bytes())?;
        std::fs::write(&cert_path, ck.cert.pem())?;
        tracing::info!(path = %cert_path.display(), ?sans, "generated self-signed TLS certificate");
    }

    let cert_pem = std::fs::read_to_string(&cert_path)?;
    let cert = CertificateDer::from_pem_slice(cert_pem.as_bytes()).context("parsing cert.pem")?;
    let key = PrivateKeyDer::from_pem_file(&key_path).context("parsing key.pem")?;

    let builder =
        ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let (builder, roles) = match known_clients {
        Some(path) => {
            let pinned = PinnedClients::load(path)?;
            let roles = pinned.roles.clone();
            (
                builder.with_client_cert_verifier(Arc::new(pinned)),
                Some(roles),
            )
        }
        None => (builder.with_no_client_auth(), None),
    };
    let mut config = builder.with_single_cert(vec![cert.clone()], key.clone_key())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let mut public_config = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key)?;
    public_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Material {
        config: Arc::new(config),
        public_config: Arc::new(public_config),
        cert_der: cert.to_vec(),
        cert_pem,
        roles,
    })
}

/// A rustls acceptor that tags each connection's requests with the client
/// certificate's fingerprint ([`ClientFingerprint`]).
#[derive(Clone)]
pub struct IdentifyingAcceptor(axum_server::tls_rustls::RustlsAcceptor);

impl IdentifyingAcceptor {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self(axum_server::tls_rustls::RustlsAcceptor::new(
            axum_server::tls_rustls::RustlsConfig::from_config(config),
        ))
    }
}

impl<I, S> axum_server::accept::Accept<I, S> for IdentifyingAcceptor
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<I>;
    type Service = tower_http::add_extension::AddExtension<S, ClientFingerprint>;
    type Future =
        Pin<Box<dyn Future<Output = std::io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let inner = self.0.clone();
        Box::pin(async move {
            let (stream, service) = inner.accept(stream, service).await?;
            let fingerprint = stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|c| c.first())
                .map(|c| Sha256::digest(c.as_ref()).into());
            Ok((
                stream,
                tower_http::add_extension::AddExtension::new(
                    service,
                    ClientFingerprint(fingerprint),
                ),
            ))
        })
    }
}

fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

/// Accepts exactly the client certificates whose SHA-256 DER fingerprint is
/// listed (one per line, hex, `:` separators and a leading name allowed, so
/// Web3Signer `knownClients` files work as-is).
///
/// An optional third column lists the certificate's roles, comma-separated:
/// `vc-node0 AB:CD:... duties` or `ops AB:CD:... exit`. A line without one
/// gets `duties,exit`, which is what every client could do before roles.
#[derive(Debug)]
struct PinnedClients {
    fingerprints: Vec<[u8; 32]>,
    roles: KnownRoles,
    algs: WebPkiSupportedAlgorithms,
}

fn parse_fingerprint(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.replace(':', "")).ok()?.try_into().ok()
}

impl PinnedClients {
    fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut fingerprints = Vec::new();
        let mut roles = KnownRoles::default();
        let mut legacy = 0;
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let cols: Vec<&str> = line.split_whitespace().collect();
            let last = cols.last().copied().unwrap_or_default();
            let (fp, granted) = match parse_fingerprint(last) {
                Some(fp) => {
                    legacy += 1;
                    (fp, vec![Role::Duties, Role::Exit])
                }
                None => {
                    let fp = cols
                        .len()
                        .checked_sub(2)
                        .and_then(|i| parse_fingerprint(cols[i]))
                        .with_context(|| format!("bad SHA-256 fingerprint {line:?}"))?;
                    let granted = Role::parse_list(last).with_context(|| format!("in {line:?}"))?;
                    (fp, granted)
                }
            };
            anyhow::ensure!(
                !fingerprints.contains(&fp),
                "{} lists a fingerprint twice: {line:?}",
                path.display()
            );
            fingerprints.push(fp);
            roles.0.insert(fp, granted);
        }
        if legacy > 0 {
            tracing::warn!(
                path = %path.display(),
                clients = legacy,
                "known clients without a roles column get duties and exit; \
                 add a third column (duties, exit, deposit) to restrict them"
            );
        }
        anyhow::ensure!(
            !fingerprints.is_empty(),
            "{} lists no client fingerprints",
            path.display()
        );
        Ok(Self {
            fingerprints,
            roles,
            algs: provider().signature_verification_algorithms,
        })
    }
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let fp: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if self.fingerprints.contains(&fp) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "client certificate not in known clients".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> anyhow::Result<PinnedClients> {
        let dir = tempfile::tempdir()?;
        let p = dir.path().join("known");
        std::fs::write(&p, text)?;
        PinnedClients::load(&p)
    }

    #[test]
    fn known_clients_roles() {
        let a = "AA:".repeat(31) + "AA";
        let b = "bb".repeat(32);
        let c = load(&format!("# comment\nvc {a} duties\nops {b} exit,deposit\n")).unwrap();
        assert!(c.roles.allows(&[0xaa; 32], Role::Duties));
        assert!(!c.roles.allows(&[0xaa; 32], Role::Exit));
        assert!(c.roles.allows(&[0xbb; 32], Role::Deposit));
        assert!(!c.roles.allows(&[0xbb; 32], Role::Duties));

        // Web3Signer's two-column format: duties and exit.
        let c = load(&format!("vc {a}\n")).unwrap();
        assert!(c.roles.allows(&[0xaa; 32], Role::Exit));
        assert!(!c.roles.allows(&[0xaa; 32], Role::Deposit));

        assert!(load(&format!("vc {a} admin\n")).is_err());
        assert!(load(&format!("vc {a} duties\nvc2 {a} exit\n")).is_err());
        assert!(load("vc nothex duties\n").is_err());
    }
}
