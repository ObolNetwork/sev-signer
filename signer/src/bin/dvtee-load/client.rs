//! HTTP client for the signer: HTTP/1.1 over a pool of keep-alive
//! connections, or HTTP/2 over one connection, with or without TLS. TLS pins
//! the signer's self-signed certificate, the way validator clients are set up
//! against it, and can present a client certificate for mTLS.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};

/// Where and how to reach the signer.
#[derive(Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
    /// `None` for plain HTTP.
    pub tls: Option<Arc<ClientConfig>>,
    pub http2: bool,
}

pub struct ClientCert {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

/// TLS config that trusts exactly `server_cert`.
pub fn tls_config(
    server_cert: CertificateDer<'static>,
    client: Option<ClientCert>,
    http2: bool,
) -> anyhow::Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            cert: server_cert,
            algs,
        }));
    let mut cfg = match client {
        Some(c) => builder.with_client_auth_cert(vec![c.cert], c.key)?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![if http2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    Ok(Arc::new(cfg))
}

#[derive(Debug)]
struct Pinned {
    cert: CertificateDer<'static>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref() == self.cert.as_ref() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate is not the pinned one".into(),
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

trait Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static> Io for T {}

async fn dial(t: &Target) -> anyhow::Result<Box<dyn Io>> {
    let tcp = TcpStream::connect((t.host.as_str(), t.port))
        .await
        .with_context(|| format!("connecting to {}:{}", t.host, t.port))?;
    tcp.set_nodelay(true)?;
    Ok(match &t.tls {
        None => Box::new(tcp),
        Some(cfg) => {
            let name = ServerName::try_from(t.host.clone())?;
            Box::new(
                tokio_rustls::TlsConnector::from(cfg.clone())
                    .connect(name, tcp)
                    .await
                    .context("TLS handshake")?,
            )
        }
    })
}

/// One connection's request sender.
#[derive(Clone)]
pub enum Conn {
    H1(Arc<Mutex<hyper::client::conn::http1::SendRequest<Full<Bytes>>>>),
    H2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}

pub async fn connect(t: &Target) -> anyhow::Result<Conn> {
    let io = TokioIo::new(dial(t).await?);
    if t.http2 {
        let (send, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
        tokio::spawn(conn);
        Ok(Conn::H2(send))
    } else {
        let (send, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        Ok(Conn::H1(Arc::new(Mutex::new(send))))
    }
}

pub struct Response {
    pub status: u16,
    pub body: Bytes,
}

impl Conn {
    pub async fn request(
        &self,
        t: &Target,
        method: &str,
        path: &str,
        body: Bytes,
    ) -> anyhow::Result<Response> {
        let req = hyper::Request::builder()
            .method(method)
            .uri(path)
            .header(hyper::header::HOST, format!("{}:{}", t.host, t.port))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(body))?;
        let resp = match self {
            Conn::H1(s) => {
                let mut s = s.lock().await;
                s.ready().await?;
                s.send_request(req).await?
            }
            Conn::H2(s) => {
                let mut s = s.clone();
                s.ready().await?;
                s.send_request(req).await?
            }
        };
        let status = resp.status().as_u16();
        let body = resp.into_body().collect().await?.to_bytes();
        Ok(Response { status, body })
    }
}

/// A signing request to send at `scheduled`.
pub struct Job {
    pub id: usize,
    pub path: String,
    pub body: Bytes,
    pub scheduled: Instant,
}

pub struct Done {
    pub id: usize,
    pub scheduled: Instant,
    pub done: Instant,
    pub result: anyhow::Result<Response>,
}

/// Sends jobs from a queue: `conns` HTTP/1.1 connections each with one
/// request in flight, or (HTTP/2) one connection with a stream per job.
/// Connections are opened, and checked with `/upcheck`, before this returns.
pub async fn start(
    t: Target,
    conns: usize,
) -> anyhow::Result<(mpsc::UnboundedSender<Job>, mpsc::UnboundedReceiver<Done>)> {
    let (job_tx, job_rx) = mpsc::unbounded_channel::<Job>();
    let (done_tx, done_rx) = mpsc::unbounded_channel::<Done>();
    let t = Arc::new(t);

    if t.http2 {
        let conn = connect(&t).await?;
        warm(&conn, &t).await?;
        let mut job_rx = job_rx;
        tokio::spawn(async move {
            while let Some(job) = job_rx.recv().await {
                let (conn, t, done_tx) = (conn.clone(), t.clone(), done_tx.clone());
                tokio::spawn(async move {
                    let result = conn.request(&t, "POST", &job.path, job.body).await;
                    let _ = done_tx.send(Done {
                        id: job.id,
                        scheduled: job.scheduled,
                        done: Instant::now(),
                        result,
                    });
                });
            }
        });
    } else {
        let job_rx = Arc::new(Mutex::new(job_rx));
        let mut pool = Vec::with_capacity(conns);
        for _ in 0..conns {
            let c = connect(&t).await?;
            warm(&c, &t).await?;
            pool.push(c);
        }
        for mut conn in pool {
            let (t, job_rx, done_tx) = (t.clone(), job_rx.clone(), done_tx.clone());
            tokio::spawn(async move {
                loop {
                    let Some(job) = job_rx.lock().await.recv().await else {
                        return;
                    };
                    let mut result = conn.request(&t, "POST", &job.path, job.body.clone()).await;
                    if result.is_err() {
                        // A dropped keep-alive connection: redial once.
                        if let Ok(c) = connect(&t).await {
                            conn = c;
                            result = conn.request(&t, "POST", &job.path, job.body).await;
                        }
                    }
                    let _ = done_tx.send(Done {
                        id: job.id,
                        scheduled: job.scheduled,
                        done: Instant::now(),
                        result,
                    });
                }
            });
        }
    }
    Ok((job_tx, done_rx))
}

async fn warm(c: &Conn, t: &Target) -> anyhow::Result<()> {
    let r = c.request(t, "GET", "/upcheck", Bytes::new()).await?;
    anyhow::ensure!(r.status == 200, "/upcheck returned {}", r.status);
    Ok(())
}
