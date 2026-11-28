//! Bearer tokens for the signing API, a second factor next to pinned client
//! certificates and the only one for validator clients that can't present a
//! certificate.
//!
//! `--auth-token-file` lists one token per line, `<name> <token> [roles]`,
//! with the same roles as `knownClients` (default `duties`). A request to
//! `/api/v1/eth2/*` must carry one of them, either as
//! `Authorization: Bearer <token>` or as the password of HTTP Basic auth,
//! because validator clients can only put credentials in the signer URL
//! (`https://vc:<token>@signer:9000`). A missing or wrong token gets `401`
//! with `WWW-Authenticate: Basic`, which Teku needs before it sends Basic
//! credentials. Tokens are compared in constant time and never logged.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::tls::Role;

/// Tokens shorter than this are refused at startup.
const MIN_TOKEN_LEN: usize = 32;

#[derive(Clone, Debug)]
struct Entry {
    name: String,
    digest: [u8; 32],
    roles: Vec<Role>,
}

#[derive(Clone, Debug)]
pub struct Tokens(Arc<Vec<Entry>>);

/// The roles of the token a request authenticated with.
#[derive(Clone, Debug)]
pub struct TokenRoles(pub Vec<Role>);

impl Tokens {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut entries: Vec<Entry> = Vec::new();
        for (n, line) in text.lines().enumerate().map(|(n, l)| (n + 1, l.trim())) {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split_whitespace().collect();
            let (name, token, roles) = match cols.as_slice() {
                [name, token] => (*name, *token, vec![Role::Duties]),
                [name, token, roles] => (*name, *token, Role::parse_list(roles)?),
                _ => anyhow::bail!(
                    "{} line {n}: expected `<name> <token> [roles]`",
                    path.display()
                ),
            };
            anyhow::ensure!(
                token.len() >= MIN_TOKEN_LEN,
                "{} line {n}: token for {name} is shorter than {MIN_TOKEN_LEN} characters",
                path.display()
            );
            anyhow::ensure!(
                token.bytes().all(|b| b.is_ascii_graphic() && b != b':'),
                "{} line {n}: token for {name} must be printable ASCII without ':'",
                path.display()
            );
            let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
            anyhow::ensure!(
                !entries.iter().any(|e| e.digest == digest || e.name == name),
                "{} line {n}: duplicate name or token",
                path.display()
            );
            entries.push(Entry {
                name: name.to_string(),
                digest,
                roles,
            });
        }
        anyhow::ensure!(!entries.is_empty(), "{} lists no tokens", path.display());
        Ok(Self(Arc::new(entries)))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Finds the entry for a presented token. Compares SHA-256 digests in
    /// constant time and always checks every entry.
    fn find(&self, presented: &[u8]) -> Option<&Entry> {
        let digest: [u8; 32] = Sha256::digest(presented).into();
        let mut found = None;
        for e in self.0.iter() {
            if ct_eq(&e.digest, &digest) {
                found = Some(e);
            }
        }
        found
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// The token in `Authorization: Bearer <t>` or `Basic base64(<user>:<t>)`.
fn presented_token(req: &Request) -> Option<Vec<u8>> {
    let value = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, rest) = value.trim().split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        Some(rest.trim().as_bytes().to_vec())
    } else if scheme.eq_ignore_ascii_case("basic") {
        let decoded = base64_decode(rest.trim())?;
        let colon = decoded.iter().position(|&b| b == b':')?;
        Some(decoded[colon + 1..].to_vec())
    } else {
        None
    }
}

/// Standard base64 with padding (RFC 4648), as HTTP Basic uses.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let b = s.as_bytes();
    if b.is_empty() || !b.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(b.len() / 4 * 3);
    for (i, chunk) in b.chunks(4).enumerate() {
        let last = i == b.len() / 4 - 1;
        let pad = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &chunk[..4 - pad] {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Some(out)
}

fn unauthorized() -> Response {
    let mut resp = (
        StatusCode::UNAUTHORIZED,
        axum::Json(serde_json::json!({"error": "missing or invalid credentials"})),
    )
        .into_response();
    resp.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"dvtee\", charset=\"UTF-8\""),
    );
    resp
}

/// Middleware for `/api/v1/eth2/*`: requires a listed token and attaches its
/// roles to the request.
pub async fn require_token(State(tokens): State<Tokens>, mut req: Request, next: Next) -> Response {
    let Some(entry) = presented_token(&req).and_then(|t| tokens.find(&t).cloned()) else {
        tracing::warn!(path = %req.uri().path(), "rejected request: missing or invalid token");
        return unauthorized();
    };
    req.headers_mut().remove(header::AUTHORIZATION);
    tracing::trace!(client = %entry.name, "token accepted");
    req.extensions_mut().insert(TokenRoles(entry.roles));
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(base64_decode("dmM6c2VjcmV0").unwrap(), b"vc:secret");
        assert_eq!(base64_decode("YQ==").unwrap(), b"a");
        assert_eq!(base64_decode("YWI=").unwrap(), b"ab");
        assert!(base64_decode("YQ=").is_none());
        assert!(base64_decode("YQ==YQ==").is_none());
        assert!(base64_decode("!!!!").is_none());
    }

    #[test]
    fn load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("tokens");
        let t1 = "a".repeat(40);
        let t2 = "b".repeat(40);
        std::fs::write(&p, format!("# x\nvc {t1}\nops {t2} exit\n")).unwrap();
        let tokens = Tokens::load(&p).unwrap();
        assert_eq!(
            tokens.find(t1.as_bytes()).unwrap().roles,
            vec![Role::Duties]
        );
        assert_eq!(tokens.find(t2.as_bytes()).unwrap().roles, vec![Role::Exit]);
        assert!(tokens.find(b"c").is_none());

        for bad in [
            "vc short\n".to_string(),
            format!("vc {t1}\nvc2 {t1}\n"),
            format!("vc {t1} admin\n"),
            format!("vc {}:x\n", "a".repeat(40)),
            "# nothing\n".to_string(),
        ] {
            std::fs::write(&p, bad).unwrap();
            assert!(Tokens::load(&p).is_err());
        }
    }
}
