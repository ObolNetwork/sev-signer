//! Web3Signer-compatible eth2 HTTP API, plus a TEE attestation endpoint.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Extension, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use crate::anti_rollback::TrustedClock;
use crate::auth::{TokenRoles, Tokens};
use crate::keystore::SecretKey;
use crate::network::Network;
use crate::pins::Pins;
use crate::platform::{Platform, PlatformError};
use crate::signing::{self, Policy, PrepareError, SignBody, SignRequest};
use crate::slashing::{SlashingDb, SlashingError};
use crate::tee;
use crate::tls::{ClientFingerprint, KnownRoles, Role};

pub struct AppState {
    pub keys: BTreeMap<[u8; 48], SecretKey>,
    pub db: Arc<SlashingDb>,
    pub network: Network,
    pub policy: Policy,
    /// DER of the TLS certificate the API is served with, if any.
    pub tls_cert: Option<(Vec<u8>, String)>,
    /// Source of attestation evidence.
    pub platform: Platform,
    /// Settings pinned from the cluster lock, if any.
    pub pins: Option<Pins>,
    /// Roles of the pinned client certificates, when mutual TLS is on.
    pub roles: Option<KnownRoles>,
    /// Bearer tokens required on `/api/v1/eth2/*`, if configured.
    pub tokens: Option<Tokens>,
    /// Start floor and horizon from trusted time; `None` when disabled.
    pub clock: Option<Arc<TrustedClock>>,
}

/// The role a request needs.
fn required_role(body: &SignBody) -> Role {
    match body {
        SignBody::VoluntaryExit { .. } => Role::Exit,
        SignBody::Deposit { .. } => Role::Deposit,
        _ => Role::Duties,
    }
}

/// Sign requests carry at most a Gloas execution payload envelope: a full
/// execution payload, hex-encoded. EIP-7934 caps the RLP block at 10 MiB,
/// which is ~20 MiB as JSON hex, plus the block access list.
const SIGN_BODY_LIMIT: usize = 32 * 1024 * 1024;

pub fn router(state: Arc<AppState>) -> Router {
    let mut eth2 = Router::new()
        .route("/api/v1/eth2/publicKeys", get(public_keys))
        .route(
            "/api/v1/eth2/sign/{identifier}",
            post(sign).layer(DefaultBodyLimit::max(SIGN_BODY_LIMIT)),
        );
    if let Some(tokens) = state.tokens.clone() {
        eth2 = eth2.route_layer(axum::middleware::from_fn_with_state(
            tokens,
            crate::auth::require_token,
        ));
    }
    Router::new()
        .route("/upcheck", get(|| async { "OK" }))
        .route(
            "/healthcheck",
            get(|| async { Json(json!({"status": "UP"})) }),
        )
        .merge(eth2)
        .route("/api/v1/tee/attestation", get(attestation))
        .layer(DefaultBodyLimit::max(256 * 1024))
        .with_state(state)
}

/// Health and attestation only, for a listener without client
/// authentication: evidence is meant to be fetched by anyone (e.g. charon
/// peers), and it reveals nothing beyond the public keys and certificate.
pub fn public_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/upcheck", get(|| async { "OK" }))
        .route(
            "/healthcheck",
            get(|| async { Json(json!({"status": "UP"})) }),
        )
        .route("/api/v1/tee/attestation", get(attestation))
        .with_state(state)
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(json!({"error": msg.into()}))).into_response()
}

async fn public_keys(State(st): State<Arc<AppState>>) -> Json<Vec<String>> {
    Json(
        st.keys
            .keys()
            .map(|k| format!("0x{}", hex::encode(k)))
            .collect(),
    )
}

fn parse_pubkey(s: &str) -> Option<[u8; 48]> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .ok()?
        .try_into()
        .ok()
}

async fn sign(
    State(st): State<Arc<AppState>>,
    Path(identifier): Path<String>,
    client: Option<Extension<ClientFingerprint>>,
    token: Option<Extension<TokenRoles>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(pubkey) = parse_pubkey(&identifier) else {
        return error(
            StatusCode::BAD_REQUEST,
            "identifier must be a 0x-prefixed BLS public key",
        );
    };
    if !st.keys.contains_key(&pubkey) {
        return error(StatusCode::NOT_FOUND, "public key not found");
    }

    let req: SignRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("invalid request body: {e}");
            tracing::warn!(pubkey = %identifier, error = %msg, "rejected sign request");
            return error(StatusCode::BAD_REQUEST, msg);
        }
    };

    // Every configured credential must grant the request's role.
    let role = required_role(&req.body);
    let denied = if let Some(roles) = &st.roles
        && !client
            .and_then(|Extension(ClientFingerprint(fp))| fp)
            .is_some_and(|fp| roles.allows(&fp, role))
    {
        Some("client certificate")
    } else if st.tokens.is_some()
        && !token.is_some_and(|Extension(TokenRoles(r))| r.contains(&role))
    {
        Some("token")
    } else {
        None
    };
    if let Some(credential) = denied {
        let msg = format!(
            "{credential} lacks the {:?} role for this request",
            role.name()
        );
        tracing::warn!(pubkey = %identifier, error = %msg, "rejected sign request");
        return error(StatusCode::FORBIDDEN, msg);
    }

    if let Some(pins) = &st.pins
        && let Err(e) = pins.check(&pubkey, &req.body)
    {
        tracing::warn!(pubkey = %identifier, status = %StatusCode::FORBIDDEN, error = %e, "rejected sign request");
        return error(StatusCode::FORBIDDEN, e.to_string());
    }

    let prepared = match signing::prepare(&req, &st.network, &st.policy) {
        Ok(p) => p,
        Err(e) => {
            let status = match e {
                PrepareError::Forbidden(_) | PrepareError::Refused(_) => StatusCode::FORBIDDEN,
                _ => StatusCode::BAD_REQUEST,
            };
            tracing::warn!(pubkey = %identifier, %status, error = %e, "rejected sign request");
            return error(status, e.to_string());
        }
    };

    // Anti-rollback: before the database, so a refusal moves no watermark.
    if let (Some(clock), Some(check)) = (&st.clock, &prepared.slashing)
        && let Err(e) = clock.check(check)
    {
        let status = if e.is_temporary() {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::PRECONDITION_FAILED
        };
        tracing::warn!(pubkey = %identifier, %status, error = %e, "refused to sign");
        return error(status, e.to_string());
    }

    // Slashing check, durable record and BLS signing are blocking work.
    let st2 = st.clone();
    let result = tokio::task::spawn_blocking(move || {
        if let Some(check) = prepared.slashing {
            st2.db
                .check_and_record(&pubkey, check, &prepared.signing_root)?;
        }
        let sk = st2.keys.get(&pubkey).expect("checked above");
        Ok::<_, SlashingError>((prepared.kind, sk.sign(&prepared.signing_root)))
    })
    .await;

    let (kind, signature) = match result {
        Ok(Ok(v)) => v,
        Ok(Err(e @ SlashingError::Violation(_))) => {
            tracing::warn!(pubkey = %identifier, error = %e, "refused to sign");
            return error(StatusCode::PRECONDITION_FAILED, e.to_string());
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "slashing protection database failure");
            return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
        }
        Err(e) => return error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };

    tracing::debug!(pubkey = %identifier, kind, "signed");
    let sig = format!("0x{}", hex::encode(signature));
    let wants_json = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"));
    if wants_json {
        Json(json!({"signature": sig})).into_response()
    } else {
        ([(header::CONTENT_TYPE, "text/plain; charset=utf-8")], sig).into_response()
    }
}

#[derive(Deserialize)]
struct AttestationQuery {
    nonce: Option<String>,
}

/// A browser asking for the page rather than an API client.
fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("text/html"))
}

async fn attestation(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    Query(q): Query<AttestationQuery>,
) -> Response {
    let html = wants_html(&headers);
    // The page needs no nonce: it proves nothing to its viewer anyway.
    let nonce = match q.nonce.as_deref() {
        Some(n) => hex::decode(n.trim_start_matches("0x"))
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok()),
        None if html => ring::rand::generate::<[u8; 32]>(&ring::rand::SystemRandom::new())
            .ok()
            .map(|n| n.expose()),
        None => None,
    };
    let Some(nonce) = nonce else {
        return error(StatusCode::BAD_REQUEST, "nonce must be 32 bytes of hex");
    };
    let Some((cert_der, cert_pem)) = st.tls_cert.clone() else {
        return error(
            StatusCode::CONFLICT,
            "attestation requires TLS: evidence is bound to the TLS certificate",
        );
    };

    let pubkeys: Vec<[u8; 48]> = st.keys.keys().copied().collect();
    let lock_hash = st.pins.as_ref().map(|p| p.lock_hash);
    let report_data = tee::report_data(&nonce, &cert_der, &pubkeys, lock_hash.as_ref());

    let st2 = st.clone();
    match tokio::task::spawn_blocking(move || st2.platform.evidence(&report_data)).await {
        Ok(Ok(ev)) if html => {
            use sha2::Digest;
            // HTTP/2 carries the host in the URI (:authority), HTTP/1.1 in Host.
            let host = uri
                .authority()
                .map(|a| a.as_str())
                .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
                .unwrap_or("this-signer");
            let page = crate::status_page::render(&crate::status_page::View {
                provider: &ev.provider,
                report: &ev.report,
                network: &st.network.name,
                keys: pubkeys
                    .iter()
                    .map(|k| (*k, st.pins.as_ref().and_then(|p| p.validator_of(k))))
                    .collect(),
                lock_hash,
                operator_index: st.pins.as_ref().map(|p| p.operator_index),
                genesis_time: st.network.genesis_time,
                epoch_ms: st.network.epoch_duration_ms(),
                now: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0),
                cert_sha256: sha2::Sha256::digest(&cert_der).into(),
                clock: st.clock.as_ref().map(|c| crate::status_page::ClockView {
                    floor: c.floor_epoch(),
                    trusted_epoch: c.trusted_epoch(),
                }),
                host,
            });
            (
                [
                    (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                    (header::CONTENT_SECURITY_POLICY, crate::status_page::CSP),
                    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
                    (header::CACHE_CONTROL, "no-store"),
                    (header::REFERRER_POLICY, "no-referrer"),
                ],
                page,
            )
                .into_response()
        }
        Ok(Ok(ev)) => Json(json!({
            "provider": ev.provider,
            "report": format!("0x{}", hex::encode(&ev.report)),
            "auxblob": ev.auxblob.map(|b| format!("0x{}", hex::encode(b))),
            "report_data": format!("0x{}", hex::encode(report_data)),
            "tls_certificate": cert_pem,
            "pubkeys": pubkeys.iter().map(|k| format!("0x{}", hex::encode(k))).collect::<Vec<_>>(),
            "cluster_lock_hash": lock_hash.map(|h| format!("0x{}", hex::encode(h))),
        }))
        .into_response(),
        Ok(Err(e @ PlatformError::Tee(tee::TeeError::Unavailable))) => {
            error(StatusCode::NOT_IMPLEMENTED, e.to_string())
        }
        Ok(Err(e)) => error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}
