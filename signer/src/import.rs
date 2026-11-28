//! Keymanager import mode (`serve --keymanager-import`): a signer that starts
//! with no keys takes its key shares straight from `charon dkg
//! --keymanager-address`, then its cluster lock, and only then signs.
//!
//! In this mode only the public listener is bound. It serves health,
//! attestation and two routes that need a token with the `import` role:
//!
//! 1. `POST /eth/v1/keystores` (the keymanager API's import, as charon calls
//!    it): allowed once. Every keystore is decrypted and checked, then all of
//!    them are written to the keystores directory and fsynced before the 200.
//!    charon checks only the status code and keeps no copy, so any failure is a
//!    non-2xx and leaves nothing behind.
//! 2. `POST /dvtee/v1/cluster-lock`: the lock `charon dkg` wrote. It is checked
//!    and pinned exactly like `--cluster-lock` (hashes, aggregate signature, and
//!    every imported key a share at one operator index). The process then exits
//!    with [`EXIT_IMPORTED`], and the service manager starts it again in
//!    signing mode.
//!
//! An `import-pending` marker is written before any key and removed only
//! after the lock is pinned. While it exists the signer never signs, so a
//! crash between the keys and the lock (charon sends keys first) can't leave
//! an unpinned signer serving.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::auth::Tokens;
use crate::keystore::{self, SecretKey};
use crate::pins::{Pins, write_durable};
use crate::slashing::SlashingDb;
use crate::tls::Role;

/// Exit status after a completed import: restart me in signing mode.
pub const EXIT_IMPORTED: i32 = 75;

const PENDING: &str = "import-pending";
const STAGING: &str = "import-staging";
const LOCK_UPLOAD: &str = "cluster-lock-upload.json";
/// Far more than any cluster's shares for one operator; bounds memory and time.
const MAX_KEYSTORES: usize = 10_000;
const BODY_LIMIT: usize = 64 * 1024 * 1024;

/// What a start finds on disk.
#[derive(Debug, PartialEq, Eq)]
pub enum Startup {
    /// No import pending: serve normally (or fail if there are no keys).
    Normal,
    /// An import is pending: stay in import mode.
    Pending,
}

/// Called once at startup, before keys are loaded: drops a half-written
/// staging directory, and reports whether an import is pending. A pending
/// import whose lock was already pinned (a crash after pinning, before the
/// marker went) is finished here.
pub fn startup(data_dir: &Path, keystores_dir: &Path) -> anyhow::Result<Startup> {
    let staging = data_dir.join(STAGING);
    if staging.exists() {
        tracing::warn!(path = %staging.display(), "removing an incomplete key import");
        fs::remove_dir_all(&staging)?;
        sync_dir(data_dir)?;
    }
    if !data_dir.join(PENDING).exists() {
        return Ok(Startup::Normal);
    }
    let keys = load_keys(keystores_dir)?;
    if !keys.is_empty()
        && let Ok(Some(_)) =
            Pins::load_or_pin(data_dir, None, &keys.keys().copied().collect::<Vec<_>>())
    {
        clear_pending(data_dir)?;
        tracing::info!("finished an import whose lock was already pinned");
        return Ok(Startup::Normal);
    }
    Ok(Startup::Pending)
}

/// The keystores in `dir`, or none if it doesn't exist.
pub fn load_keys(dir: &Path) -> anyhow::Result<BTreeMap<[u8; 48], SecretKey>> {
    if dir.exists() {
        keystore::load_dir(dir)
    } else {
        Ok(BTreeMap::new())
    }
}

pub struct ImportState {
    data_dir: PathBuf,
    keystores_dir: PathBuf,
    tokens: Tokens,
    db: Arc<SlashingDb>,
    /// Public keys imported so far (empty until the import). Held for the
    /// whole of each request: one import or lock upload at a time.
    keys: tokio::sync::Mutex<Vec<[u8; 48]>>,
    done: tokio::sync::Notify,
}

impl ImportState {
    pub fn new(
        data_dir: PathBuf,
        keystores_dir: PathBuf,
        tokens: Tokens,
        db: Arc<SlashingDb>,
        keys: Vec<[u8; 48]>,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(
            tokens.any_with(Role::Import),
            "--keymanager-import needs a token with the `import` role in --auth-token-file"
        );
        Ok(Arc::new(Self {
            data_dir,
            keystores_dir,
            tokens,
            db,
            keys: tokio::sync::Mutex::new(keys),
            done: tokio::sync::Notify::new(),
        }))
    }

    /// Resolves once the lock is pinned and the process should restart.
    pub async fn finished(&self) {
        self.done.notified().await;
    }
}

pub fn router(state: Arc<ImportState>) -> Router {
    Router::new()
        .route("/eth/v1/keystores", post(import_keystores))
        .route("/dvtee/v1/cluster-lock", post(upload_lock))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .with_state(state)
}

fn error(status: StatusCode, msg: impl Into<String>) -> Response {
    let msg = msg.into();
    tracing::warn!(status = status.as_u16(), error = %msg, "import refused");
    (status, Json(json!({"message": msg}))).into_response()
}

/// The keymanager API's import request body.
#[derive(Deserialize)]
struct ImportRequest {
    keystores: Vec<String>,
    passwords: Vec<String>,
    #[serde(default)]
    slashing_protection: Option<String>,
}

async fn import_keystores(
    State(st): State<Arc<ImportState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !st.tokens.grants(&headers, Role::Import) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid import token");
    }
    let mut keys = st.keys.lock().await;
    if !keys.is_empty() {
        return error(
            StatusCode::CONFLICT,
            "keys were already imported; import is once only",
        );
    }
    let req: ImportRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => return error(StatusCode::BAD_REQUEST, format!("bad request body: {e}")),
    };
    let n = req.keystores.len();
    if n == 0 || n != req.passwords.len() {
        return error(
            StatusCode::BAD_REQUEST,
            "keystores and passwords must be non-empty and the same length",
        );
    }
    if n > MAX_KEYSTORES {
        return error(
            StatusCode::BAD_REQUEST,
            format!("more than {MAX_KEYSTORES} keystores"),
        );
    }
    let passwords: Vec<Zeroizing<String>> = req.passwords.into_iter().map(Zeroizing::new).collect();
    let keystores = req.keystores;
    let slashing = req.slashing_protection;

    let st2 = st.clone();
    let result =
        tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 48]>, (StatusCode, String)> {
            let secrets =
                decrypt_all(&keystores, &passwords).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            let pubkeys: Vec<[u8; 48]> = secrets.iter().map(SecretKey::public_key).collect();
            let mut seen = pubkeys.clone();
            seen.sort();
            seen.dedup();
            if seen.len() != pubkeys.len() {
                return Err((StatusCode::BAD_REQUEST, "duplicate keystores".into()));
            }
            if let Some(interchange) = &slashing {
                st2.db
                    .import(interchange.as_bytes())
                    .map_err(|e| (StatusCode::BAD_REQUEST, format!("slashing protection: {e}")))?;
            }
            persist(&st2.data_dir, &st2.keystores_dir, &keystores, &passwords).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("persisting keys: {e}"),
                )
            })?;
            Ok(pubkeys)
        })
        .await;

    match result {
        Ok(Ok(pubkeys)) => {
            for pk in &pubkeys {
                tracing::info!(pubkey = %format!("0x{}", hex::encode(pk)), "imported key");
            }
            tracing::info!(
                keys = pubkeys.len(),
                "keys imported; waiting for the cluster lock"
            );
            let data: Vec<_> = pubkeys
                .iter()
                .map(|_| json!({"status": "imported", "message": ""}))
                .collect();
            *keys = pubkeys;
            Json(json!({"data": data})).into_response()
        }
        Ok(Err((status, msg))) => error(status, msg),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

/// Decrypts every keystore, spread over the available cores (charon allows
/// about 2 s per keystore for the whole request).
fn decrypt_all(
    keystores: &[String],
    passwords: &[Zeroizing<String>],
) -> Result<Vec<SecretKey>, String> {
    let threads = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(keystores.len());
    let chunk = keystores.len().div_ceil(threads);
    let results: Vec<Result<Vec<SecretKey>, String>> = std::thread::scope(|s| {
        let handles: Vec<_> = keystores
            .chunks(chunk)
            .zip(passwords.chunks(chunk))
            .enumerate()
            .map(|(c, (ks, pw))| {
                s.spawn(move || {
                    ks.iter()
                        .zip(pw)
                        .enumerate()
                        .map(|(i, (k, p))| {
                            keystore::decrypt(k, p)
                                .map_err(|e| format!("keystore {}: {e}", c * chunk + i))
                        })
                        .collect()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err("decrypt thread panicked".into()))
            })
            .collect()
    });
    let mut out = Vec::with_capacity(keystores.len());
    for r in results {
        out.extend(r?);
    }
    Ok(out)
}

/// Writes the keystores and their passwords as charon's `validator_keys/`
/// layout: the pending marker first, then a staging directory that is
/// fsynced and renamed into place.
fn persist(
    data_dir: &Path,
    keystores_dir: &Path,
    keystores: &[String],
    passwords: &[Zeroizing<String>],
) -> std::io::Result<()> {
    write_durable(data_dir, &data_dir.join(PENDING), b"pending\n")?;
    let staging = data_dir.join(STAGING);
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }
    fs::create_dir(&staging)?;
    for (i, (ks, pw)) in keystores.iter().zip(passwords).enumerate() {
        write_private(&staging.join(format!("keystore-{i}.json")), ks.as_bytes())?;
        write_private(&staging.join(format!("keystore-{i}.txt")), pw.as_bytes())?;
    }
    sync_dir(&staging)?;
    if keystores_dir.exists() {
        // Empty by construction (no keys were loaded); refuse anything else.
        fs::remove_dir(keystores_dir)?;
    }
    fs::rename(&staging, keystores_dir)?;
    sync_dir(keystores_dir.parent().unwrap_or(data_dir))?;
    sync_dir(data_dir)
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

fn sync_dir(dir: &Path) -> std::io::Result<()> {
    fs::File::open(dir)?.sync_all()
}

fn clear_pending(data_dir: &Path) -> std::io::Result<()> {
    match fs::remove_file(data_dir.join(PENDING)) {
        Ok(()) => sync_dir(data_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

async fn upload_lock(
    State(st): State<Arc<ImportState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !st.tokens.grants(&headers, Role::Import) {
        return error(StatusCode::UNAUTHORIZED, "missing or invalid import token");
    }
    let keys = st.keys.lock().await;
    if keys.is_empty() {
        return error(
            StatusCode::CONFLICT,
            "import the keys before the cluster lock",
        );
    }
    let pubkeys = keys.clone();
    let st2 = st.clone();
    let result = tokio::task::spawn_blocking(move || -> anyhow::Result<Pins> {
        let upload = st2.data_dir.join(LOCK_UPLOAD);
        write_durable(&st2.data_dir, &upload, &body)?;
        let pinned = Pins::load_or_pin(&st2.data_dir, Some(&upload), &pubkeys);
        let _ = fs::remove_file(&upload);
        let pins = pinned?.ok_or_else(|| anyhow::anyhow!("lock was not pinned"))?;
        clear_pending(&st2.data_dir)?;
        Ok(pins)
    })
    .await;
    match result {
        Ok(Ok(pins)) => {
            tracing::info!(
                lock_hash = %format!("0x{}", hex::encode(pins.lock_hash)),
                operator_index = pins.operator_index,
                "cluster lock pinned; import complete, restarting into signing mode"
            );
            st.done.notify_one();
            Json(json!({
                "lock_hash": format!("0x{}", hex::encode(pins.lock_hash)),
                "operator_index": pins.operator_index,
                "validators": pins.validators,
            }))
            .into_response()
        }
        Ok(Err(e)) => error(StatusCode::BAD_REQUEST, format!("cluster lock: {e:#}")),
        Err(e) => error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::testlock::{Spec, build, secret};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const TOKEN: &str = "import-token-0123456789abcdef0123456789abcdef";

    fn spec() -> Spec {
        Spec {
            threshold: 3,
            validators: vec![([0x11; 20], (0..4).map(secret).collect())],
        }
    }

    /// A keystore for operator 1's share, with a fast pbkdf2 KDF.
    fn share_keystore() -> (String, String) {
        let sk = secret(1);
        (
            crate::keystore::tests_encrypt(&sk, "pw-one"),
            "pw-one".to_string(),
        )
    }

    struct Fixture {
        dir: tempfile::TempDir,
        state: Arc<ImportState>,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir_all(&data).unwrap();
        let tokens_path = dir.path().join("tokens.txt");
        fs::write(&tokens_path, format!("charon {TOKEN} import\n")).unwrap();
        let tokens = Tokens::load(&tokens_path).unwrap();
        let db = Arc::new(SlashingDb::open(&data.join("slashing"), [0u8; 32]).unwrap());
        let state = ImportState::new(
            data.clone(),
            data.join("validator_keys"),
            tokens,
            db,
            vec![],
        )
        .unwrap();
        Fixture { dir, state }
    }

    async fn post(
        state: &Arc<ImportState>,
        path: &str,
        token: Option<&str>,
        body: String,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::post(path).header("content-type", "application/json");
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let resp = router(state.clone())
            .oneshot(req.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    fn import_body(ks: &str, pw: &str) -> String {
        json!({"keystores": [ks], "passwords": [pw]}).to_string()
    }

    #[tokio::test]
    async fn import_then_lock_then_restart() {
        let f = fixture();
        let data = f.dir.path().join("data");
        let (ks, pw) = share_keystore();

        // No token, and a token without the import role, are refused.
        assert_eq!(
            post(&f.state, "/eth/v1/keystores", None, import_body(&ks, &pw))
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        // The lock before the keys is refused.
        assert_eq!(
            post(
                &f.state,
                "/dvtee/v1/cluster-lock",
                Some(TOKEN),
                String::from_utf8(build(&spec())).unwrap()
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        let (status, body) = post(
            &f.state,
            "/eth/v1/keystores",
            Some(TOKEN),
            import_body(&ks, &pw),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["data"][0]["status"], "imported");
        assert!(data.join("validator_keys/keystore-0.json").exists());
        assert!(data.join(PENDING).exists());
        // A crash now restarts into import mode, never signing.
        assert_eq!(
            startup(&data, &data.join("validator_keys")).unwrap(),
            Startup::Pending
        );

        // Once only.
        assert_eq!(
            post(
                &f.state,
                "/eth/v1/keystores",
                Some(TOKEN),
                import_body(&ks, &pw)
            )
            .await
            .0,
            StatusCode::CONFLICT
        );

        let (status, body) = post(
            &f.state,
            "/dvtee/v1/cluster-lock",
            Some(TOKEN),
            String::from_utf8(build(&spec())).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["operator_index"], 1);
        assert!(!data.join(PENDING).exists());
        assert_eq!(
            startup(&data, &data.join("validator_keys")).unwrap(),
            Startup::Normal
        );
    }

    #[tokio::test]
    async fn bad_password_persists_nothing() {
        let f = fixture();
        let data = f.dir.path().join("data");
        let (ks, _) = share_keystore();
        let (status, _) = post(
            &f.state,
            "/eth/v1/keystores",
            Some(TOKEN),
            import_body(&ks, "wrong"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!data.join(PENDING).exists());
        assert!(!data.join("validator_keys").exists());
        // Mismatched lengths and an empty import are refused too.
        let body = json!({"keystores": [ks], "passwords": []}).to_string();
        assert_eq!(
            post(&f.state, "/eth/v1/keystores", Some(TOKEN), body)
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn lock_for_other_shares_is_refused() {
        let f = fixture();
        let data = f.dir.path().join("data");
        let (ks, pw) = share_keystore();
        assert_eq!(
            post(
                &f.state,
                "/eth/v1/keystores",
                Some(TOKEN),
                import_body(&ks, &pw)
            )
            .await
            .0,
            StatusCode::OK
        );
        let other = Spec {
            threshold: 3,
            validators: vec![([0x11; 20], (20..24).map(secret).collect())],
        };
        let (status, _) = post(
            &f.state,
            "/dvtee/v1/cluster-lock",
            Some(TOKEN),
            String::from_utf8(build(&other)).unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            data.join(PENDING).exists(),
            "still pending: never signs without its lock"
        );
    }

    #[test]
    fn incomplete_staging_is_removed() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path();
        fs::create_dir_all(data.join(STAGING)).unwrap();
        fs::write(data.join(STAGING).join("keystore-0.json"), "{}").unwrap();
        fs::write(data.join(PENDING), "pending\n").unwrap();
        assert_eq!(
            startup(data, &data.join("validator_keys")).unwrap(),
            Startup::Pending
        );
        assert!(!data.join(STAGING).exists());
    }
}
