//! Cross-implementation tests against vectors produced by `tests/vecgen`
//! (upstream go-eth2-client v0.30.3 SSZ, herumi BLS and the wealdtech EIP-2335
//! encryptor, as charon uses them). The Gloas vectors run on Hoodi with Gloas
//! scheduled at epoch 60000 (`tests/vectors/gloas-config.yaml`).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use dvtee::anti_rollback::{Bounds, TrustedClock};
use dvtee::api::{AppState, router};
use dvtee::keystore::{self, SecretKey};
use dvtee::network::Network;
use dvtee::signing::{self, Policy, PrepareError, SignRequest};
use dvtee::slashing::SlashingDb;
use http_body_util::BodyExt;
use serde::Deserialize;
use tower::ServiceExt;

#[derive(Deserialize)]
struct Vectors {
    secret_key: String,
    public_key: String,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    request: serde_json::Value,
    signing_root: String,
    signature: String,
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn vectors() -> Vectors {
    serde_json::from_slice(&std::fs::read(dir().join("signing_vectors.json")).unwrap()).unwrap()
}

fn hoodi() -> Network {
    "hoodi".parse().unwrap()
}

/// Hoodi plus Gloas at epoch 60000, loaded through the config.yaml `--network` parser.
fn hoodi_gloas() -> Network {
    let cfg = std::fs::read_to_string(dir().join("gloas-config.yaml")).unwrap();
    Network::from_config_yaml(&cfg, hoodi().genesis_validators_root).unwrap()
}

fn is_gloas(v: &Vector) -> bool {
    v.name.contains("gloas")
        || [
            "PAYLOAD_ATTESTATION_MESSAGE",
            "PROPOSER_PREFERENCES",
            "EXECUTION_PAYLOAD_ENVELOPE",
            "BUILDER_REQUEST_AUTH",
        ]
        .contains(&v.request["type"].as_str().unwrap())
}

fn get<'a>(v: &'a Vectors, name: &str) -> &'a Vector {
    v.vectors
        .iter()
        .find(|x| x.name == name)
        .unwrap_or_else(|| panic!("no vector {name}"))
}

fn prep(body: serde_json::Value, net: &Network) -> Result<signing::Prepared, PrepareError> {
    let req: SignRequest = serde_json::from_value(body).unwrap();
    signing::prepare(&req, net, &allow_all())
}

fn allow_all() -> Policy {
    Policy {
        allow_voluntary_exits: true,
        allow_deposits: true,
    }
}

fn secret(v: &Vectors) -> SecretKey {
    SecretKey::from_bytes(&hex::decode(v.secret_key.trim_start_matches("0x")).unwrap()).unwrap()
}

#[test]
fn signing_roots_and_signatures_match_go() {
    let v = vectors();
    let sk = secret(&v);
    assert_eq!(format!("0x{}", hex::encode(sk.public_key())), v.public_key);
    assert_eq!(v.vectors.len(), 21);
    assert_eq!(v.vectors.iter().filter(|x| is_gloas(x)).count(), 8);

    for vec in &v.vectors {
        let req: SignRequest = serde_json::from_value(vec.request.clone())
            .unwrap_or_else(|e| panic!("{}: parse: {e}", vec.name));
        let p = signing::prepare(&req, &hoodi_gloas(), &allow_all())
            .unwrap_or_else(|e| panic!("{}: prepare: {e}", vec.name));
        assert_eq!(
            format!("0x{}", hex::encode(p.signing_root)),
            vec.signing_root,
            "{}",
            vec.name
        );
        assert_eq!(
            format!("0x{}", hex::encode(sk.sign(&p.signing_root))),
            vec.signature,
            "{}",
            vec.name
        );
    }
}

#[test]
fn roots_are_computed_not_trusted() {
    let v = vectors();
    for vec in &v.vectors {
        // Without signingRoot the computed root is still produced...
        let mut body = vec.request.clone();
        body.as_object_mut().unwrap().remove("signingRoot");
        let req: SignRequest = serde_json::from_value(body).unwrap();
        let p = signing::prepare(&req, &hoodi_gloas(), &allow_all()).unwrap();
        assert_eq!(
            format!("0x{}", hex::encode(p.signing_root)),
            vec.signing_root,
            "{}",
            vec.name
        );

        // ...and a mismatching signingRoot is rejected.
        let mut body = vec.request.clone();
        body["signingRoot"] = serde_json::json!(format!("0x{}", "11".repeat(32)));
        let req: SignRequest = serde_json::from_value(body).unwrap();
        assert!(
            signing::prepare(&req, &hoodi_gloas(), &allow_all()).is_err(),
            "{}",
            vec.name
        );
    }
}

/// On the real Hoodi schedule (Gloas not scheduled) the pre-Gloas vectors
/// still sign and every versioned Gloas one is refused. (ATTESTATION carries
/// no version and has the same shape in every fork.)
#[test]
fn hoodi_preset_refuses_gloas() {
    let v = vectors();
    for vec in &v.vectors {
        let r = prep(vec.request.clone(), &hoodi());
        if is_gloas(vec) && vec.name != "attestation_gloas" {
            assert!(r.is_err(), "{}", vec.name);
        } else {
            assert_eq!(
                format!("0x{}", hex::encode(r.unwrap().signing_root)),
                vec.signing_root,
                "{}",
                vec.name
            );
        }
    }
}

/// Lighthouse and Teku send Electra aggregates under the v1
/// `AGGREGATE_AND_PROOF` type (seen on a devnet, 2026-11). The root must equal
/// the Go-computed Electra one.
#[test]
fn v1_aggregate_type_with_electra_body() {
    let v = vectors();
    let v2 = get(&v, "aggregate_and_proof_v2_fulu");
    let mut body = v2.request.clone();
    let inner = body["aggregate_and_proof"]["data"].clone();
    body["type"] = serde_json::json!("AGGREGATE_AND_PROOF");
    body["aggregate_and_proof"] = inner;
    let req: SignRequest = serde_json::from_value(body).unwrap();
    let p = signing::prepare(&req, &hoodi(), &allow_all()).unwrap();
    assert_eq!(p.kind, "AGGREGATE_AND_PROOF");
    assert_eq!(
        format!("0x{}", hex::encode(p.signing_root)),
        v2.signing_root
    );
}

/// The v1 aggregate type has no version: the fork at the slot picks the
/// schema and `committee_bits` must agree with it.
#[test]
fn v1_aggregate_schema_follows_fork() {
    let v = vectors();
    let net = hoodi_gloas();
    let gloas = &get(&v, "aggregate_and_proof_gloas").request;
    let mut no_bits = gloas.clone();
    no_bits["aggregate_and_proof"]["aggregate"]
        .as_object_mut()
        .unwrap()
        .remove("committee_bits");
    no_bits.as_object_mut().unwrap().remove("signingRoot");
    assert!(prep(no_bits, &net).is_err());

    let phase0 = &get(&v, "aggregate_and_proof_phase0").request;
    let mut with_bits = phase0.clone();
    with_bits["aggregate_and_proof"]["aggregate"]["committee_bits"] =
        serde_json::json!("0x0100000000000000");
    with_bits.as_object_mut().unwrap().remove("signingRoot");
    assert!(prep(with_bits, &net).is_err());

    // Without a fork schedule (custom:), committee_bits picks Phase0 vs
    // Electra as before, so a Gloas body cannot be hashed correctly: that is
    // why Gloas needs a schedule.
    let custom: Network = format!(
        "custom:0x{}:0x10000910:0x40000910",
        hex::encode(hoodi().genesis_validators_root)
    )
    .parse()
    .unwrap();
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(prep(phase0.clone(), &custom).unwrap().signing_root)
        ),
        get(&v, "aggregate_and_proof_phase0").signing_root
    );
    assert!(
        prep(gloas.clone(), &custom).is_err(),
        "signingRoot mismatch"
    );
}

#[test]
fn version_must_match_fork_at_slot() {
    let v = vectors();
    let net = hoodi_gloas();
    for (name, path, wrong) in [
        ("block_v2_gloas", "/beacon_block/version", "FULU"),
        ("block_v2_fulu", "/beacon_block/version", "GLOAS"),
        ("block_v2_fulu", "/beacon_block/version", "ELECTRA"),
        (
            "aggregate_and_proof_v2_fulu",
            "/aggregate_and_proof/version",
            "ELECTRA",
        ),
        (
            "aggregate_and_proof_v2_gloas",
            "/aggregate_and_proof/version",
            "FULU",
        ),
        (
            "payload_attestation_message",
            "/payload_attestation_message/version",
            "FULU",
        ),
        (
            "proposer_preferences_fork_boundary",
            "/proposer_preferences/version",
            "FULU",
        ),
        (
            "execution_payload_envelope",
            "/execution_payload_envelope/version",
            "FULU",
        ),
        (
            "builder_request_auth",
            "/builder_request_auth/version",
            "FULU",
        ),
        ("block_v2_gloas", "/beacon_block/version", "HEZE"),
    ] {
        let mut body = get(&v, name).request.clone();
        *body.pointer_mut(path).unwrap() = serde_json::json!(wrong);
        body.as_object_mut().unwrap().remove("signingRoot");
        let err = prep(body, &net).unwrap_err();
        assert!(
            matches!(err, PrepareError::Invalid(_)),
            "{name} {wrong}: {err}"
        );
    }
    // Lower case is accepted.
    let mut body = get(&v, "block_v2_gloas").request.clone();
    body["beacon_block"]["version"] = serde_json::json!("gloas");
    prep(body, &net).unwrap();

    // A Gloas-only type for a slot before the fork.
    let mut body = get(&v, "payload_attestation_message").request.clone();
    body["payload_attestation_message"]["data"]["slot"] = serde_json::json!("1622116");
    body.as_object_mut().unwrap().remove("signingRoot");
    assert!(prep(body, &net).is_err());
}

/// The proposer preferences domain takes the fork version of the proposal
/// epoch from the schedule, whatever fork_info says (only its genesis
/// validators root is checked).
#[test]
fn proposer_preferences_domain_from_schedule() {
    let v = vectors();
    let vec = get(&v, "proposer_preferences_fork_boundary");
    assert_eq!(
        vec.request["fork_info"]["fork"]["current_version"], "0x70000910",
        "signed from Fulu"
    );
    let mut body = vec.request.clone();
    body["fork_info"]["fork"]["current_version"] = serde_json::json!("0x80000910");
    body["fork_info"]["fork"]["epoch"] = serde_json::json!("60000");
    assert_eq!(
        format!(
            "0x{}",
            hex::encode(prep(body, &hoodi_gloas()).unwrap().signing_root)
        ),
        vec.signing_root
    );
}

#[test]
fn envelope_and_bid_policy() {
    let v = vectors();
    let net = hoodi_gloas();
    let env = get(&v, "execution_payload_envelope");
    let p = prep(env.request.clone(), &net).unwrap();
    let block = prep(get(&v, "block_v2_gloas").request.clone(), &net).unwrap();
    let Some(signing::SlashingCheck::Block { slot, block_root }) = block.slashing else {
        panic!("block check")
    };
    assert_eq!(
        p.slashing,
        Some(signing::SlashingCheck::OwnBlockPayload { slot, block_root })
    );

    let mut builder = env.request.clone();
    builder["execution_payload_envelope"]["data"]["builder_index"] = serde_json::json!("7");
    builder.as_object_mut().unwrap().remove("signingRoot");
    assert!(matches!(prep(builder, &net), Err(PrepareError::Refused(_))));

    let bid = serde_json::json!({"type": "EXECUTION_PAYLOAD_BID", "anything": [1, 2]});
    assert!(matches!(prep(bid, &net), Err(PrepareError::Refused(_))));
}

#[test]
fn builder_request_auth_data_bounds() {
    let v = vectors();
    let net = hoodi_gloas();
    let mut body = get(&v, "builder_request_auth").request.clone();
    body.as_object_mut().unwrap().remove("signingRoot");
    for (data, ok) in [
        ("0x".to_string(), false),
        (format!("0x{}", "ab".repeat(4096)), true),
        (format!("0x{}", "ab".repeat(4097)), false),
    ] {
        body["builder_request_auth"]["data"]["data"] = serde_json::json!(data);
        assert_eq!(
            prep(body.clone(), &net).is_ok(),
            ok,
            "{} bytes",
            data.len() / 2 - 1
        );
    }
}

#[test]
fn other_network_is_rejected() {
    let v = vectors();
    let req: SignRequest = serde_json::from_value(v.vectors[0].request.clone()).unwrap();
    assert!(signing::prepare(&req, &"mainnet".parse().unwrap(), &allow_all()).is_err());
}

#[test]
fn charon_keystores_decrypt() {
    let v = vectors();
    let keys = keystore::load_dir(&dir().join("keystores")).unwrap();
    assert_eq!(keys.len(), 1, "both keystores hold the same key");
    let pk = keys.keys().next().unwrap();
    assert_eq!(format!("0x{}", hex::encode(pk)), v.public_key);
}

fn app(data: &std::path::Path, policy: Policy) -> axum::Router {
    app_on(data, policy, hoodi_gloas())
}

fn app_on(data: &std::path::Path, policy: Policy, net: Network) -> axum::Router {
    app_with_clock(data, policy, net, None)
}

fn app_with_clock(
    data: &std::path::Path,
    policy: Policy,
    net: Network,
    clock: Option<Arc<TrustedClock>>,
) -> axum::Router {
    let state = AppState {
        keys: keystore::load_dir(&dir().join("keystores")).unwrap(),
        db: SlashingDb::open(&data.join("slashing"), net.genesis_validators_root).unwrap(),
        network: net,
        policy,
        tls_cert: None,
        platform: dvtee::platform::Platform::Tee,
        pins: None,
        roles: None,
        tokens: None,
        clock,
    };
    router(Arc::new(state))
}

async fn post(
    app: &axum::Router,
    pubkey: &str,
    body: &serde_json::Value,
    json: bool,
) -> (StatusCode, String) {
    let mut req = Request::post(format!("/api/v1/eth2/sign/{pubkey}"))
        .header("content-type", "application/json");
    if json {
        req = req.header("accept", "application/json");
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn http_api() {
    let v = vectors();
    let get = |name: &str| get(&v, name);
    let tmp = tempfile::tempdir().unwrap();
    let app = app(
        tmp.path(),
        Policy {
            allow_voluntary_exits: true,
            allow_deposits: false,
        },
    );
    let pk = &v.public_key;

    // publicKeys
    let resp = app
        .clone()
        .oneshot(
            Request::get("/api/v1/eth2/publicKeys")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Vec<String>>(&body).unwrap(),
        vec![pk.clone()]
    );

    // Plain-text and JSON responses.
    let att = get("attestation");
    let (s, b) = post(&app, pk, &att.request, false).await;
    assert_eq!((s, b.as_str()), (StatusCode::OK, att.signature.as_str()));
    let (s, b) = post(&app, pk, &att.request, true).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&b).unwrap()["signature"],
        att.signature
    );

    // Older attestation after a newer one is refused by slashing protection.
    let (s, _) = post(&app, pk, &get("attestation_previous_fork").request, false).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED);

    // Block: first sign ok, conflicting block at the same slot refused.
    let block = get("block_v2_fulu");
    assert_eq!(
        post(&app, pk, &block.request, false).await.0,
        StatusCode::OK
    );
    let mut conflicting = block.request.clone();
    conflicting["beacon_block"]["block_header"]["state_root"] =
        serde_json::json!(format!("0x{}", "ee".repeat(32)));
    conflicting.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(
        post(&app, pk, &conflicting, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );

    // Policy, unknown key, malformed input.
    assert_eq!(
        post(&app, pk, &get("deposit").request, false).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&app, pk, &get("voluntary_exit").request, false)
            .await
            .0,
        StatusCode::OK
    );
    let other = format!("0x{}", "aa".repeat(48));
    assert_eq!(
        post(&app, &other, &att.request, false).await.0,
        StatusCode::NOT_FOUND
    );
    let mut bad = att.request.clone();
    bad["type"] = serde_json::json!("BLOCK");
    assert_eq!(post(&app, pk, &bad, false).await.0, StatusCode::BAD_REQUEST);

    // Slashing protection survives a restart.
    drop(app);
    let app = self::app(tmp.path(), allow_all());
    assert_eq!(
        post(&app, pk, &conflicting, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );
    assert_eq!(
        post(&app, pk, &block.request, false).await.0,
        StatusCode::OK,
        "identical re-sign"
    );
}

#[tokio::test]
async fn http_api_gloas() {
    let v = vectors();
    let get = |name: &str| get(&v, name);
    let tmp = tempfile::tempdir().unwrap();
    let app = app(tmp.path(), Policy::default());
    let pk = &v.public_key;
    let env = get("execution_payload_envelope");
    let block = get("block_v2_gloas");

    // The envelope needs this key's block first.
    let (s, b) = post(&app, pk, &env.request, false).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "{b}");
    let (s, b) = post(&app, pk, &block.request, false).await;
    assert_eq!((s, b.as_str()), (StatusCode::OK, block.signature.as_str()));
    let (s, b) = post(&app, pk, &env.request, false).await;
    assert_eq!((s, b.as_str()), (StatusCode::OK, env.signature.as_str()));

    // An envelope for another block root at the same slot.
    let mut other = env.request.clone();
    other["execution_payload_envelope"]["data"]["beacon_block_root"] =
        serde_json::json!(format!("0x{}", "ee".repeat(32)));
    other.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(
        post(&app, pk, &other, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );

    // Refused outright: external builder envelopes and bids.
    let mut builder = env.request.clone();
    builder["execution_payload_envelope"]["data"]["builder_index"] = serde_json::json!("3");
    builder.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(
        post(&app, pk, &builder, false).await.0,
        StatusCode::FORBIDDEN
    );
    let bid = serde_json::json!({"type": "EXECUTION_PAYLOAD_BID", "execution_payload_bid": {}});
    assert_eq!(post(&app, pk, &bid, false).await.0, StatusCode::FORBIDDEN);

    for name in [
        "payload_attestation_message",
        "proposer_preferences_fork_boundary",
        "builder_request_auth",
        "aggregate_and_proof_v2_gloas",
        "attestation_gloas",
    ] {
        let vec = get(name);
        let (s, b) = post(&app, pk, &vec.request, true).await;
        assert_eq!(s, StatusCode::OK, "{name}: {b}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&b).unwrap()["signature"],
            vec.signature,
            "{name}"
        );
    }

    // A large envelope (8 MiB of transactions) fits the request size limit.
    let mut big = env.request.clone();
    big["execution_payload_envelope"]["data"]["payload"]["transactions"] =
        serde_json::json!([format!("0x{}", "ab".repeat(8 << 20))]);
    big.as_object_mut().unwrap().remove("signingRoot");
    assert_eq!(post(&app, pk, &big, false).await.0, StatusCode::OK);

    // Gloas types are refused on a network without Gloas scheduled.
    let tmp2 = tempfile::tempdir().unwrap();
    let hoodi_app = app_on(tmp2.path(), Policy::default(), hoodi());
    assert_eq!(
        post(&hoodi_app, pk, &block.request, false).await.0,
        StatusCode::BAD_REQUEST
    );
}

/// Client roles: each pinned certificate may only request what its
/// `knownClients` line grants.
#[tokio::test]
async fn client_roles() {
    use dvtee::tls::{ClientFingerprint, known_roles};

    let v = vectors();
    let tmp = tempfile::tempdir().unwrap();
    let (vc, ops, legacy) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let fp = |b: &[u8; 32]| {
        b.iter()
            .map(|x| format!("{x:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    let known = tmp.path().join("knownClients.txt");
    std::fs::write(
        &known,
        format!(
            "vc {} duties\nops {} exit\nold {}\n",
            fp(&vc),
            fp(&ops),
            fp(&legacy)
        ),
    )
    .unwrap();
    let roles = known_roles(&known).unwrap();

    let net = hoodi_gloas();
    let state = AppState {
        keys: keystore::load_dir(&dir().join("keystores")).unwrap(),
        db: SlashingDb::open(&tmp.path().join("slashing"), net.genesis_validators_root).unwrap(),
        network: net,
        policy: allow_all(),
        tls_cert: None,
        platform: dvtee::platform::Platform::Tee,
        pins: None,
        roles: Some(roles),
        tokens: None,
        clock: None,
    };
    let app = router(Arc::new(state));

    let send = |client: Option<[u8; 32]>, name: &str| {
        let app = app.clone();
        let body = get(&v, name).request.clone();
        let pk = v.public_key.clone();
        async move {
            let mut req = Request::post(format!("/api/v1/eth2/sign/{pk}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap();
            req.extensions_mut().insert(ClientFingerprint(client));
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        send(Some(vc), "voluntary_exit").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(Some(ops), "attestation").await, StatusCode::FORBIDDEN);
    assert_eq!(send(None, "attestation").await, StatusCode::FORBIDDEN);
    assert_eq!(
        send(Some([9u8; 32]), "attestation").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send(Some(vc), "attestation").await, StatusCode::OK);
    assert_eq!(send(Some(ops), "voluntary_exit").await, StatusCode::OK);
    // A line without roles keeps the old behaviour: duties and exits.
    assert_eq!(send(Some(legacy), "voluntary_exit").await, StatusCode::OK);
    // Nobody was granted deposits.
    assert_eq!(send(Some(legacy), "deposit").await, StatusCode::FORBIDDEN);
}

/// Bearer tokens: required on /api/v1/eth2/*, accepted as Bearer or as the
/// Basic password, answered with a Basic challenge, and carrying roles.
#[tokio::test]
async fn auth_tokens() {
    use dvtee::auth::Tokens;

    let v = vectors();
    let tmp = tempfile::tempdir().unwrap();
    let (vc, ops) = ("v".repeat(40), "o".repeat(40));
    let file = tmp.path().join("tokens");
    std::fs::write(&file, format!("vc {vc}\nops {ops} exit\n")).unwrap();

    let net = hoodi_gloas();
    let state = AppState {
        keys: keystore::load_dir(&dir().join("keystores")).unwrap(),
        db: SlashingDb::open(&tmp.path().join("slashing"), net.genesis_validators_root).unwrap(),
        network: net,
        policy: allow_all(),
        tls_cert: None,
        platform: dvtee::platform::Platform::Tee,
        pins: None,
        roles: None,
        tokens: Some(Tokens::load(&file).unwrap()),
        clock: None,
    };
    let app = router(Arc::new(state));

    let call = |auth: Option<String>, path: String, body: Option<serde_json::Value>| {
        let app = app.clone();
        async move {
            let mut req = match &body {
                Some(_) => Request::post(&path).header("content-type", "application/json"),
                None => Request::get(&path),
            };
            if let Some(a) = auth {
                req = req.header("authorization", a);
            }
            let body = body.map_or(Body::empty(), |b| Body::from(b.to_string()));
            app.oneshot(req.body(body).unwrap()).await.unwrap()
        }
    };
    let basic = |user: &str, pass: &str| {
        // Base64 of "user:pass" for ASCII input.
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let input = format!("{user}:{pass}");
        let mut out = String::new();
        for c in input.as_bytes().chunks(3) {
            let n = (c[0] as u32) << 16
                | (*c.get(1).unwrap_or(&0) as u32) << 8
                | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                if i <= c.len() {
                    out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        format!("Basic {out}")
    };
    let sign = format!("/api/v1/eth2/sign/{}", v.public_key);
    let att = get(&v, "attestation").request.clone();
    let exit = get(&v, "voluntary_exit").request.clone();

    // Health and evidence stay open.
    assert_eq!(
        call(None, "/upcheck".into(), None).await.status(),
        StatusCode::OK
    );

    let r = call(None, "/api/v1/eth2/publicKeys".into(), None).await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    assert!(
        r.headers()["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Basic")
    );
    let r = call(
        Some(format!("Bearer {}", "x".repeat(40))),
        sign.clone(),
        Some(att.clone()),
    )
    .await;
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let r = call(
        Some(format!("Bearer {vc}")),
        "/api/v1/eth2/publicKeys".into(),
        None,
    )
    .await;
    assert_eq!(r.status(), StatusCode::OK);
    let r = call(Some(basic("vc", &vc)), sign.clone(), Some(att.clone())).await;
    assert_eq!(r.status(), StatusCode::OK);
    // The Basic username is ignored; only the token counts.
    let r = call(Some(basic("anything", &vc)), sign.clone(), Some(att)).await;
    assert_eq!(r.status(), StatusCode::OK);

    // Roles: the duties token can't exit, the exit token can.
    let r = call(Some(basic("vc", &vc)), sign.clone(), Some(exit.clone())).await;
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let r = call(Some(format!("Bearer {ops}")), sign, Some(exit)).await;
    assert_eq!(r.status(), StatusCode::OK);
}

/// The start floor and horizon sit in front of the slashing database.
#[tokio::test]
async fn http_anti_rollback() {
    let v = vectors();
    let pk = &v.public_key;
    let att = get(&v, "attestation"); // source 50688, target 50690
    let randao = get(&v, "randao_reveal");
    let mut net = hoodi_gloas();
    net.genesis_time = Some(1742213400);
    let at = |epoch: u64| 1742213400 + epoch * 384 + 10;
    let new_clock = || {
        Arc::new(TrustedClock::new(&net, 1, Duration::from_secs(288), || Duration::ZERO).unwrap())
    };
    let tmp = tempfile::tempdir().unwrap();
    let watermark = tmp
        .path()
        .join("slashing")
        .join(format!("{}.json", pk.trim_start_matches("0x")));

    // No trusted time yet: slashable kinds wait, others are signed.
    let clock = new_clock();
    let app = app_with_clock(tmp.path(), allow_all(), net.clone(), Some(clock.clone()));
    let (s, b) = post(&app, pk, &att.request, false).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(
        post(&app, pk, &randao.request, false).await.0,
        StatusCode::OK
    );

    // Started during epoch 50689: floor 50691 covers target 50690.
    let b = Bounds {
        earliest: at(50689),
        latest: at(50689),
        agreeing: 3,
    };
    assert_eq!(clock.update(b), 50691);
    let (s, b) = post(&app, pk, &att.request, false).await;
    assert_eq!(s, StatusCode::PRECONDITION_FAILED, "{b}");
    assert!(b.contains("start floor"), "{b}");
    assert!(!watermark.exists(), "a refused request moved the watermark");

    // Started during epoch 50687 (floor 50689), now in 50689 (horizon 50690).
    let clock = new_clock();
    clock.update(Bounds {
        earliest: at(50687),
        latest: at(50687),
        agreeing: 3,
    });
    let app = app_with_clock(tmp.path(), allow_all(), net.clone(), Some(clock.clone()));
    assert_eq!(
        post(&app, pk, &att.request, false).await.0,
        StatusCode::PRECONDITION_FAILED
    );
    clock.update(Bounds {
        earliest: at(50689),
        latest: at(50689),
        agreeing: 3,
    });
    let (s, b) = post(&app, pk, &att.request, false).await;
    assert_eq!((s, b.as_str()), (StatusCode::OK, att.signature.as_str()));
    assert!(watermark.exists());
}
