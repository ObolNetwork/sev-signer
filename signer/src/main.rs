use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

use dvtee::anti_rollback::{self, TrustedClock};
use dvtee::api::{self, AppState};
use dvtee::network::{self, Network};
use dvtee::pins::Pins;
use dvtee::platform::{PlatformArgs, SnpKeyParams};
use dvtee::signing::Policy;
use dvtee::slashing::SlashingDb;
use dvtee::{keystore, snp, tee, tls};

/// Web3Signer-compatible BLS remote signer designed to run inside a
/// confidential VM (AMD SEV-SNP today; Intel TDX / Arm CCA via configfs-tsm).
#[derive(Parser)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve the signing API.
    Serve(Box<ServeArgs>),
    /// Print the slashing protection database as EIP-3076 interchange JSON.
    SlashingExport {
        #[arg(long, env = "DVTEE_DATA_DIR", default_value = "/var/lib/dvtee")]
        data_dir: PathBuf,
        #[command(flatten)]
        network: NetworkArgs,
    },
    /// Write a 32-byte sealing key for PURPOSE to stdout, e.g. for
    /// `cryptsetup open --key-file=-`. On SEV-SNP it is derived from the
    /// chip's VCEK, the launch measurement, the guest policy and a pinned
    /// minimum TCB, so only the same measured image on the same chip gets it.
    SealingKey {
        #[arg(long, default_value = "data-disk")]
        purpose: String,
        /// Minimum TCB_VERSION mixed into the SNP key, as the raw 64-bit hex
        /// value from an attestation report (its encoding varies by CPU
        /// generation). Required for --platform tee.
        #[arg(long, env = "DVTEE_SNP_MIN_TCB", value_parser = parse_hex_u64)]
        snp_min_tcb: Option<u64>,
        /// VMPL mixed into the SNP key; must be >= the guest's own VMPL.
        #[arg(long, env = "DVTEE_SNP_VMPL", default_value_t = 0)]
        snp_vmpl: u32,
        #[command(flatten)]
        platform: PlatformArgs,
    },
    /// Offline check of evidence fetched from /api/v1/tee/attestation. For
    /// SEV-SNP: the AMD chain (pinned ARK -> ASK -> VCEK), the report
    /// signature, the VCEK's TCB and chip id, guest policy, VMPL, a minimum
    /// TCB, the measurement and the REPORT_DATA binding. For TDX only the
    /// binding, debug bit and measurement, and only with
    /// --allow-unverified-tdx (the quote signature is not checked).
    VerifyEvidence(VerifyArgs),
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// JSON response saved from /api/v1/tee/attestation.
    #[arg(long)]
    evidence: PathBuf,
    /// The nonce you sent, hex.
    #[arg(long)]
    nonce: String,
    /// Expected launch measurement, hex (from sev-snp-measure / MRTD).
    #[arg(long)]
    expected_measurement: Option<String>,
    /// Expected cluster lock hash, hex: the signer must be pinned to this
    /// lock (compare with your own cluster-lock.json's lock_hash).
    #[arg(long)]
    expected_cluster_lock_hash: Option<String>,
    /// SEV-SNP: the VCEK (or VLEK), DER or PEM. Default: the certificate
    /// table in the evidence's auxblob, if the host provisioned one.
    #[arg(long)]
    vcek: Option<PathBuf>,
    /// SEV-SNP: fetch the VCEK from AMD's KDS (kdsintf.amd.com) for the
    /// report's chip id and reported TCB. The only network access; the
    /// certificate is still checked against the pinned AMD roots.
    #[arg(long, conflicts_with = "vcek")]
    fetch_vcek: bool,
    /// SEV-SNP: minimum TCB_VERSION, raw 64-bit hex, the same value as
    /// `sealing-key --snp-min-tcb`. Checked per component against the
    /// reported and committed TCB.
    #[arg(long, value_parser = parse_hex_u64)]
    min_tcb: Option<u64>,
    /// SEV-SNP: VMPL the report must come from.
    #[arg(long, default_value_t = 0)]
    expected_vmpl: u32,
    /// SEV-SNP: fail if SMT is enabled on the host.
    #[arg(long)]
    deny_smt: bool,
    /// Accept `insecure_dev` evidence (development and e2e tests only).
    #[arg(long)]
    allow_insecure_dev: bool,
    /// Accept TDX evidence after only the binding, debug and measurement
    /// checks. Its quote signature is not verified here (use Intel DCAP),
    /// and the provider label comes from the evidence itself.
    #[arg(long)]
    allow_unverified_tdx: bool,
}

#[derive(clap::Args)]
struct NetworkArgs {
    /// Network to sign for, as Web3Signer and Teku take it: a preset name
    /// (mainnet, hoodi, sepolia) or the path of a consensus config.yaml with
    /// the fork schedule (e.g. a devnet's network-configs/config.yaml). A
    /// config file needs --genesis-validators-root. The older
    /// custom:<gvr>:<genesis_fork>:<capella_fork> form still works but has no
    /// fork schedule, so Gloas request types are refused on it.
    #[arg(long, env = "DVTEE_NETWORK", value_name = "NAME|CONFIG.YAML")]
    network: String,
    /// Genesis validators root, hex. Required with a config.yaml --network,
    /// because the config file doesn't contain it.
    #[arg(long, env = "DVTEE_GENESIS_VALIDATORS_ROOT")]
    genesis_validators_root: Option<String>,
    /// Genesis time (Unix seconds) of a config.yaml or custom: network, for
    /// the anti-rollback start floor. Presets know their own.
    #[arg(long, env = "DVTEE_GENESIS_TIME")]
    genesis_time: Option<u64>,
}

impl NetworkArgs {
    fn resolve(&self) -> anyhow::Result<Network> {
        let is_file = self.network.contains(std::path::MAIN_SEPARATOR)
            || self.network.contains('/')
            || self.network.ends_with(".yaml")
            || self.network.ends_with(".yml");
        let mut network = self.resolve_inner(is_file)?;
        match network.public_preset() {
            // A config.yaml or custom: form of a public network keeps the
            // preset's timing: the start floor must not depend on flags.
            Some(p) => {
                if self.genesis_time.is_some_and(|t| Some(t) != p.genesis_time) {
                    bail!("--genesis-time differs from {}'s genesis time", p.name);
                }
                if network.slot_duration_ms != p.slot_duration_ms {
                    bail!("the slot duration differs from {}'s", p.name);
                }
                network.genesis_time = p.genesis_time;
            }
            None => network.genesis_time = self.genesis_time,
        }
        Ok(network)
    }

    fn resolve_inner(&self, is_file: bool) -> anyhow::Result<Network> {
        if !is_file {
            if self.genesis_validators_root.is_some() {
                bail!("--genesis-validators-root is only used with a config.yaml --network");
            }
            return self.network.parse::<Network>().map_err(anyhow::Error::msg);
        }
        let Some(gvr) = &self.genesis_validators_root else {
            bail!(
                "--network {} is a config file; it needs --genesis-validators-root",
                self.network
            );
        };
        let gvr = network::parse_root(gvr).map_err(anyhow::Error::msg)?;
        let cfg = std::fs::read_to_string(&self.network)
            .with_context(|| format!("reading {}", self.network))?;
        Network::from_config_yaml(&cfg, gvr).map_err(|e| anyhow::anyhow!("{}: {e}", self.network))
    }
}

#[derive(clap::Args)]
struct ServeArgs {
    #[arg(long, env = "DVTEE_LISTEN", default_value = "127.0.0.1:9000")]
    listen: SocketAddr,
    /// Holds the slashing protection database and TLS key. Must be on the
    /// encrypted, measured disk in a TEE deployment.
    #[arg(long, env = "DVTEE_DATA_DIR", default_value = "/var/lib/dvtee")]
    data_dir: PathBuf,
    /// EIP-2335 keystores with sibling .txt password files (charon's
    /// validator_keys layout).
    #[arg(long, env = "DVTEE_KEYSTORES_DIR")]
    keystores_dir: PathBuf,
    #[command(flatten)]
    network: NetworkArgs,
    /// Serve plain HTTP. Only for development: TLS must terminate inside the
    /// TEE for attestation to mean anything.
    #[arg(long, env = "DVTEE_INSECURE_HTTP")]
    insecure_http: bool,
    /// Subject alternative names for the generated TLS certificate.
    #[arg(long = "tls-san", env = "DVTEE_TLS_SANS", value_delimiter = ',', default_values_t = ["localhost".to_string(), "127.0.0.1".to_string()])]
    tls_sans: Vec<String>,
    /// Require client certificates whose SHA-256 fingerprints are listed in
    /// this file (Web3Signer knownClients format).
    #[arg(long, env = "DVTEE_TLS_KNOWN_CLIENTS")]
    tls_known_clients: Option<PathBuf>,
    /// Bearer tokens required on /api/v1/eth2/*, one per line:
    /// `<name> <token> [roles]` (roles as in knownClients, default `duties`).
    /// Validator clients send one as the password in the signer URL
    /// (`https://vc:<token>@host:port`) or as `Authorization: Bearer`.
    #[arg(long, env = "DVTEE_AUTH_TOKEN_FILE")]
    auth_token_file: Option<PathBuf>,
    /// Second TLS listener serving only /upcheck, /healthcheck and
    /// /api/v1/tee/attestation, without client certificates, so peers and
    /// monitoring can fetch evidence while signing stays behind mTLS.
    #[arg(long, env = "DVTEE_PUBLIC_LISTEN")]
    public_listen: Option<SocketAddr>,
    #[arg(long, env = "DVTEE_ALLOW_VOLUNTARY_EXITS", default_value_t = true, action = clap::ArgAction::Set)]
    allow_voluntary_exits: bool,
    #[arg(long, env = "DVTEE_ALLOW_DEPOSITS", default_value_t = false, action = clap::ArgAction::Set)]
    allow_deposits: bool,
    /// Charon cluster-lock.json to pin on first start. The signer checks it,
    /// requires every loaded key to be one of its public shares (at one
    /// operator index), stores it in the data directory and from then on
    /// refuses any other lock. Fee recipients in registrations, proposer
    /// preferences and self-built payloads must match it. Optional once
    /// pinned.
    #[arg(long, env = "DVTEE_CLUSTER_LOCK")]
    cluster_lock: Option<PathBuf>,
    /// Anti-rollback start floor and horizon from Roughtime (see README).
    /// Defaults to on for mainnet, hoodi and sepolia, and off for devnets. It
    /// can only be turned off for a public network in an insecure-dev build.
    #[arg(long, env = "DVTEE_ANTI_ROLLBACK", action = clap::ArgAction::Set)]
    anti_rollback: Option<bool>,
    /// k: never sign a block or attestation more than k epochs ahead of
    /// trusted time. After a start, everything up to epoch clock + k + 1 is
    /// refused.
    #[arg(long, env = "DVTEE_ANTI_ROLLBACK_EPOCHS", default_value_t = 1,
          value_parser = clap::value_parser!(u64).range(1..=anti_rollback::MAX_K))]
    anti_rollback_epochs: u64,
    /// Roughtime servers as BASE64KEY@host:port (comma-separated). Defaults
    /// to five independent public servers.
    #[arg(
        long = "roughtime-server",
        env = "DVTEE_ROUGHTIME_SERVERS",
        value_delimiter = ','
    )]
    roughtime_servers: Vec<anti_rollback::Server>,
    /// How many servers must agree.
    #[arg(long, env = "DVTEE_ROUGHTIME_QUORUM", default_value_t = 3)]
    roughtime_quorum: usize,
    /// Maximum spread of the agreeing servers' times, seconds.
    #[arg(long, env = "DVTEE_ROUGHTIME_TOLERANCE", default_value_t = 10)]
    roughtime_tolerance: u64,
    /// EIP-3076 interchange file to import before serving.
    #[arg(long, env = "DVTEE_SLASHING_PROTECTION_IMPORT")]
    slashing_protection_import: Option<PathBuf>,
    #[arg(long, env = "DVTEE_LOG_JSON")]
    log_json: bool,
    #[command(flatten)]
    platform: PlatformArgs,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve(args) => {
            init_logging(args.log_json);
            tokio::runtime::Runtime::new()?.block_on(serve(*args))
        }
        Cmd::SlashingExport { data_dir, network } => {
            let network = network.resolve()?;
            let db = SlashingDb::open(&data_dir.join("slashing"), network.genesis_validators_root)?;
            println!("{}", serde_json::to_string_pretty(&db.export()?)?);
            Ok(())
        }
        Cmd::SealingKey {
            purpose,
            snp_min_tcb,
            snp_vmpl,
            platform,
        } => {
            use std::io::{IsTerminal, Write};
            let platform = platform.build()?;
            let snp = snp_min_tcb.map(|min_tcb| SnpKeyParams {
                min_tcb,
                vmpl: snp_vmpl,
            });
            let key = platform.sealing_key(&purpose, snp)?;
            let mut out = std::io::stdout();
            if out.is_terminal() {
                bail!("refusing to write a raw key to a terminal; pipe it to cryptsetup");
            }
            out.write_all(key.as_ref())?;
            Ok(())
        }
        Cmd::VerifyEvidence(args) => verify_evidence(&args),
    }
}

fn parse_hex_u64(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn init_logging(json: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let fmt = tracing_subscriber::fmt().with_env_filter(filter);
    if json {
        fmt.json().init();
    } else {
        use std::io::IsTerminal;
        fmt.with_ansi(std::io::stdout().is_terminal()).init();
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let network = args.network.resolve()?;
    let clock = anti_rollback_clock(&args, &network)?;
    let platform = args.platform.build()?;
    if platform.is_insecure() {
        refuse_mainnet(&network)?;
        tracing::warn!(
            "INSECURE-DEV PLATFORM: no TEE, keys are readable by the host, evidence is unsigned. \
             Development and testing only."
        );
    }

    let keys = keystore::load_dir(&args.keystores_dir)?;
    if keys.is_empty() {
        bail!("no keystores found in {}", args.keystores_dir.display());
    }

    let key_list: Vec<[u8; 48]> = keys.keys().copied().collect();
    let pins = Pins::load_or_pin(&args.data_dir, args.cluster_lock.as_deref(), &key_list)?;
    match &pins {
        Some(p) => tracing::info!(
            lock_hash = %format!("0x{}", hex::encode(p.lock_hash)),
            operator_index = p.operator_index,
            validators = p.validators,
            "pinned to cluster lock: fee recipients are fixed"
        ),
        None if platform.is_insecure() => {}
        None => tracing::warn!(
            "no cluster lock pinned (--cluster-lock): fee recipients are not checked"
        ),
    }

    let db = SlashingDb::open(
        &args.data_dir.join("slashing"),
        network.genesis_validators_root,
    )?;
    if let Some(path) = &args.slashing_protection_import {
        let n = db.import(&std::fs::read(path)?)?;
        tracing::info!(entries = n, path = %path.display(), "imported slashing protection");
    }

    let tls = if args.insecure_http {
        tracing::warn!("serving plain HTTP: attestation is disabled and traffic is unprotected");
        None
    } else {
        Some(tls::load_or_generate(
            &args.data_dir.join("tls"),
            &args.tls_sans,
            args.tls_known_clients.as_deref(),
        )?)
    };

    let tokens = match &args.auth_token_file {
        Some(path) => {
            let t = dvtee::auth::Tokens::load(path)?;
            if tls.is_none() {
                tracing::warn!("auth tokens over plain HTTP are visible to the network");
            }
            Some(t)
        }
        None => None,
    };

    let state = Arc::new(AppState {
        keys,
        db,
        network: network.clone(),
        policy: Policy {
            allow_voluntary_exits: args.allow_voluntary_exits,
            allow_deposits: args.allow_deposits,
        },
        tls_cert: tls
            .as_ref()
            .map(|m| (m.cert_der.clone(), m.cert_pem.clone())),
        platform,
        pins,
        roles: tls.as_ref().and_then(|m| m.roles.clone()),
        tokens,
        clock,
    });
    let app = api::router(state.clone()).layer(tower_http::trace::TraceLayer::new_for_http());

    tracing::info!(
        listen = %args.listen,
        network = %network.name,
        gloas_epoch = ?network
            .forks
            .iter()
            .find(|f| f.name == network::ForkName::Gloas && f.epoch != network::FAR_FUTURE_EPOCH)
            .map(|f| f.epoch),
        keys = state.keys.len(),
        tls = tls.is_some(),
        mtls = args.tls_known_clients.is_some(),
        tokens = state.tokens.as_ref().map_or(0, |t| t.len()),
        "dvtee serving"
    );

    let handle = axum_server::Handle::new();
    let h = handle.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        tracing::info!("shutting down");
        h.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    });

    if args.public_listen.is_some() && tls.is_none() {
        bail!("--public-listen requires TLS (it serves attestation evidence bound to the TLS key)");
    }
    match tls {
        Some(m) => {
            if let Some(addr) = args.public_listen {
                let public = api::public_router(state.clone())
                    .layer(tower_http::trace::TraceLayer::new_for_http());
                let cfg = axum_server::tls_rustls::RustlsConfig::from_config(m.public_config);
                let h = handle.clone();
                tracing::info!(listen = %addr, "public listener (health, attestation)");
                tokio::spawn(async move {
                    if let Err(e) = axum_server::bind_rustls(addr, cfg)
                        .handle(h)
                        .serve(public.into_make_service())
                        .await
                    {
                        tracing::error!(error = %e, "public listener failed");
                    }
                });
            }
            axum_server::bind(args.listen)
                .acceptor(tls::IdentifyingAcceptor::new(m.config))
                .handle(handle)
                .serve(app.into_make_service())
                .await?
        }
        None => {
            axum_server::bind(args.listen)
                .handle(handle)
                .serve(app.into_make_service())
                .await?
        }
    }
    Ok(())
}

/// Starts the trusted-time thread, if anti-rollback is on. Slashable requests
/// are refused until the first quorum reading sets the start floor.
fn anti_rollback_clock(
    args: &ServeArgs,
    network: &Network,
) -> anyhow::Result<Option<Arc<TrustedClock>>> {
    let enabled = args.anti_rollback.unwrap_or(network.is_public());
    if !enabled {
        if network.is_public() && !cfg!(feature = "insecure-dev") {
            bail!("--anti-rollback can only be turned off on devnets or in insecure-dev builds");
        }
        tracing::warn!(
            "anti-rollback is off: a restored disk snapshot can roll back slashing protection"
        );
        return Ok(None);
    }

    let servers = if args.roughtime_servers.is_empty() {
        anti_rollback::default_servers()
    } else {
        args.roughtime_servers.clone()
    };
    anti_rollback::check_distinct(&servers).map_err(anyhow::Error::msg)?;
    let quorum = args.roughtime_quorum;
    if quorum == 0 || quorum > servers.len() {
        bail!(
            "--roughtime-quorum must be between 1 and the number of servers ({})",
            servers.len()
        );
    }
    if quorum < 2 && network.is_public() {
        bail!("--roughtime-quorum must be at least 2 on a public network");
    }
    let epoch = Duration::from_millis(network.epoch_duration_ms());
    // Re-query every quarter epoch. A reading is used for at most three
    // quarters of an epoch of guest time, so with k = 1 the horizon always
    // covers the current epoch while the quorum answers.
    let refresh = epoch / 4;
    let max_age = epoch * 3 / 4;
    let clock = Arc::new(
        TrustedClock::with_monotonic_clock(network, args.anti_rollback_epochs, max_age)
            .map_err(anyhow::Error::msg)?,
    );
    let settings = anti_rollback::Settings {
        servers,
        quorum,
        tolerance: args.roughtime_tolerance,
        timeout: Duration::from_secs(3),
    };
    tracing::info!(
        servers = settings.servers.len(),
        quorum,
        k = args.anti_rollback_epochs,
        "anti-rollback on: blocks and attestations wait for trusted time"
    );
    anti_rollback::spawn(
        clock.clone(),
        settings,
        Arc::new(anti_rollback::Udp),
        refresh,
    );
    Ok(Some(clock))
}

/// SIGINT or SIGTERM. Containers send SIGTERM, and as PID 1 the signer gets
/// no default handler for it.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut term) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = term.recv() => {}
                }
                return;
            }
            Err(e) => tracing::warn!(error = %e, "cannot listen for SIGTERM"),
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// The insecure platform must never hold mainnet keys. Checked by genesis
/// validators root and fork version, so `custom:` cannot get around it.
fn refuse_mainnet(network: &Network) -> anyhow::Result<()> {
    let mainnet = Network::presets()
        .into_iter()
        .find(|n| n.name == "mainnet")
        .expect("mainnet preset");
    if network.genesis_validators_root == mainnet.genesis_validators_root
        || network.genesis_fork_version == mainnet.genesis_fork_version
    {
        bail!("the insecure-dev platform refuses to run on mainnet");
    }
    Ok(())
}

fn verify_evidence(args: &VerifyArgs) -> anyhow::Result<()> {
    use rustls::pki_types::pem::PemObject;

    let ev: serde_json::Value = serde_json::from_slice(&std::fs::read(&args.evidence)?)?;
    let field = |k: &str| {
        ev[k]
            .as_str()
            .with_context(|| format!("evidence is missing {k}"))
    };
    let unhex = |s: &str| hex::decode(s.trim_start_matches("0x")).context("bad hex");

    let provider = field("provider")?;
    let report = unhex(field("report")?)?;
    let nonce: [u8; 32] = unhex(&args.nonce)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("nonce must be 32 bytes"))?;
    let cert =
        rustls::pki_types::CertificateDer::from_pem_slice(field("tls_certificate")?.as_bytes())?;
    let pubkeys: Vec<[u8; 48]> = ev["pubkeys"]
        .as_array()
        .context("evidence is missing pubkeys")?
        .iter()
        .map(|v| {
            let b = unhex(v.as_str().unwrap_or_default())?;
            b.try_into().map_err(|_| anyhow::anyhow!("bad pubkey"))
        })
        .collect::<anyhow::Result<_>>()?;
    let expected = args
        .expected_measurement
        .as_deref()
        .map(&unhex)
        .transpose()?;
    let lock_hash: Option<[u8; 32]> = match ev["cluster_lock_hash"].as_str() {
        Some(h) => Some(
            unhex(h)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("cluster_lock_hash must be 32 bytes"))?,
        ),
        None => None,
    };
    let expected_rd = tee::report_data(&nonce, &cert, &pubkeys, lock_hash.as_ref());

    println!("provider:            {provider}");
    println!(
        "tls cert sha256:     {}",
        hex::encode(Sha256::digest(&cert))
    );
    println!("bls pubkeys:         {}", pubkeys.len());
    match &lock_hash {
        Some(h) => println!("cluster lock hash:   0x{}", hex::encode(h)),
        None => println!("cluster lock hash:   none (signer not pinned to a lock)"),
    }
    // The hash is bound into REPORT_DATA above; this checks it is the lock
    // the verifier expects.
    let mut lock_ok = true;
    if let Some(exp) = &args.expected_cluster_lock_hash {
        let exp = exp.trim_start_matches("0x").to_ascii_lowercase();
        match &lock_hash {
            Some(h) if hex::encode(h) == exp => println!("cluster lock:        OK"),
            _ => {
                println!("cluster lock:        MISMATCH (expected 0x{exp})");
                lock_ok = false;
            }
        }
    }

    if provider == "sev_guest" {
        let auxblob = ev["auxblob"].as_str().map(unhex).transpose()?;
        let leaf = snp_leaf(args, &report, auxblob.as_deref())?;
        let expect = snp::Expect {
            report_data: Some(expected_rd),
            measurement: expected
                .map(|m| m.try_into())
                .transpose()
                .map_err(|_| anyhow::anyhow!("--expected-measurement must be 48 bytes"))?,
            min_tcb: args.min_tcb,
            vmpl: args.expected_vmpl,
            deny_smt: args.deny_smt,
            now: std::time::SystemTime::now(),
        };
        let out = snp::verify(&report, leaf.as_deref(), &snp::amd_anchors(), &expect);
        for l in &out.lines {
            let detail = match (l.status, l.detail.as_str()) {
                (snp::Status::Ok, "") => "OK".to_string(),
                (snp::Status::Ok, d) => format!("OK ({d})"),
                (snp::Status::Fail, d) => format!("FAIL ({d})"),
                (snp::Status::Info, d) => d.to_string(),
            };
            println!("{:<20} {detail}", format!("{}:", l.name));
        }
        if !out.ok() || !lock_ok {
            bail!("evidence verification failed");
        }
        return Ok(());
    }

    let layout =
        tee::layout(provider).with_context(|| format!("unsupported provider {provider}"))?;
    let actual_rd = report
        .get(layout.report_data..layout.report_data + 64)
        .context("report too short")?;
    let (m_off, m_len) = layout.measurement;
    let measurement = report
        .get(m_off..m_off + m_len)
        .context("report too short")?;
    println!(
        "{:<20} {}",
        format!("{}:", layout.measurement_name),
        hex::encode(measurement)
    );

    let mut ok = lock_ok;
    if actual_rd == expected_rd {
        println!("report_data binding: OK");
    } else {
        println!("report_data binding: MISMATCH");
        ok = false;
    }
    if provider == "insecure_dev" {
        if args.allow_insecure_dev {
            println!("platform:            INSECURE DEV (accepted by --allow-insecure-dev)");
        } else {
            println!("platform:            FAIL (insecure_dev evidence: no TEE, unsigned)");
            ok = false;
        }
    } else {
        match tee::tdx_debug(&report) {
            Some(false) => println!("debug policy:        OK (debug disabled)"),
            Some(true) => {
                println!(
                    "debug policy:        FAIL (guest is debuggable; host can read its memory)"
                );
                ok = false;
            }
            None => println!("debug policy:        unknown"),
        }
    }
    match &expected {
        Some(exp) if exp.as_slice() == measurement => println!("measurement:         OK"),
        Some(exp) => {
            println!(
                "measurement:         MISMATCH (expected {})",
                hex::encode(exp)
            );
            ok = false;
        }
        None => println!("measurement:         not checked (pass --expected-measurement)"),
    }
    if provider == "tdx_guest" {
        if args.allow_unverified_tdx {
            println!("quote signature:     NOT VERIFIED (accepted by --allow-unverified-tdx)");
        } else {
            println!(
                "quote signature:     FAIL (TDX quotes are not verified here; use Intel DCAP)"
            );
            ok = false;
        }
    }
    if !ok {
        bail!("evidence verification failed");
    }
    Ok(())
}

/// The VCEK/VLEK for an SNP report: --vcek, else the evidence's certificate
/// table, else KDS with --fetch-vcek. None if none of these has it.
fn snp_leaf(
    args: &VerifyArgs,
    report: &[u8],
    auxblob: Option<&[u8]>,
) -> anyhow::Result<Option<Vec<u8>>> {
    if let Some(path) = &args.vcek {
        let b = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
        println!("vcek:                {}", path.display());
        return Ok(Some(snp::pem_to_der(&b).unwrap_or(b)));
    }
    // A report that doesn't parse fails in snp::verify with the reason.
    let Ok(r) = snp::Report::parse(report) else {
        return Ok(None);
    };
    let key = r.signing_key().unwrap_or(snp::SigningKey::Vcek);
    if let Some(aux) = auxblob {
        match snp::leaf_from_cert_table(aux, key) {
            Ok(Some(leaf)) => {
                println!("vcek:                from the evidence's certificate table");
                return Ok(Some(leaf));
            }
            Ok(None) => println!("vcek:                not in the evidence's certificate table"),
            Err(e) => println!("vcek:                bad certificate table in evidence: {e}"),
        }
    }
    let url = snp::report_product(&r).map(|p| {
        let tcb = snp::Tcb::decode(r.reported_tcb, p);
        snp::kds_vcek_url(p, &r.chip_id, &tcb)
    });
    match (&url, args.fetch_vcek) {
        _ if key == snp::SigningKey::Vlek => Ok(None),
        (Some(url), true) => {
            println!("vcek:                fetching {url}");
            Ok(Some(kds_get(url)?))
        }
        (None, true) => bail!(
            "report v{} has no CPUID, so the KDS product is unknown; download the VCEK and pass --vcek",
            r.version
        ),
        (Some(url), false) => {
            println!(
                "vcek:                none (pass --fetch-vcek, or download {url} and pass --vcek)"
            );
            Ok(None)
        }
        (None, false) => Ok(None),
    }
}

/// HTTPS GET of a KDS certificate. The certificate is verified against the
/// pinned AMD roots afterwards, so TLS here only guards availability.
fn kds_get(url: &str) -> anyhow::Result<Vec<u8>> {
    use std::io::{Read, Write};

    let rest = url
        .strip_prefix("https://")
        .context("KDS URL must be https")?;
    let (host, path) = rest.split_once('/').context("bad KDS URL")?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    if roots.is_empty() {
        bail!("no system CA certificates to reach {host}");
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(config), name)?;
    let sock = std::net::TcpStream::connect((host, 443))?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut tls = rustls::StreamOwned::new(conn, sock);
    write!(
        tls,
        "GET /{path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/octet-stream\r\nUser-Agent: dvtee\r\n\r\n"
    )?;
    let mut resp = Vec::new();
    // HTTP/1.0: the body ends when the server closes the connection.
    match tls.take(1 << 20).read_to_end(&mut resp) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !resp.is_empty() => {}
        Err(e) => return Err(e).context("reading from KDS"),
    }
    let split = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("bad HTTP response from KDS")?;
    let head = String::from_utf8_lossy(&resp[..split]);
    let status = head.lines().next().unwrap_or_default();
    if status.split_whitespace().nth(1) != Some("200") {
        bail!("KDS answered {status} (it rate limits; retry later or pass --vcek)");
    }
    Ok(resp[split + 4..].to_vec())
}
