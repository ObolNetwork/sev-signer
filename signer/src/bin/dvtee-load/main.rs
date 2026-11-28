//! Load test for dvtee. See `docs/load-test.md`.
//!
//! `run` starts the real `dvtee` binary on generated test keys (or uses
//! `--url`) and drives its HTTP API with one charon DV signer's per-slot duty
//! mix on a compressed slot clock, then reports latency per kind and whether
//! every kind stayed under the budget.
//!
//! `micro` times BLS signing and slashing-database writes in-process, alone
//! and in bursts, to split the end-to-end time into its parts.

mod client;
mod duties;
mod keys;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use hyper::body::Bytes;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use duties::{Kind, Mix, PHASES, Schedule};
use dvtee::network::Network;
use dvtee::signing::{Policy, SignRequest, SlashingCheck};
use dvtee::slashing::SlashingDb;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Parser)]
#[command(about = "Load test for dvtee (test keys only; see docs/load-test.md)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a signer (or use --url) and drive it with the per-slot duty mix.
    Run(Box<RunArgs>),
    /// Time BLS signing and slashing-database writes in-process.
    Micro(MicroArgs),
    /// Log disk sync stalls once a second: in-place overwrite + fdatasync of
    /// a preallocated file (no journal commit on ext4), and the signer's
    /// create + fsync + rename + directory fsync. Run it next to `run`.
    Probe {
        #[arg(long, default_value = "load-test-work")]
        dir: PathBuf,
        #[arg(long, default_value_t = 300)]
        secs: u64,
    },
    /// Write the load-test devnet's config.yaml and genesis-validators-root
    /// to OUT, for provisioning a signer that `run --url` will drive.
    DevnetConfig {
        #[arg(long, default_value = "hoodi")]
        network: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write N test keystores (pbkdf2, one iteration) to WORK_DIR/keys-N.
    Keygen {
        #[arg(long)]
        keys: usize,
        #[arg(long, default_value = "load-test-work")]
        work_dir: PathBuf,
    },
}

#[derive(Args)]
struct RunArgs {
    /// Keys to load into the signer. Each key attests once per epoch, so the
    /// realistic mix has KEYS/32 attestations per slot.
    #[arg(long)]
    keys: Option<usize>,
    /// Stress mode: this many keys attest in every simulated slot (each
    /// simulated slot is a new epoch). The rest of the mix scales with it.
    #[arg(long)]
    attesters_per_slot: Option<usize>,
    /// Measured epochs (simulated slots / 32).
    #[arg(long, default_value_t = 2)]
    epochs: usize,
    /// Simulated slots before measuring. Default 32: every key's watermark
    /// file exists, and the writeback of creating them is behind us.
    #[arg(long)]
    warmup_slots: Option<usize>,
    /// Simulated slot length. Duties start at 0, 1/3 and 2/3 of it. A 12 s
    /// mainnet slot has 4 s between bursts; any length works as long as each
    /// burst finishes before the next (the run fails otherwise).
    #[arg(long, default_value_t = 3000)]
    slot_ms: u64,
    /// Latency budget per request, from the start of its burst.
    #[arg(long, default_value_t = 1000)]
    budget_ms: u64,
    /// Active validators on the network: sets the committee size (and so
    /// the aggregator share), the sync committee share and proposals.
    #[arg(long, default_value_t = 1_000_000)]
    total_validators: u64,
    #[arg(long)]
    aggregator_ratio: Option<f64>,
    #[arg(long)]
    sync_members: Option<usize>,
    /// HTTP/2 over one connection instead of an HTTP/1.1 pool.
    #[arg(long)]
    http2: bool,
    /// HTTP/1.1 connections (each has one request in flight).
    #[arg(long, default_value_t = 128)]
    conns: usize,
    /// Plain HTTP (the signer's --insecure-http), to measure the TLS cost.
    #[arg(long)]
    plain_http: bool,
    /// TLS without a client certificate.
    #[arg(long)]
    no_mtls: bool,
    /// Holds cached keystores and run directories. Put it on the disk under
    /// test: the slashing database lives here.
    #[arg(long, default_value = "load-test-work")]
    work_dir: PathBuf,
    /// Parent of the signer's data dir, if not WORK_DIR (e.g. /dev/shm to
    /// take fsync out).
    #[arg(long)]
    data_parent: Option<PathBuf>,
    /// dvtee binary. Default: next to this one.
    #[arg(long)]
    signer_bin: Option<PathBuf>,
    /// Fork schedule to copy. The signer runs as a devnet with this schedule
    /// and the load test's own genesis validators root (see `devnet-config`;
    /// a signer given with --url must be set up with it).
    #[arg(long, default_value = "hoodi")]
    network: String,
    /// First simulated epoch. Default 60000 (Fulu on Hoodi) with a fresh
    /// data dir; required with --url.
    #[arg(long)]
    start_epoch: Option<u64>,
    /// Use a running signer (https://host:port or http://host:port).
    #[arg(long)]
    url: Option<String>,
    /// The running signer's cert.pem (with --url https://).
    #[arg(long)]
    ca: Option<PathBuf>,
    #[arg(long, requires = "client_key")]
    client_cert: Option<PathBuf>,
    #[arg(long, requires = "client_cert")]
    client_key: Option<PathBuf>,
    /// Worker threads of this tool's runtime. Kept low so the client takes
    /// little CPU from a signer on the same machine.
    #[arg(long, default_value_t = 2)]
    client_threads: usize,
    /// Signatures to verify per kind.
    #[arg(long, default_value_t = 16)]
    verify: usize,
    /// Append a JSON summary line here.
    #[arg(long)]
    json_out: Option<PathBuf>,
    #[arg(long, default_value = "")]
    label: String,
    /// Keep the run's data dir and signer log.
    #[arg(long)]
    keep: bool,
}

#[derive(Args)]
struct MicroArgs {
    /// Directory on the disk under test.
    #[arg(long, default_value = "load-test-work")]
    dir: PathBuf,
    /// Burst sizes.
    #[arg(long, value_delimiter = ',', default_values_t = [100usize, 200, 1000, 3200])]
    bursts: Vec<usize>,
    /// Measured bursts per size (after one warm-up burst).
    #[arg(long, default_value_t = 5)]
    rounds: usize,
}

fn main() -> anyhow::Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { keys, work_dir } => {
            let dir = keys::ensure(&work_dir, keys)?;
            println!("{}", dir.display());
            Ok(())
        }
        Cmd::DevnetConfig { network: n, out } => {
            let (net, yaml) = load_devnet(&network(&n)?)?;
            std::fs::create_dir_all(&out)?;
            std::fs::write(out.join("config.yaml"), yaml)?;
            let gvr = format!("0x{}", hex::encode(net.genesis_validators_root));
            std::fs::write(out.join("genesis-validators-root"), format!("{gvr}\n"))?;
            println!(
                "{}: config.yaml, genesis-validators-root {gvr}",
                out.display()
            );
            Ok(())
        }
        Cmd::Probe { dir, secs } => probe(&dir, secs),
        Cmd::Micro(a) => tokio::runtime::Runtime::new()?.block_on(micro(a)),
        Cmd::Run(a) => tokio::runtime::Builder::new_multi_thread()
            .worker_threads(a.client_threads.max(1))
            .enable_all()
            .build()?
            .block_on(run(*a)),
    }
}

fn network(name: &str) -> anyhow::Result<Network> {
    let net: Network = name.parse().map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        net.has_schedule(),
        "--network needs a preset with a fork schedule"
    );
    Ok(net)
}

/// The network the load test signs on: `base`'s fork schedule under a
/// genesis validators root of its own, as a config.yaml devnet. A public
/// root would turn the start floor on, which refuses the compressed clock's
/// epochs; on a devnet it is off by default, so the release binary is
/// measured unchanged. The keys and signatures are worthless anywhere else.
fn load_devnet(base: &Network) -> anyhow::Result<(Network, String)> {
    let gvr: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"dvtee-load devnet").into();
    let mut yaml = format!(
        "PRESET_BASE: mainnet\nCONFIG_NAME: dvtee-load\nGENESIS_FORK_VERSION: 0x{}\nSLOT_DURATION_MS: {}\n",
        hex::encode(base.genesis_fork_version),
        base.slot_duration_ms
    );
    for f in &base.forks[1..] {
        yaml += &format!(
            "{0}_FORK_VERSION: 0x{1}\n{0}_FORK_EPOCH: {2}\n",
            f.name,
            hex::encode(f.version),
            f.epoch
        );
    }
    let net = Network::from_config_yaml(&yaml, gvr).map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        net.forks == base.forks && !net.is_public(),
        "the load-test devnet does not match {}'s fork schedule",
        base.name
    );
    Ok((net, yaml))
}

// ---------------------------------------------------------------------------
// Local signer.

struct Signer {
    child: Child,
    run_dir: PathBuf,
    /// A data dir outside the run dir (`--data-parent`).
    data_dir: Option<PathBuf>,
    keep: bool,
}

impl Drop for Signer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if !self.keep {
            let _ = std::fs::remove_dir_all(&self.run_dir);
            if let Some(d) = &self.data_dir {
                let _ = std::fs::remove_dir_all(d);
            }
        }
    }
}

fn free_port() -> anyhow::Result<u16> {
    Ok(std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port())
}

fn signer_bin(a: &RunArgs) -> anyhow::Result<PathBuf> {
    let bin = match &a.signer_bin {
        Some(p) => p.clone(),
        None => std::env::current_exe()?
            .parent()
            .context("exe dir")?
            .join("dvtee"),
    };
    anyhow::ensure!(
        bin.exists(),
        "{} not found: build it with `cargo build --release --features load-test`, or pass --signer-bin",
        bin.display()
    );
    Ok(bin)
}

struct Local {
    /// Stops the signer when dropped.
    _signer: Signer,
    target: client::Target,
}

/// Starts the signer as in production (TLS, mTLS, fsynced slashing DB)
/// unless told otherwise.
async fn start_local(a: &RunArgs, keys: usize, net: &Network, yaml: &str) -> anyhow::Result<Local> {
    let bin = signer_bin(a)?;
    let keystores = keys::ensure(&a.work_dir, keys)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let run_dir = a.work_dir.join(format!("run-{stamp}"));
    let data_dir = match &a.data_parent {
        Some(p) => p.join(format!("dvtee-load-{stamp}")),
        None => run_dir.join("data"),
    };
    std::fs::create_dir_all(&run_dir)?;
    std::fs::write(run_dir.join("config.yaml"), yaml)?;
    std::fs::create_dir_all(&data_dir)?;
    let port = free_port()?;

    let mut cmd = Command::new(&bin);
    cmd.arg("serve")
        .arg("--network")
        .arg(run_dir.join("config.yaml"))
        .args([
            "--genesis-validators-root",
            &format!("0x{}", hex::encode(net.genesis_validators_root)),
        ])
        .arg("--keystores-dir")
        .arg(&keystores)
        .arg("--data-dir")
        .arg(&data_dir)
        .args(["--listen", &format!("127.0.0.1:{port}")]);

    let mut client_cert = None;
    if a.plain_http {
        cmd.arg("--insecure-http");
    } else if !a.no_mtls {
        let ck = rcgen::generate_simple_self_signed(vec!["dvtee-load".to_string()])?;
        let der = ck.cert.der().clone();
        let fp = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&der));
        let known = run_dir.join("knownClients.txt");
        std::fs::write(&known, format!("dvtee-load {fp}\n"))?;
        cmd.arg("--tls-known-clients").arg(&known);
        client_cert = Some(client::ClientCert {
            cert: der,
            key: PrivateKeyDer::try_from(ck.signing_key.serialize_der())
                .map_err(anyhow::Error::msg)?,
        });
    }
    let log = std::fs::File::create(run_dir.join("signer.log"))?;
    cmd.env("RUST_LOG", "warn")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    let child = cmd
        .spawn()
        .with_context(|| format!("starting {}", bin.display()))?;
    let mut signer = Signer {
        child,
        run_dir: run_dir.clone(),
        data_dir: a.data_parent.as_ref().map(|_| data_dir.clone()),
        keep: a.keep,
    };

    // Wait for the listener (keystore loading comes first).
    let started = Instant::now();
    let deadline = Duration::from_secs(60) + Duration::from_millis(keys as u64 * 5);
    let cert_path = data_dir.join("tls/cert.pem");
    loop {
        if let Some(status) = signer.child.try_wait()? {
            bail!(
                "signer exited with {status}; see {}",
                run_dir.join("signer.log").display()
            );
        }
        let ready = std::net::TcpStream::connect(("127.0.0.1", port)).is_ok()
            && (a.plain_http || cert_path.exists());
        if ready {
            break;
        }
        anyhow::ensure!(started.elapsed() < deadline, "signer did not start");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    eprintln!("signer up with {keys} keys in {:.1?}", started.elapsed());
    let tls = if a.plain_http {
        None
    } else {
        let cert = CertificateDer::from_pem_file(&cert_path).context("signer cert.pem")?;
        Some(client::tls_config(cert, client_cert, a.http2)?)
    };
    Ok(Local {
        _signer: signer,
        target: client::Target {
            host: "127.0.0.1".into(),
            port,
            tls,
            http2: a.http2,
        },
    })
}

fn remote_target(a: &RunArgs) -> anyhow::Result<client::Target> {
    let url: hyper::Uri = a.url.as_deref().context("--url")?.parse()?;
    let https = match url.scheme_str() {
        Some("https") => true,
        Some("http") => false,
        _ => bail!("--url must be http:// or https://"),
    };
    let host = url.host().context("--url host")?.to_string();
    let port = url.port_u16().unwrap_or(if https { 443 } else { 80 });
    let tls = if https {
        let ca =
            a.ca.as_ref()
                .context("--url https:// needs --ca cert.pem")?;
        let cert = CertificateDer::from_pem_file(ca).context("--ca")?;
        let client = match (&a.client_cert, &a.client_key) {
            (Some(c), Some(k)) => Some(client::ClientCert {
                cert: CertificateDer::from_pem_file(c).context("--client-cert")?,
                key: PrivateKeyDer::from_pem_file(k).context("--client-key")?,
            }),
            _ => None,
        };
        Some(client::tls_config(cert, client, a.http2)?)
    } else {
        None
    };
    Ok(client::Target {
        host,
        port,
        tls,
        http2: a.http2,
    })
}

// ---------------------------------------------------------------------------
// Run.

struct Meta {
    kind: Kind,
    slot: usize,
    phase: usize,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[idx.clamp(1, sorted.len()) - 1]
}

async fn run(a: RunArgs) -> anyhow::Result<()> {
    let (net, yaml) = load_devnet(&network(&a.network)?)?;
    let (local, target, start_epoch) = match &a.url {
        Some(_) => {
            let start = a
                .start_epoch
                .context("--url needs --start-epoch above the signer's last run")?;
            (None, remote_target(&a)?, start)
        }
        None => {
            let keys = a.keys.context("--keys")?;
            let l = start_local(&a, keys, &net, &yaml).await?;
            let t = l.target.clone();
            (Some(l), t, a.start_epoch.unwrap_or(60_000))
        }
    };

    // Keys as the signer lists them.
    let conn = client::connect(&target).await?;
    let r = conn
        .request(&target, "GET", "/api/v1/eth2/publicKeys", Bytes::new())
        .await?;
    anyhow::ensure!(r.status == 200, "publicKeys: {}", r.status);
    let pubkeys: Vec<String> = serde_json::from_slice(&r.body)?;
    if let Some(n) = a.keys {
        anyhow::ensure!(
            pubkeys.len() == n,
            "signer has {} keys, expected {n}",
            pubkeys.len()
        );
    }
    let n = pubkeys.len();
    if let Some(k) = a.attesters_per_slot {
        anyhow::ensure!(k > 0 && k <= n, "--attesters-per-slot must be 1..={n}");
    }
    let paths = duties::sign_paths(&pubkeys);

    let mix = Mix::new(
        n,
        a.attesters_per_slot,
        a.total_validators,
        a.aggregator_ratio,
        a.sync_members,
    );
    let warmup = a
        .warmup_slots
        .unwrap_or(32.max(a.attesters_per_slot.map_or(0, |k| n.div_ceil(k))));
    let measured = a.epochs * 32;
    let total_slots = warmup + measured;
    let mode = if a.attesters_per_slot.is_some() {
        "stress"
    } else {
        "realistic"
    };
    let transport = format!(
        "{} {}{}",
        if target.tls.is_none() {
            "http"
        } else if a.no_mtls || (a.url.is_some() && a.client_cert.is_none()) {
            "https"
        } else {
            "https+mTLS"
        },
        if a.http2 {
            "h2".to_string()
        } else {
            format!("h1x{}", a.conns)
        },
        a.data_parent
            .as_ref()
            .map(|p| format!(" data:{}", p.display()))
            .unwrap_or_default()
    );
    eprintln!(
        "{mode}: {n} keys, {:.1} attesters/slot, aggregator ratio {:.3}, {} sync members, \
         {:.3} proposals/slot; {transport}; slot {} ms, {warmup} warm-up + {measured} measured slots",
        mix.attesters_per_slot(),
        mix.aggregator_ratio,
        mix.sync_members,
        mix.proposals_per_slot,
        a.slot_ms,
    );

    let mut schedule = Schedule::new(mix.clone(), net.clone(), start_epoch);
    let next_epoch = schedule.next_start_epoch(total_slots);
    let (job_tx, mut done_rx) = client::start(target.clone(), a.conns).await?;

    // Collector.
    let metas: Arc<std::sync::Mutex<Vec<Meta>>> = Arc::default();
    let samples: Arc<std::sync::Mutex<BTreeMap<usize, Bytes>>> = Arc::default();
    let collector = {
        let samples = samples.clone();
        tokio::spawn(async move {
            let mut done = Vec::new();
            while let Some(d) = done_rx.recv().await {
                if let Ok(r) = &d.result
                    && r.status == 200
                    && samples.lock().unwrap().contains_key(&d.id)
                {
                    samples.lock().unwrap().insert(d.id, r.body.clone());
                }
                done.push(d);
            }
            done
        })
    };

    let slot_len = Duration::from_millis(a.slot_ms);
    let phase_len = slot_len / PHASES as u32;
    let t0 = Instant::now() + Duration::from_millis(500);
    let release =
        |slot: usize, phase: usize| t0 + slot_len * slot as u32 + phase_len * phase as u32;
    let mut sample_count: BTreeMap<Kind, usize> = BTreeMap::new();
    let mut request_bodies: BTreeMap<usize, (usize, Bytes)> = BTreeMap::new();
    let mut slot_sigs = Vec::with_capacity(total_slots);

    let mut next = tokio::task::spawn_blocking(move || {
        let s = schedule.slot(0);
        (schedule, s)
    });
    let mut id = 0usize;
    for i in 0..total_slots {
        let (mut sched, slot) = next.await?;
        next = tokio::task::spawn_blocking(move || {
            let s = sched.slot(i + 1);
            (sched, s)
        });
        slot_sigs.push(slot.phases.iter().map(Vec::len).sum::<usize>());
        for (phase, reqs) in slot.phases.into_iter().enumerate() {
            let at = release(i, phase);
            if Instant::now() > at {
                eprintln!("warning: slot {i} phase {phase} released late");
            }
            tokio::time::sleep_until(at.into()).await;
            let mut m = metas.lock().unwrap();
            for r in reqs {
                m.push(Meta {
                    kind: r.kind,
                    slot: i,
                    phase,
                });
                if i >= warmup {
                    let c = sample_count.entry(r.kind).or_default();
                    if *c < a.verify {
                        *c += 1;
                        samples.lock().unwrap().insert(id, Bytes::new());
                        request_bodies.insert(id, (r.key, r.body.clone()));
                    }
                }
                job_tx
                    .send(client::Job {
                        id,
                        path: paths[r.key].clone(),
                        body: r.body,
                        scheduled: at,
                    })
                    .map_err(|_| anyhow::anyhow!("client stopped"))?;
                id += 1;
            }
        }
        if i == warmup {
            eprintln!("warm-up done, measuring");
        }
    }
    drop(next);
    // Let the last burst drain.
    let drain_deadline = Instant::now() + Duration::from_secs(30);
    drop(job_tx);
    let done = tokio::time::timeout_at(drain_deadline.into(), collector)
        .await
        .context("requests still outstanding 30 s after the last burst")??;
    anyhow::ensure!(done.len() == id, "{} of {id} requests finished", done.len());

    // Statistics over the measured slots.
    let metas = metas.lock().unwrap();
    let budget = Duration::from_millis(a.budget_ms);
    let mut lat: BTreeMap<Kind, Vec<f64>> = BTreeMap::new();
    let mut errors: BTreeMap<String, usize> = BTreeMap::new();
    let mut burst_end: BTreeMap<(usize, usize), Instant> = BTreeMap::new();
    let mut within = vec![0usize; total_slots];
    for d in &done {
        let m = &metas[d.id];
        if m.slot < warmup {
            continue;
        }
        let ok = match &d.result {
            Ok(r) if r.status == 200 => true,
            Ok(r) => {
                *errors
                    .entry(format!(
                        "{} {}: {}",
                        m.kind.name(),
                        r.status,
                        String::from_utf8_lossy(&r.body)
                    ))
                    .or_default() += 1;
                false
            }
            Err(e) => {
                *errors
                    .entry(format!("{}: {e:#}", m.kind.name()))
                    .or_default() += 1;
                false
            }
        };
        let l = d.done - d.scheduled;
        if ok {
            lat.entry(m.kind)
                .or_default()
                .push(l.as_secs_f64() * 1000.0);
            if l <= budget {
                within[m.slot] += 1;
            }
        }
        let e = burst_end.entry((m.slot, m.phase)).or_insert(d.done);
        *e = (*e).max(d.done);
    }
    // A burst that ends after the next one starts makes the compressed
    // clock pessimistic; on a real 12 s slot the gap is 4 s.
    let overlaps = burst_end
        .iter()
        .filter(|((s, p), end)| {
            let next = if p + 1 < PHASES {
                release(*s, p + 1)
            } else {
                release(s + 1, 0)
            };
            **end > next
        })
        .count();
    // Completion time of each attestation burst (the 1/3 phase).
    let mut att_bursts: Vec<(f64, usize)> = burst_end
        .iter()
        .filter(|((_, p), _)| *p == 1)
        .map(|((s, p), end)| ((*end - release(*s, *p)).as_secs_f64() * 1000.0, *s))
        .collect();
    att_bursts.sort_by(|x, y| x.0.total_cmp(&y.0));

    // Verify a sample of signatures against the signing roots the signer's
    // own code computes.
    let policy = Policy {
        allow_voluntary_exits: false,
        allow_deposits: false,
    };
    let samples = samples.lock().unwrap();
    let mut verified = 0;
    for (id, (key, body)) in &request_bodies {
        let Some(resp) = samples.get(id).filter(|b| !b.is_empty()) else {
            continue;
        };
        let req: SignRequest = serde_json::from_slice(body)?;
        let root = dvtee::signing::prepare(&req, &net, &policy)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .signing_root;
        let sig_hex = std::str::from_utf8(resp)?.trim();
        let sig =
            blst::min_pk::Signature::from_bytes(&hex::decode(sig_hex.trim_start_matches("0x"))?)
                .map_err(|e| anyhow::anyhow!("signature: {e:?}"))?;
        let pk = blst::min_pk::PublicKey::from_bytes(&hex::decode(
            pubkeys[*key].trim_start_matches("0x"),
        )?)
        .map_err(|e| anyhow::anyhow!("pubkey: {e:?}"))?;
        anyhow::ensure!(
            sig.verify(true, &root, DST, &[], &pk, true) == blst::BLST_ERROR::BLST_SUCCESS,
            "signature {id} does not verify"
        );
        verified += 1;
    }

    // Report.
    let measured_sigs: usize = slot_sigs[warmup..].iter().sum();
    let max_sigs = slot_sigs[warmup..].iter().copied().max().unwrap_or(0);
    let in_budget: usize = within[warmup..].iter().sum();
    let mut pass = errors.is_empty() && overlaps == 0;
    println!();
    println!(
        "## {mode} {n} keys{} ({transport})",
        if a.label.is_empty() {
            String::new()
        } else {
            format!(", {}", a.label)
        }
    );
    println!();
    println!("| kind | count | p50 ms | p95 ms | p99 ms | max ms |");
    println!("|---|---:|---:|---:|---:|---:|");
    let mut kinds_json = serde_json::Map::new();
    for kind in Kind::ALL {
        let Some(v) = lat.get_mut(&kind) else {
            continue;
        };
        v.sort_by(f64::total_cmp);
        let (p50, p95, p99, max) = (
            percentile(v, 50.0),
            percentile(v, 95.0),
            percentile(v, 99.0),
            *v.last().unwrap(),
        );
        if p99 > a.budget_ms as f64 {
            pass = false;
        }
        println!(
            "| {} | {} | {p50:.1} | {p95:.1} | {p99:.1} | {max:.1} |",
            kind.name(),
            v.len()
        );
        kinds_json.insert(
            kind.name().into(),
            serde_json::json!({"count": v.len(), "p50": p50, "p95": p95, "p99": p99, "max": max}),
        );
    }
    println!();
    println!(
        "attestations/slot {:.1}; signatures/slot {:.1} avg, {max_sigs} max; {:.2}% within {} ms; \
         bursts overlapping the next: {overlaps}; errors: {}; signatures verified: {verified}",
        mix.attesters_per_slot(),
        measured_sigs as f64 / measured as f64,
        100.0 * in_budget as f64 / measured_sigs.max(1) as f64,
        a.budget_ms,
        errors.values().sum::<usize>(),
    );
    if !att_bursts.is_empty() {
        let b: Vec<f64> = att_bursts.iter().map(|x| x.0).collect();
        println!(
            "attestation burst completion: p50 {:.1} ms, p90 {:.1} ms, max {:.1} ms; slowest: {}",
            percentile(&b, 50.0),
            percentile(&b, 90.0),
            b[b.len() - 1],
            att_bursts
                .iter()
                .rev()
                .take(3)
                .map(|(ms, s)| format!("slot {} {ms:.0} ms", s - warmup))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for (e, c) in errors.iter().take(10) {
        println!("  {c} x {e}");
    }
    println!("verdict: {}", if pass { "PASS" } else { "FAIL" });
    if a.url.is_some() {
        println!("next --start-epoch for this signer: {next_epoch}");
    }

    if let Some(path) = &a.json_out {
        use std::io::Write;
        let line = serde_json::json!({
            "label": a.label,
            "mode": mode,
            "keys": n,
            "attesters_per_slot": mix.attesters_per_slot(),
            "transport": transport,
            "slot_ms": a.slot_ms,
            "budget_ms": a.budget_ms,
            "measured_slots": measured,
            "signatures_per_slot": measured_sigs as f64 / measured as f64,
            "within_budget": in_budget as f64 / measured_sigs.max(1) as f64,
            "overlaps": overlaps,
            "errors": errors.values().sum::<usize>(),
            "pass": pass,
            "kinds": kinds_json,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(f, "{line}")?;
    }
    drop(local);
    Ok(())
}

// ---------------------------------------------------------------------------
// Micro benchmarks.

fn stats_ms(mut v: Vec<f64>) -> String {
    v.sort_by(f64::total_cmp);
    format!(
        "p50 {:.3} ms, p99 {:.3} ms, mean {:.3} ms",
        percentile(&v, 50.0),
        percentile(&v, 99.0),
        v.iter().sum::<f64>() / v.len() as f64
    )
}

fn fake_pubkey(i: usize) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[..8].copy_from_slice(&(i as u64).to_le_bytes());
    pk
}

async fn micro(a: MicroArgs) -> anyhow::Result<()> {
    let dir = a.dir.join(format!(
        "micro-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
    ));
    let db = Arc::new(SlashingDb::open(&dir, [1u8; 32])?);
    let sk = Arc::new(dvtee::keystore::SecretKey::from_bytes(
        &blst::min_pk::SecretKey::key_gen(&[7u8; 32], &[])
            .map_err(|e| anyhow::anyhow!("{e:?}"))?
            .to_bytes(),
    )?);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    println!("micro benchmarks in {} ({threads} CPUs)", dir.display());

    // Serial.
    let mut v = Vec::new();
    for i in 0..2000u32 {
        let root = [i as u8; 32];
        let t = Instant::now();
        std::hint::black_box(sk.sign(&root));
        v.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    println!("BLS sign, serial:              {}", stats_ms(v));
    let att = |e: u64| SlashingCheck::Attestation {
        source: e - 1,
        target: e,
    };
    for i in 0..300 {
        db.check_and_record(&fake_pubkey(i), att(10), &[0; 32])?;
    }
    let mut v = Vec::new();
    for i in 0..300 {
        let t = Instant::now();
        db.check_and_record(&fake_pubkey(i), att(11), &[0; 32])?;
        v.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    println!("watermark write, serial:       {}", stats_ms(v));

    // For comparison: overwriting a block of a preallocated file and
    // fdatasync, which needs no journal commit on ext4 (a log-style store).
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = std::fs::File::create(dir.join("prealloc.bin"))?;
        f.write_all(&vec![0u8; 64 * 4096])?;
        f.sync_all()?;
        let mut v = Vec::new();
        for i in 0..300u64 {
            let t = Instant::now();
            f.seek(SeekFrom::Start((i % 64) * 4096))?;
            f.write_all(&[i as u8; 512])?;
            f.sync_data()?;
            v.push(t.elapsed().as_secs_f64() * 1000.0);
        }
        println!("overwrite + fdatasync, serial: {}", stats_ms(v));
    }

    // Bursts through spawn_blocking, as the signer's handler does.
    println!();
    println!(
        "Burst completion (all done), median of {} rounds:",
        a.rounds
    );
    println!();
    println!("| burst | sign only ms | watermark only ms | watermark + sign ms |");
    println!("|---:|---:|---:|---:|");
    let mut epoch = 100u64;
    for &b in &a.bursts {
        let mut res = [Vec::new(), Vec::new(), Vec::new()];
        for round in 0..=a.rounds {
            for (variant, out) in res.iter_mut().enumerate() {
                epoch += 1;
                let e = epoch;
                let t = Instant::now();
                let handles: Vec<_> = (0..b)
                    .map(|i| {
                        let (db, sk) = (db.clone(), sk.clone());
                        tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                            let root = [i as u8; 32];
                            if variant != 0 {
                                db.check_and_record(&fake_pubkey(10_000 + i), att(e), &root)?;
                            }
                            if variant != 1 {
                                std::hint::black_box(sk.sign(&root));
                            }
                            Ok(())
                        })
                    })
                    .collect();
                for h in handles {
                    h.await??;
                }
                if round > 0 {
                    out.push(t.elapsed().as_secs_f64() * 1000.0);
                }
            }
        }
        let med = |v: &mut Vec<f64>| {
            v.sort_by(f64::total_cmp);
            percentile(v, 50.0)
        };
        println!(
            "| {b} | {:.1} | {:.1} | {:.1} |",
            med(&mut res[0]),
            med(&mut res[1]),
            med(&mut res[2])
        );
    }
    // The same bursts as in-place overwrites of one preallocated file, each
    // with its own fdatasync (a journal-free store without batching).
    println!();
    println!("| burst | overwrite + fdatasync ms |");
    println!("|---:|---:|");
    {
        use std::io::Write;
        use std::os::unix::fs::FileExt;
        let max = a.bursts.iter().copied().max().unwrap_or(0);
        let mut f = std::fs::File::create(dir.join("records.bin"))?;
        f.write_all(&vec![0u8; max * 4096])?;
        f.sync_all()?;
        let f = Arc::new(f);
        for &b in &a.bursts {
            let mut v = Vec::new();
            for round in 0..=a.rounds {
                let t = Instant::now();
                let handles: Vec<_> = (0..b)
                    .map(|i| {
                        let f = f.clone();
                        tokio::task::spawn_blocking(move || -> std::io::Result<()> {
                            f.write_at(&[round as u8; 512], i as u64 * 4096)?;
                            f.sync_data()
                        })
                    })
                    .collect();
                for h in handles {
                    h.await??;
                }
                if round > 0 {
                    v.push(t.elapsed().as_secs_f64() * 1000.0);
                }
            }
            v.sort_by(f64::total_cmp);
            println!("| {b} | {:.1} |", percentile(&v, 50.0));
        }
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Stall probe.

fn probe(dir: &std::path::Path, secs: u64) -> anyhow::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let dir = dir.join(format!("probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let mut pre = std::fs::File::create(dir.join("prealloc.bin"))?;
    pre.write_all(&vec![0u8; 64 * 4096])?;
    pre.sync_all()?;
    let file = dir.join("watermark.json");
    let tmp = dir.join("watermark.tmp");
    println!("time_s,overwrite_fdatasync_max_ms,create_fsync_rename_dirsync_max_ms,io_some_avg10");
    let start = Instant::now();
    let mut i = 0u64;
    while start.elapsed().as_secs() < secs {
        let second = Instant::now();
        let (mut a, mut b) = (0f64, 0f64);
        // Ten of each per second, alternating.
        while second.elapsed() < Duration::from_secs(1) {
            let t = Instant::now();
            pre.seek(SeekFrom::Start((i % 64) * 4096))?;
            pre.write_all(&[i as u8; 512])?;
            pre.sync_data()?;
            a = a.max(t.elapsed().as_secs_f64() * 1000.0);

            let t = Instant::now();
            {
                let mut f = std::fs::File::create(&tmp)?;
                f.write_all(format!("{{\"n\":{i}}}").as_bytes())?;
                f.sync_all()?;
            }
            std::fs::rename(&tmp, &file)?;
            std::fs::File::open(&dir)?.sync_all()?;
            b = b.max(t.elapsed().as_secs_f64() * 1000.0);
            i += 1;
            std::thread::sleep(Duration::from_millis(100).saturating_sub(t.elapsed()));
        }
        let psi = std::fs::read_to_string("/proc/pressure/io")
            .ok()
            .and_then(|s| {
                s.lines()
                    .next()?
                    .split_whitespace()
                    .find_map(|f| f.strip_prefix("avg10=").map(str::to_string))
            })
            .unwrap_or_default();
        println!("{},{a:.1},{b:.1},{psi}", start.elapsed().as_secs());
    }
    std::fs::remove_dir_all(&dir)?;
    Ok(())
}
