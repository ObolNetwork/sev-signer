//! A minimal HTML view of `/api/v1/tee/attestation` for browsers
//! (`Accept: text/html`). It shows what the evidence says and how to verify
//! it. It can't vouch for the signer: a compromised signer could serve the
//! same page, so the page says so and gives the command that does verify.
//!
//! No scripts, no external resources, a strict CSP. Every value is either a
//! number, hex, or escaped.

use std::fmt::Write;

use crate::snp::{self, Tcb};

pub struct View<'a> {
    pub provider: &'a str,
    pub report: &'a [u8],
    pub network: &'a str,
    /// Each share, with its validator's group key when a lock is pinned.
    pub keys: Vec<([u8; 48], Option<[u8; 48]>)>,
    pub lock_hash: Option<[u8; 32]>,
    pub operator_index: Option<usize>,
    pub cert_sha256: [u8; 32],
    /// `None` when anti-rollback is off.
    pub clock: Option<ClockView>,
    /// The request's Host header, for the verify command.
    pub host: &'a str,
    /// Genesis time and epoch length, to show epochs as times.
    pub genesis_time: Option<u64>,
    pub epoch_ms: u64,
    /// Unix seconds now (the guest clock; display only).
    pub now: u64,
}

pub struct ClockView {
    pub floor: Option<u64>,
    pub trusted_epoch: Option<u64>,
}

/// Content-Security-Policy for the page: inline styles only.
pub const CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; \
                       form-action 'none'; frame-ancestors 'none'";

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

/// The launchpad's page for a cluster, for the public networks it serves.
/// Only clusters created through the launchpad are listed there.
fn launchpad_url(network: &str, lock_hash: &[u8; 32]) -> Option<String> {
    let host = match network {
        "mainnet" => "launchpad.obol.org",
        "hoodi" => "hoodi.launchpad.obol.org",
        "sepolia" => "sepolia.launchpad.obol.org",
        _ => return None,
    };
    Some(format!(
        "https://{host}/cluster/details/?lockHash={}",
        hx(lock_hash)
    ))
}

/// The validator's page on beaconcha.in for the public networks.
fn explorer_url(network: &str, pubkey: &[u8; 48]) -> Option<String> {
    let host = match network {
        "mainnet" => "beaconcha.in",
        "hoodi" => "hoodi.beaconcha.in",
        "sepolia" => "sepolia.beaconcha.in",
        _ => return None,
    };
    Some(format!("https://{host}/validator/{}", hx(pubkey)))
}

/// `YYYY-MM-DD HH:MM UTC` for Unix seconds (proleptic Gregorian).
fn utc(t: u64) -> String {
    let days = (t / 86_400) as i64;
    let secs = t % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

/// "epoch N (≈ time, in about M min)" when the genesis time is known.
fn epoch_label(v: &View, epoch: u64) -> String {
    let Some(g) = v.genesis_time else {
        return format!("epoch {epoch}");
    };
    let start = g.saturating_add(epoch.saturating_mul(v.epoch_ms) / 1000);
    let rel = if start > v.now {
        let min = (start - v.now).div_ceil(60);
        format!(", in about {min} min")
    } else {
        String::new()
    };
    format!("epoch {epoch} (≈ {}{rel})", utc(start))
}

fn tcb(t: &Tcb) -> String {
    let mut s = format!(
        "bootloader {} · TEE {} · SNP {} · microcode {}",
        t.bootloader, t.tee, t.snp, t.microcode
    );
    if let Some(f) = t.fmc {
        s = format!("FMC {f} · {s}");
    }
    s
}

pub fn render(v: &View) -> String {
    let mut rows: Vec<(&str, String, &str)> = Vec::new(); // (label, html, class)
    let (platform, ok) = match v.provider {
        "sev_guest" => ("AMD SEV-SNP", true),
        "tdx_guest" => ("Intel TDX", true),
        "insecure_dev" => ("insecure-dev: NO SECURITY, development only", false),
        other => (other, false),
    };
    rows.push(("Platform", esc(platform), if ok { "" } else { "bad" }));

    if let Some(l) = crate::tee::layout(v.provider)
        && let Some(m) = v
            .report
            .get(l.measurement.0..l.measurement.0 + l.measurement.1)
    {
        rows.push(("Measurement", format!("<code>{}</code>", hx(m)), ""));
    }
    if matches!(v.provider, "sev_guest" | "insecure_dev")
        && let Ok(r) = snp::Report::parse(v.report)
    {
        let debug = r.policy & (1 << 19) != 0;
        rows.push((
            "Guest policy",
            format!(
                "<code>{:#x}</code>, debugging {}",
                r.policy,
                if debug { "ALLOWED" } else { "off" }
            ),
            if debug { "bad" } else { "" },
        ));
        if let Some(p) = snp::report_product(&r) {
            rows.push((
                "Reported TCB",
                format!("{} ({})", tcb(&Tcb::decode(r.reported_tcb, p)), p.name()),
                "",
            ));
        }
        let (a, b, c) = r.current_fw;
        rows.push(("Firmware", format!("{a}.{b}.{c}"), ""));
    }
    rows.push(("Network", esc(v.network), ""));
    rows.push((
        "Cluster lock",
        match v.lock_hash {
            Some(h) => {
                let mut s = format!("<code>{}</code>", hx(&h));
                if let Some(i) = v.operator_index {
                    let _ = write!(s, "<br>operator {i}");
                }
                if let Some(url) = launchpad_url(v.network, &h) {
                    let _ = write!(
                        s,
                        " · <a href=\"{url}\" rel=\"noopener noreferrer\">cluster on the Obol launchpad</a>"
                    );
                }
                s
            }
            None => "not pinned".into(),
        },
        "",
    ));
    let n = v.keys.len();
    let mut keys = format!(
        "<details><summary>{n} key share{}{}</summary>",
        if n == 1 { "" } else { "s" },
        match (v.lock_hash.is_some(), n == 1) {
            (false, _) => "",
            (true, true) => " of a distributed validator",
            (true, false) => " of distributed validators",
        }
    );
    for (share, dv) in &v.keys {
        match dv {
            Some(dv) => {
                let link = explorer_url(v.network, dv)
                    .map(|u| {
                        format!(" · <a href=\"{u}\" rel=\"noopener noreferrer\">beaconcha.in</a>")
                    })
                    .unwrap_or_default();
                let _ = write!(
                    keys,
                    "<div class=\"key\">validator <code>{}</code>{link}<br>this share <code>{}</code></div>",
                    hx(dv),
                    hx(share)
                );
            }
            None => {
                let _ = write!(keys, "<div class=\"key\"><code>{}</code></div>", hx(share));
            }
        }
    }
    keys.push_str("</details>");
    rows.push(("Keys", keys, ""));
    rows.push((
        "TLS certificate",
        format!("sha256 <code>{}</code>", hex::encode(v.cert_sha256)),
        "",
    ));
    let (time, signing, class) = match &v.clock {
        None => ("off".to_string(), "no start floor".to_string(), ""),
        Some(c) => match (c.floor, c.trusted_epoch) {
            (None, _) => (
                "waiting for a Roughtime quorum".into(),
                "blocks and attestations wait for trusted time".into(),
                "warn",
            ),
            (Some(_), None) => (
                "reading expired; waiting for the quorum".into(),
                "blocks and attestations paused".into(),
                "warn",
            ),
            (Some(f), Some(e)) if e <= f => (
                format!("{}, from a Roughtime quorum", epoch_label(v, e)),
                format!(
                    "blocks and attestations from {}, after the start floor",
                    epoch_label(v, f + 1)
                ),
                "warn",
            ),
            (Some(_), Some(e)) => (
                format!("{}, from a Roughtime quorum", epoch_label(v, e)),
                "signing".into(),
                "",
            ),
        },
    };
    rows.push(("Trusted time", time, ""));
    rows.push(("Duties", signing, class));

    let mut table = String::new();
    for (label, html, class) in &rows {
        let _ = write!(
            table,
            "<tr class=\"{class}\"><th>{label}</th><td>{html}</td></tr>"
        );
    }

    let lock_flag = v
        .lock_hash
        .map(|h| format!(" \\\n  --expected-cluster-lock-hash {}", hx(&h)))
        .unwrap_or_default();
    let tee_flags = if v.provider == "insecure_dev" {
        " --allow-insecure-dev"
    } else {
        " --fetch-vcek \\\n  --expected-measurement &lt;the published measurement&gt;"
    };
    let host = esc(v.host);

    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DVTEE signer</title>
<style>
:root{{--bg:#0D1D21;--fg:#DFEAED;--muted:#8FA5AB;--ok:#2FE4AB;--warn:#F4C95D;--bad:#FF6B6B;--line:#1F3A40}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}}
main{{max-width:760px;margin:0 auto;padding:32px 16px}}
h1{{font-size:22px;margin:0 0 4px}}
h1 span{{color:var(--ok)}}
p{{color:var(--muted);margin:0 0 20px}}
table{{width:100%;border-collapse:collapse}}
th,td{{text-align:left;vertical-align:top;padding:8px 0;border-top:1px solid var(--line)}}
th{{width:150px;color:var(--muted);font-weight:500;padding-right:12px}}
td{{word-break:break-all}}
tr.warn td{{color:var(--warn)}}
tr.bad td{{color:var(--bad)}}
code,pre{{font:13px ui-monospace,monospace}}
pre{{background:#091011;border:1px solid var(--line);padding:12px;overflow-x:auto;white-space:pre}}
summary{{cursor:pointer}}
a{{color:var(--ok)}}
.key{{margin:8px 0}}
h2{{font-size:16px;margin:28px 0 6px}}
</style></head><body><main>
<h1><span>●</span> DVTEE signer</h1>
<p>One key share of an Obol distributed validator, held in a trusted execution environment.</p>
<table>{table}</table>
<h2>Don't trust this page</h2>
<p>The signer generated this page from a fresh attestation report, but a compromised signer could
show the same thing. Check the report yourself, against the measurement published for the release
you expect:</p>
<pre>NONCE=$(openssl rand -hex 32)
curl -sk "https://{host}/api/v1/tee/attestation?nonce=$NONCE" &gt; evidence.json
dvtee verify-evidence --evidence evidence.json --nonce $NONCE{tee_flags}{lock_flag}</pre>
</main></body></html>
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view<'a>(provider: &'a str, report: &'a [u8], host: &'a str) -> View<'a> {
        View {
            provider,
            report,
            network: "hoodi<script>",
            keys: vec![([0xab; 48], Some([0xcd; 48]))],
            lock_hash: Some([0x6a; 32]),
            operator_index: Some(2),
            cert_sha256: [0x11; 32],
            clock: Some(ClockView {
                floor: Some(100),
                trusted_epoch: Some(99),
            }),
            host,
            genesis_time: Some(1742213400),
            epoch_ms: 384_000,
            now: 1742213400 + 99 * 384,
        }
    }

    #[test]
    fn escapes_and_shows_values() {
        let report = vec![0u8; 0x4A0];
        let html = render(&view(
            "insecure_dev",
            &report,
            "x\"><script>alert(1)</script>",
        ));
        assert!(!html.contains("<script>"), "{html}");
        assert!(html.contains("hoodi&lt;script&gt;"));
        assert!(html.contains("NO SECURITY"));
        assert!(html.contains(&format!("0x{}", "6a".repeat(32))));
        assert!(
            html.contains(
                "from epoch 101 (≈ 2025-03-17 22:56 UTC, in about 13 min), after the start floor"
            ),
            "{html}"
        );
        assert!(html.contains("--allow-insecure-dev"));
        assert!(html.contains("--expected-cluster-lock-hash"));
        assert!(html.contains(&format!("validator <code>0x{}", "cd".repeat(48))));
        assert!(html.contains(&format!("this share <code>0x{}", "ab".repeat(48))));
        assert!(html.contains("operator 2"));
        // A custom network name gets no launchpad link.
        assert!(!html.contains("launchpad.obol.org"));
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1742213400), "2025-03-17 12:10 UTC"); // Hoodi genesis
        assert_eq!(utc(1797361944), "2026-12-15 19:12 UTC"); // Hoodi Gloas
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn launchpad_link_for_public_networks() {
        let h = [0x6a; 32];
        assert_eq!(
            launchpad_url("hoodi", &h).unwrap(),
            format!(
                "https://hoodi.launchpad.obol.org/cluster/details/?lockHash=0x{}",
                "6a".repeat(32)
            )
        );
        assert!(
            launchpad_url("mainnet", &h)
                .unwrap()
                .starts_with("https://launchpad.obol.org/")
        );
        assert!(launchpad_url("devnet", &h).is_none());
        let k = [0xcd; 48];
        assert_eq!(
            explorer_url("hoodi", &k).unwrap(),
            format!("https://hoodi.beaconcha.in/validator/0x{}", "cd".repeat(48))
        );
        assert!(
            explorer_url("mainnet", &k)
                .unwrap()
                .starts_with("https://beaconcha.in/validator/")
        );
        assert!(
            explorer_url("sepolia", &k)
                .unwrap()
                .starts_with("https://sepolia.beaconcha.in/")
        );
        assert!(explorer_url("devnet", &k).is_none());
    }

    #[test]
    fn snp_asks_for_the_measurement() {
        let html = render(&view("sev_guest", &[0u8; 16], "signer:9001"));
        assert!(html.contains("AMD SEV-SNP"));
        assert!(html.contains("--fetch-vcek"));
        assert!(!html.contains("--allow-insecure-dev"));
        assert!(html.contains("https://signer:9001/api"));
    }
}
