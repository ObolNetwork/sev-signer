//! TEE attestation via the Linux configfs-tsm report interface
//! (`/sys/kernel/config/tsm/report`, Linux >= 6.7).
//!
//! configfs-tsm is vendor neutral: the same code path yields an AMD SEV-SNP
//! attestation report (provider `sev_guest`), an Intel TDX quote (provider
//! `tdx_guest`) or an Arm CCA token, so the signer itself carries no
//! vendor-specific code for producing evidence.
//!
//! The 64-byte REPORT_DATA binds the evidence to this signer instance:
//!
//! ```text
//! SHA-512( "obol-dvtee/attestation/v1"
//!        || nonce                       (32 bytes, verifier chosen)
//!        || SHA-256(TLS certificate DER)
//!        || SHA-256(sorted BLS pubkeys) )
//! ```
//!
//! A verifier that checks the report signature, the launch measurement and
//! this binding knows that the TLS key it is talking to, and the BLS keys
//! behind it, live inside the measured guest.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256, Sha512};

const TSM_REPORT_DIR: &str = "/sys/kernel/config/tsm/report";
const BINDING_DOMAIN: &[u8] = b"obol-dvtee/attestation/v1";

/// REPORT_DATA: SHA-512 over the domain, the verifier's nonce, the TLS
/// certificate's hash, the hash of the sorted BLS key set and, when the
/// signer is pinned to a cluster lock, a tag and the lock hash (without one,
/// the bytes are the same as before locks were pinned).
pub fn report_data(
    nonce: &[u8; 32],
    tls_cert_der: &[u8],
    pubkeys: &[[u8; 48]],
    cluster_lock_hash: Option<&[u8; 32]>,
) -> [u8; 64] {
    let mut sorted = pubkeys.to_vec();
    sorted.sort();
    let mut pk_hash = Sha256::new();
    for pk in &sorted {
        pk_hash.update(pk);
    }

    let mut h = Sha512::new();
    h.update(BINDING_DOMAIN);
    h.update(nonce);
    h.update(Sha256::digest(tls_cert_der));
    h.update(pk_hash.finalize());
    if let Some(lock_hash) = cluster_lock_hash {
        h.update(b"cluster-lock");
        h.update(lock_hash);
    }
    h.finalize().into()
}

pub struct Evidence {
    pub provider: String,
    pub report: Vec<u8>,
    pub auxblob: Option<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error(
        "no TEE attestation interface ({TSM_REPORT_DIR} missing): not running in a confidential VM, or kernel < 6.7"
    )]
    Unavailable,
    #[error("attestation report generation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("attestation report raced with another request, retry")]
    Race,
}

/// Removes the report entry when dropped.
struct Entry(PathBuf);

impl Drop for Entry {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.0);
    }
}

fn read_generation(dir: &Path) -> std::io::Result<String> {
    Ok(fs::read_to_string(dir.join("generation"))?
        .trim()
        .to_string())
}

/// Requests attestation evidence with the given REPORT_DATA. Blocking.
pub fn get_evidence(report_data: &[u8; 64]) -> Result<Evidence, TeeError> {
    let base = Path::new(TSM_REPORT_DIR);
    if !base.is_dir() {
        return Err(TeeError::Unavailable);
    }

    let mut nonce = [0u8; 8];
    getrandom(&mut nonce)?;
    let entry = Entry(base.join(format!("dvtee-{}", hex::encode(nonce))));
    fs::create_dir(&entry.0)?;

    fs::write(entry.0.join("inblob"), report_data)?;
    let generation = read_generation(&entry.0)?;
    let provider = fs::read_to_string(entry.0.join("provider"))?
        .trim()
        .to_string();
    let report = fs::read(entry.0.join("outblob"))?;
    // Certificates (e.g. the SNP VCEK chain) only if the host provisioned them.
    let auxblob = fs::read(entry.0.join("auxblob"))
        .ok()
        .filter(|b| !b.is_empty());

    // configfs-tsm bumps `generation` on every write; a change means another
    // writer touched our entry between inblob and outblob.
    if read_generation(&entry.0)? != generation {
        return Err(TeeError::Race);
    }

    Ok(Evidence {
        provider,
        report,
        auxblob,
    })
}

fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
    use std::io::Read;
    fs::File::open("/dev/urandom")?.read_exact(buf)
}

/// Offsets into the raw evidence for the fields a verifier compares.
pub struct Layout {
    pub report_data: usize,
    pub measurement: (usize, usize),
    pub measurement_name: &'static str,
}

pub fn layout(provider: &str) -> Option<Layout> {
    match provider {
        // AMD SEV-SNP ATTESTATION_REPORT (SEV-SNP ABI spec, table 22). The
        // insecure-dev platform emits unsigned reports in the same layout.
        "sev_guest" | "insecure_dev" => Some(Layout {
            report_data: 0x50,
            measurement: (0x90, 48),
            measurement_name: "MEASUREMENT",
        }),
        // Intel TDX quote v4: 48-byte header, then the TD report body.
        "tdx_guest" => Some(Layout {
            report_data: 48 + 520,
            measurement: (48 + 136, 48),
            measurement_name: "MRTD",
        }),
        _ => None,
    }
}

/// AMD SEV-SNP guest policy bit 19: debugging allowed. A guest launched with
/// it set offers no confidentiality against the host.
pub fn snp_debug_allowed(report: &[u8]) -> Option<bool> {
    let policy = u64::from_le_bytes(report.get(0x08..0x10)?.try_into().ok()?);
    Some(policy & (1 << 19) != 0)
}

/// Intel TDX TDATTRIBUTES bit 0: DEBUG.
pub fn tdx_debug(report: &[u8]) -> Option<bool> {
    let attrs = u64::from_le_bytes(report.get(48 + 120..48 + 128)?.try_into().ok()?);
    Some(attrs & 1 != 0)
}
