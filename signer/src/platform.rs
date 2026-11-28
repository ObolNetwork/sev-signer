//! The two things the signer needs from the hardware: attestation evidence
//! and a sealing key that only the measured guest can derive.
//!
//! * [`Platform::Tee`]: configfs-tsm for evidence (see [`crate::tee`]) and,
//!   on AMD SEV-SNP, the firmware's derived key (`MSG_KEY_REQ` via
//!   `/dev/sev-guest`). This is the production backend.
//! * [`Platform::InsecureDev`]: a software stand-in so the rest of the
//!   system (e2e with charon, the image's unlock flow, the verifier) can be
//!   built on machines without SEV-SNP. It is compiled only with the
//!   `insecure-dev` cargo feature, refuses to serve mainnet keys, and labels
//!   its evidence `insecure_dev` so no verifier can mistake it for SNP.
//!
//! Sealing keys are domain separated per purpose:
//! `HMAC-SHA256(root, "obol-dvtee/sealing/v1" || 0x00 || purpose)`,
//! where `root` is the SNP derived key (or the dev root key file).

use std::path::PathBuf;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::tee::{self, Evidence, TeeError};

const SEALING_DOMAIN: &[u8] = b"obol-dvtee/sealing/v1";

/// Backend selector for the CLI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum PlatformKind {
    /// Confidential VM: configfs-tsm evidence, SNP derived sealing key.
    Tee,
    /// NO SECURITY. Software stand-in for development and e2e tests.
    /// Requires a build with `--features insecure-dev`.
    InsecureDev,
}

/// Platform flags shared by `serve` and `sealing-key`.
#[derive(Clone, Debug, clap::Args)]
pub struct PlatformArgs {
    #[arg(long = "platform", env = "DVTEE_PLATFORM", value_enum, default_value_t = PlatformKind::Tee)]
    pub kind: PlatformKind,
    /// Root key file for --platform insecure-dev (created if missing).
    /// Keep it outside the data dir; delete it to simulate a host move.
    #[arg(long, env = "DVTEE_INSECURE_DEV_ROOT_KEY")]
    pub insecure_dev_root_key: Option<PathBuf>,
}

impl PlatformArgs {
    pub fn build(self) -> Result<Platform, PlatformError> {
        Platform::new(self.kind, self.insecure_dev_root_key)
    }
}

pub enum Platform {
    Tee,
    #[cfg(feature = "insecure-dev")]
    InsecureDev(dev::Dev),
}

/// Inputs to the SNP derived key. Both end up in the key, so they are part
/// of the disk's identity: changing either makes old sealed data unreadable.
#[derive(Clone, Copy, Debug)]
pub struct SnpKeyParams {
    /// Minimum TCB_VERSION (raw 64-bit value, encoding varies by CPU
    /// generation). Pin a minimum rather than the current TCB so firmware
    /// updates keep the key, while a rollback below it cannot derive it.
    pub min_tcb: u64,
    /// VMPL mixed into the key; must be >= the guest's current VMPL.
    pub vmpl: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    #[error(transparent)]
    Tee(#[from] TeeError),
    #[error("SNP derived key: {0}")]
    Snp(String),
    #[error("{0}")]
    Config(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Platform {
    /// `dev_root_key` is only used by the insecure backend. It is a path,
    /// not something under the data dir: the sealing key exists to unlock
    /// the data dir, so it cannot live inside it. Deleting the file models a
    /// host move (the chip-derived key changes and sealed data is lost).
    pub fn new(kind: PlatformKind, dev_root_key: Option<PathBuf>) -> Result<Self, PlatformError> {
        match kind {
            PlatformKind::Tee => Ok(Platform::Tee),
            #[cfg(feature = "insecure-dev")]
            PlatformKind::InsecureDev => {
                let path = dev_root_key.ok_or_else(|| {
                    PlatformError::Config(
                        "--platform insecure-dev requires --insecure-dev-root-key".into(),
                    )
                })?;
                Ok(Platform::InsecureDev(dev::Dev::open(path)?))
            }
            #[cfg(not(feature = "insecure-dev"))]
            PlatformKind::InsecureDev => {
                let _ = dev_root_key;
                Err(PlatformError::Config(
                    "this build has no insecure-dev platform (rebuild with --features insecure-dev)"
                        .into(),
                ))
            }
        }
    }

    pub fn is_insecure(&self) -> bool {
        !matches!(self, Platform::Tee)
    }

    /// Attestation evidence carrying `report_data`. Blocking.
    pub fn evidence(&self, report_data: &[u8; 64]) -> Result<Evidence, PlatformError> {
        match self {
            Platform::Tee => Ok(tee::get_evidence(report_data)?),
            #[cfg(feature = "insecure-dev")]
            Platform::InsecureDev(d) => Ok(d.evidence(report_data)),
        }
    }

    /// A 32-byte key for `purpose`, derivable only by this platform. Blocking.
    pub fn sealing_key(
        &self,
        purpose: &str,
        snp: Option<SnpKeyParams>,
    ) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let root = match self {
            Platform::Tee => {
                let p = snp.ok_or_else(|| {
                    PlatformError::Config("the SNP sealing key needs a pinned minimum TCB".into())
                })?;
                snp::derived_key(p)?
            }
            #[cfg(feature = "insecure-dev")]
            Platform::InsecureDev(d) => d.root.clone(),
        };
        Ok(expand(&root, purpose))
    }
}

fn expand(root: &[u8; 32], purpose: &str) -> Zeroizing<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(root).expect("any key length");
    mac.update(SEALING_DOMAIN);
    mac.update(&[0]);
    mac.update(purpose.as_bytes());
    Zeroizing::new(mac.finalize().into_bytes().into())
}

/// AMD SEV-SNP derived keys through the Linux sev-guest driver
/// (`include/uapi/linux/sev-guest.h`).
///
/// NOT YET RUN ON HARDWARE. Struct layouts and the ioctl number are pinned
/// by the tests below against the kernel UAPI header; the end-to-end path
/// still needs a first run on an SNP guest.
mod snp {
    use super::{PlatformError, SnpKeyParams};
    use zeroize::Zeroizing;

    const DEVICE: &str = "/dev/sev-guest";

    /// `_IOWR('S', 0x1, struct snp_guest_request_ioctl)`.
    pub(super) const SNP_GET_DERIVED_KEY: u64 = 0xc020_5301;

    /// SEV-SNP ABI, MSG_KEY_REQ GUEST_FIELD_SELECT.
    pub(super) const FIELD_GUEST_POLICY: u64 = 1 << 0;
    pub(super) const FIELD_MEASUREMENT: u64 = 1 << 3;
    pub(super) const FIELD_TCB_VERSION: u64 = 1 << 5;

    /// `struct snp_derived_key_req`.
    #[repr(C)]
    #[derive(Default)]
    pub(super) struct KeyReq {
        pub root_key_select: u32,
        pub rsvd: u32,
        pub guest_field_select: u64,
        pub vmpl: u32,
        pub guest_svn: u32,
        pub tcb_version: u64,
    }

    /// `struct snp_guest_request_ioctl`.
    #[repr(C)]
    #[derive(Default)]
    pub(super) struct GuestRequest {
        pub msg_version: u8,
        pub req_data: u64,
        pub resp_data: u64,
        pub exitinfo2: u64,
    }

    pub(super) fn request(p: SnpKeyParams) -> KeyReq {
        KeyReq {
            // 0 = VCEK: chip-unique, so the key does not survive a host move.
            root_key_select: 0,
            guest_field_select: FIELD_GUEST_POLICY | FIELD_MEASUREMENT | FIELD_TCB_VERSION,
            vmpl: p.vmpl,
            tcb_version: p.min_tcb,
            ..Default::default()
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn derived_key(p: SnpKeyParams) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        use std::os::fd::AsRawFd;

        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(DEVICE)
            .map_err(|e| PlatformError::Snp(format!("{DEVICE}: {e} (not an SNP guest?)")))?;

        let req = request(p);
        // `struct snp_derived_key_resp`: the firmware's MSG_KEY_RSP, i.e.
        // STATUS (u32), 28 reserved bytes, DERIVED_KEY (32 bytes).
        let mut resp = Zeroizing::new([0u8; 64]);
        let mut ioc = GuestRequest {
            msg_version: 1,
            req_data: &req as *const KeyReq as u64,
            resp_data: resp.as_mut_ptr() as u64,
            exitinfo2: 0,
        };
        // SAFETY: `ioc` points at a live request and a 64-byte response
        // buffer matching the kernel's struct sizes (pinned in tests); the
        // kernel copies in/out of them during the call only.
        let rc = unsafe {
            libc::ioctl(
                dev.as_raw_fd(),
                SNP_GET_DERIVED_KEY as _,
                &mut ioc as *mut GuestRequest,
            )
        };
        if rc != 0 {
            return Err(PlatformError::Snp(format!(
                "ioctl failed: {} (fw_error {:#x}, vmm_error {:#x})",
                std::io::Error::last_os_error(),
                ioc.exitinfo2 & 0xffff_ffff,
                ioc.exitinfo2 >> 32,
            )));
        }
        parse_response(&resp)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn derived_key(_: SnpKeyParams) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        Err(PlatformError::Snp("only supported on Linux".into()))
    }

    pub(super) fn parse_response(data: &[u8; 64]) -> Result<Zeroizing<[u8; 32]>, PlatformError> {
        let status = u32::from_le_bytes(data[0..4].try_into().expect("4 bytes"));
        if status != 0 {
            // 0x16: invalid parameters, e.g. min TCB above the committed TCB.
            return Err(PlatformError::Snp(format!(
                "firmware status {status:#x} (0x16 = invalid parameters: is the minimum TCB above the platform's committed TCB?)"
            )));
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&data[32..64]);
        Ok(key)
    }
}

#[cfg(feature = "insecure-dev")]
pub mod dev {
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;

    use sha2::{Digest, Sha384};
    use zeroize::Zeroizing;

    use crate::tee::Evidence;

    pub const PROVIDER: &str = "insecure_dev";

    /// Size of an SNP ATTESTATION_REPORT; the dev report reuses its layout.
    const REPORT_LEN: usize = 0x4A0;

    pub struct Dev {
        pub(super) root: Zeroizing<[u8; 32]>,
        measurement: [u8; 48],
    }

    impl Dev {
        /// Loads the root key, creating a random one (mode 0600) if absent.
        pub fn open(path: PathBuf) -> std::io::Result<Self> {
            let root = match fs::read(&path) {
                Ok(b) => Zeroizing::new(b.as_slice().try_into().map_err(|_| {
                    std::io::Error::other(format!("{}: must be 32 bytes", path.display()))
                })?),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    let mut k = Zeroizing::new([0u8; 32]);
                    fs::File::open("/dev/urandom")
                        .and_then(|mut f| std::io::Read::read_exact(&mut f, k.as_mut()))?;
                    let mut opts = fs::OpenOptions::new();
                    opts.write(true).create_new(true);
                    #[cfg(unix)]
                    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
                    opts.open(&path)?.write_all(k.as_ref())?;
                    tracing::warn!(path = %path.display(), "generated a new insecure-dev root key");
                    k
                }
                Err(e) => return Err(e),
            };
            // Stand-in for the launch measurement: the running binary.
            let measurement = std::env::current_exe()
                .and_then(fs::read)
                .map(|b| Sha384::digest(b).into())
                .unwrap_or([0u8; 48]);
            Ok(Dev { root, measurement })
        }

        /// An unsigned report in SNP layout (REPORT_DATA at 0x50,
        /// MEASUREMENT at 0x90), with the debug policy bit set, because a
        /// process on a normal host has no confidentiality.
        pub fn evidence(&self, report_data: &[u8; 64]) -> Evidence {
            let mut r = vec![0u8; REPORT_LEN];
            r[0..4].copy_from_slice(&2u32.to_le_bytes());
            let policy: u64 = (1 << 17) | (1 << 19);
            r[0x08..0x10].copy_from_slice(&policy.to_le_bytes());
            r[0x50..0x90].copy_from_slice(report_data);
            r[0x90..0xC0].copy_from_slice(&self.measurement);
            Evidence {
                provider: PROVIDER.into(),
                report: r,
                auxblob: None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    // Values from include/uapi/linux/sev-guest.h, compiled with the
    // kernel headers: SNP_GET_DERIVED_KEY = 0xc0205301, request ioctl 32
    // bytes (req_data @8, resp_data @16, exitinfo2 @24), derived key
    // request 32 bytes (tcb_version @24), response 64 bytes.
    #[test]
    fn snp_uapi_layout() {
        assert_eq!(size_of::<snp::GuestRequest>(), 32);
        assert_eq!(offset_of!(snp::GuestRequest, req_data), 8);
        assert_eq!(offset_of!(snp::GuestRequest, resp_data), 16);
        assert_eq!(offset_of!(snp::GuestRequest, exitinfo2), 24);
        assert_eq!(size_of::<snp::KeyReq>(), 32);
        assert_eq!(offset_of!(snp::KeyReq, guest_field_select), 8);
        assert_eq!(offset_of!(snp::KeyReq, vmpl), 16);
        assert_eq!(offset_of!(snp::KeyReq, tcb_version), 24);

        // _IOWR('S', 1, 32 bytes): dir RW (3) << 30 | size << 16 | 'S' << 8 | 1.
        let ioc = (3u64 << 30) | ((size_of::<snp::GuestRequest>() as u64) << 16) | (0x53 << 8) | 1;
        assert_eq!(ioc, snp::SNP_GET_DERIVED_KEY);
    }

    #[test]
    fn snp_request_mixes_policy_measurement_and_min_tcb() {
        let r = snp::request(SnpKeyParams {
            min_tcb: 0xdb18_0000_0000_0304,
            vmpl: 0,
        });
        assert_eq!(r.root_key_select, 0, "VCEK root");
        assert_eq!(r.guest_field_select, 0b10_1001);
        assert_eq!(r.tcb_version, 0xdb18_0000_0000_0304);
    }

    #[test]
    fn snp_response_parsing() {
        let mut data = [0u8; 64];
        data[32..].copy_from_slice(&[7u8; 32]);
        assert_eq!(*snp::parse_response(&data).unwrap(), [7u8; 32]);
        data[0] = 0x16;
        assert!(snp::parse_response(&data).is_err());
    }

    #[test]
    fn sealing_keys_are_domain_separated() {
        let root = [1u8; 32];
        assert_ne!(*expand(&root, "data-disk"), *expand(&root, "other"));
        assert_eq!(*expand(&root, "data-disk"), *expand(&root, "data-disk"));
    }

    #[test]
    fn tee_sealing_key_requires_min_tcb() {
        assert!(matches!(
            Platform::Tee.sealing_key("data-disk", None),
            Err(PlatformError::Config(_))
        ));
    }

    #[cfg(not(feature = "insecure-dev"))]
    #[test]
    fn insecure_dev_needs_the_feature() {
        assert!(Platform::new(PlatformKind::InsecureDev, Some("x".into())).is_err());
    }

    #[cfg(feature = "insecure-dev")]
    #[test]
    fn insecure_dev_root_key_persists_and_models_host_move() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root.key");
        let a = Platform::new(PlatformKind::InsecureDev, Some(path.clone())).unwrap();
        let b = Platform::new(PlatformKind::InsecureDev, Some(path.clone())).unwrap();
        let ka = a.sealing_key("data-disk", None).unwrap();
        assert_eq!(*ka, *b.sealing_key("data-disk", None).unwrap());
        std::fs::remove_file(&path).unwrap();
        let c = Platform::new(PlatformKind::InsecureDev, Some(path)).unwrap();
        assert_ne!(*ka, *c.sealing_key("data-disk", None).unwrap());
    }

    #[cfg(feature = "insecure-dev")]
    #[test]
    fn insecure_dev_evidence_is_labelled_and_debuggable() {
        let dir = tempfile::tempdir().unwrap();
        let p = Platform::new(PlatformKind::InsecureDev, Some(dir.path().join("k"))).unwrap();
        assert!(p.is_insecure());
        let rd = [9u8; 64];
        let ev = p.evidence(&rd).unwrap();
        assert_eq!(ev.provider, dev::PROVIDER);
        let l = tee::layout(&ev.provider).unwrap();
        assert_eq!(&ev.report[l.report_data..l.report_data + 64], &rd);
        assert_eq!(tee::snp_debug_allowed(&ev.report), Some(true));
    }
}
