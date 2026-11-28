//! Settings pinned from the cluster lock.
//!
//! On first start with `--cluster-lock`, the signer checks the lock, checks
//! that every loaded key is one of its public shares at a single operator
//! index, and stores the lock on its (sealed) data disk. From then on it
//! refuses to start with any other lock: a new lock means new shares, which
//! means a new signer (a reshare or recover into a fresh guest), not an edit.
//!
//! The pinned lock fixes the fee recipient of each validator. Requests that
//! carry a fee recipient are refused unless it matches:
//! `VALIDATOR_REGISTRATION` (whose `pubkey` must be the share's validator or
//! the share itself), Gloas `PROPOSER_PREFERENCES`, and self-built Gloas
//! `EXECUTION_PAYLOAD_ENVELOPE`s. Pre-Gloas blocks are signed as headers, so
//! their fee recipient can't be checked here. Gas limits are not pinned.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::lock::{ClusterLock, Located, LockValidator};
use crate::signing::{PrepareError, SignBody};
use crate::ssz::Root;

const PINNED_FILE: &str = "cluster-lock.json";

#[derive(Clone, Debug)]
pub struct Pins {
    pub lock_hash: Root,
    pub operator_index: usize,
    pub validators: usize,
    located: Located,
}

impl Pins {
    fn from_lock(lock: &ClusterLock, keys: &[[u8; 48]]) -> anyhow::Result<Self> {
        lock.verify_aggregate()?;
        let located = lock.locate(keys)?;
        Ok(Self {
            lock_hash: lock.lock_hash,
            operator_index: located.operator_index,
            validators: lock.validators.len(),
            located,
        })
    }

    /// Loads the pinned lock from `data_dir`, or pins `given` if nothing is
    /// pinned yet. Returns `None` when there is neither.
    pub fn load_or_pin(
        data_dir: &Path,
        given: Option<&Path>,
        keys: &[[u8; 48]],
    ) -> anyhow::Result<Option<Self>> {
        let pinned_path = data_dir.join(PINNED_FILE);
        let pinned = match fs::read(&pinned_path) {
            Ok(b) => Some(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };

        match (pinned, given) {
            (None, None) => Ok(None),
            (Some(bytes), given) => {
                let lock = ClusterLock::parse(&bytes)
                    .map_err(|e| anyhow::anyhow!("pinned {}: {e}", pinned_path.display()))?;
                if let Some(path) = given {
                    let other = ClusterLock::parse(&fs::read(path)?)
                        .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                    anyhow::ensure!(
                        other.lock_hash == lock.lock_hash,
                        "this signer is pinned to cluster lock 0x{}; {} is 0x{}. \
                         A new lock needs a new signer (reshare or recover into a fresh guest)",
                        hex::encode(lock.lock_hash),
                        path.display(),
                        hex::encode(other.lock_hash)
                    );
                }
                Self::from_lock(&lock, keys)
                    .map(Some)
                    .map_err(|e| anyhow::anyhow!("pinned cluster lock: {e}"))
            }
            (None, Some(path)) => {
                let bytes = fs::read(path)?;
                let lock = ClusterLock::parse(&bytes)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                let pins = Self::from_lock(&lock, keys)
                    .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
                write_durable(data_dir, &pinned_path, &bytes)?;
                tracing::info!(
                    lock_hash = %format!("0x{}", hex::encode(lock.lock_hash)),
                    operator_index = pins.operator_index,
                    "pinned cluster lock"
                );
                Ok(Some(pins))
            }
        }
    }

    /// The distributed validator's group public key for one of this signer's
    /// shares.
    pub fn validator_of(&self, share: &[u8; 48]) -> Option<[u8; 48]> {
        self.located.by_share.get(share).map(|v| v.pubkey)
    }

    fn validator(&self, share: &[u8; 48]) -> Result<&LockValidator, PrepareError> {
        self.located.by_share.get(share).ok_or_else(|| {
            PrepareError::Refused("key is not a share in the pinned cluster lock".into())
        })
    }

    /// Refuses a request whose fee recipient differs from the pinned lock, or
    /// a registration whose pubkey is neither the validator's nor this share.
    pub fn check(&self, share: &[u8; 48], body: &SignBody) -> Result<(), PrepareError> {
        let v = self.validator(share)?;
        let fee_recipient = |kind: &str, got: &[u8; 20]| {
            if *got == v.fee_recipient {
                Ok(())
            } else {
                Err(PrepareError::Refused(format!(
                    "{kind} fee recipient 0x{} is not the cluster lock's 0x{}",
                    hex::encode(got),
                    hex::encode(v.fee_recipient)
                )))
            }
        };
        match body {
            SignBody::ValidatorRegistration {
                validator_registration: r,
            } => {
                // A DV's validator client only knows its share, so it puts the
                // share in `pubkey`; charon registers with the lock's own
                // registration instead. Accept either, with the lock's fee
                // recipient.
                if r.pubkey.0 != v.pubkey && r.pubkey.0 != *share {
                    return Err(PrepareError::Refused(format!(
                        "VALIDATOR_REGISTRATION for 0x{}, but this share belongs to 0x{}",
                        hex::encode(r.pubkey.0),
                        hex::encode(v.pubkey)
                    )));
                }
                fee_recipient("VALIDATOR_REGISTRATION", &r.fee_recipient.0)
            }
            SignBody::ProposerPreferences {
                proposer_preferences: p,
                ..
            } => fee_recipient("PROPOSER_PREFERENCES", &p.data.fee_recipient.0),
            SignBody::ExecutionPayloadEnvelope {
                execution_payload_envelope: e,
                ..
            } => fee_recipient(
                "EXECUTION_PAYLOAD_ENVELOPE",
                &e.data.payload.fee_recipient.0,
            ),
            _ => Ok(()),
        }
    }
}

/// Writes `path` via a temporary file, fsyncing the file and the directory.
pub(crate) fn write_durable(dir: &Path, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    fs::File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lock::testlock::{Spec, build, secret};
    use crate::signing::SignRequest;
    use serde_json::{Value, json};

    const FR: [u8; 20] = [0x11; 20];

    fn spec() -> Spec {
        Spec {
            threshold: 3,
            validators: vec![(FR, (0..4).map(secret).collect())],
        }
    }

    fn hx(b: &[u8]) -> String {
        format!("0x{}", hex::encode(b))
    }

    fn body(v: Value) -> SignBody {
        serde_json::from_value::<SignRequest>(v).unwrap().body
    }

    fn example(name: &str) -> Value {
        let all: Value = serde_json::from_str(include_str!(
            "../tests/vectors/web3signer-gloas-examples.json"
        ))
        .unwrap();
        let mut v = all["examples"][name].clone();
        // Web3Signer's envelope example has a 262-byte logs_bloom.
        if let Some(p) = v.pointer_mut("/execution_payload_envelope/data/payload/logs_bloom") {
            *p = hx(&[0u8; 256]).into();
        }
        v
    }

    #[test]
    fn pins_once_and_refuses_another_lock() {
        let s = spec();
        let key = s.validators[0].1[1].public_key();
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("lock.json");
        std::fs::write(&lock_path, build(&s)).unwrap();
        let data = dir.path().join("data");

        assert!(Pins::load_or_pin(&data, None, &[key]).unwrap().is_none());
        let pins = Pins::load_or_pin(&data, Some(&lock_path), &[key])
            .unwrap()
            .unwrap();
        assert_eq!(pins.operator_index, 1);
        assert!(data.join(PINNED_FILE).exists());

        // Restarts: without the flag, or with the same lock.
        assert!(Pins::load_or_pin(&data, None, &[key]).unwrap().is_some());
        assert!(
            Pins::load_or_pin(&data, Some(&lock_path), &[key])
                .unwrap()
                .is_some()
        );

        // A different lock (another fee recipient) is refused.
        let mut other = spec();
        other.validators[0].0 = [0x99; 20];
        let other_path = dir.path().join("other.json");
        std::fs::write(&other_path, build(&other)).unwrap();
        let e = Pins::load_or_pin(&data, Some(&other_path), &[key])
            .unwrap_err()
            .to_string();
        assert!(e.contains("pinned"), "{e}");

        // A key that isn't in the pinned lock is refused.
        assert!(Pins::load_or_pin(&data, None, &[secret(77).public_key()]).is_err());
    }

    #[test]
    fn checks_fee_recipients() {
        let s = spec();
        let key = s.validators[0].1[0].public_key();
        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("lock.json");
        let json = build(&s);
        std::fs::write(&lock_path, &json).unwrap();
        let pins = Pins::load_or_pin(dir.path(), Some(&lock_path), &[key])
            .unwrap()
            .unwrap();
        let dv: Value = serde_json::from_slice(&json).unwrap();
        let dv_pubkey = dv["distributed_validators"][0]["distributed_public_key"].clone();

        let reg = |fr: [u8; 20], pk: Value| {
            body(
                json!({"type": "VALIDATOR_REGISTRATION", "validator_registration": {
                "fee_recipient": hx(&fr), "gas_limit": "60000000", "timestamp": "1764115200",
                "pubkey": pk}}),
            )
        };
        assert!(pins.check(&key, &reg(FR, dv_pubkey.clone())).is_ok());
        assert!(
            pins.check(&key, &reg([0x66; 20], dv_pubkey.clone()))
                .is_err()
        );
        assert!(pins.check(&key, &reg(FR, hx(&[0x31; 48]).into())).is_err());
        // The share itself, as a DV's validator client sends it.
        assert!(pins.check(&key, &reg(FR, hx(&key).into())).is_ok());
        assert!(pins.check(&key, &reg([0x66; 20], hx(&key).into())).is_err());
        // Another operator's share of the same validator is refused.
        let other = s.validators[0].1[1].public_key();
        assert!(pins.check(&key, &reg(FR, hx(&other).into())).is_err());

        let mut prefs = example("PROPOSER_PREFERENCES (GLOAS)");
        assert!(pins.check(&key, &body(prefs.clone())).is_err());
        prefs["proposer_preferences"]["data"]["fee_recipient"] = hx(&FR).into();
        assert!(pins.check(&key, &body(prefs)).is_ok());

        let mut env = example("EXECUTION_PAYLOAD_ENVELOPE (GLOAS)");
        assert!(pins.check(&key, &body(env.clone())).is_err());
        env["execution_payload_envelope"]["data"]["payload"]["fee_recipient"] = hx(&FR).into();
        assert!(pins.check(&key, &body(env)).is_ok());

        // Duties without a fee recipient pass through.
        assert!(
            pins.check(&key, &body(example("PAYLOAD_ATTESTATION_MESSAGE (GLOAS)")))
                .is_ok()
        );
        // A key not in the lock is refused outright.
        assert!(
            pins.check(&secret(77).public_key(), &reg(FR, dv_pubkey))
                .is_err()
        );
    }
}
