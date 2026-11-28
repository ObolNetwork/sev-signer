//! Test keystores: EIP-2335 with pbkdf2 at one iteration, so thousands of
//! keys load in seconds. The signer already accepts any pbkdf2 count, so no
//! test-only code path is needed in it. These keys are derived from a public
//! seed and are worthless: never deposit them.

use std::path::{Path, PathBuf};

use aes::cipher::{KeyIvInit, StreamCipher};
use anyhow::Context;
use sha2::{Digest, Sha256};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// A random password for one key directory. It is written next to each
/// keystore, so cached keystores keep working; the keys themselves still come
/// from the public seed.
fn random_password() -> anyhow::Result<String> {
    let b = ring::rand::generate::<[u8; 16]>(&ring::rand::SystemRandom::new())
        .map_err(|_| anyhow::anyhow!("no randomness"))?;
    Ok(hex::encode(b.expose()))
}

fn ikm(i: usize) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"dvtee-load key ")
        .chain_update((i as u64).to_le_bytes())
        .finalize()
        .into()
}

fn keystore_json(i: usize, password: &str) -> anyhow::Result<(String, [u8; 48])> {
    let sk = blst::min_pk::SecretKey::key_gen(&ikm(i), &[])
        .map_err(|e| anyhow::anyhow!("key_gen: {e:?}"))?;
    let pk = sk.sk_to_pk().to_bytes();
    let salt: [u8; 32] = Sha256::digest(ikm(i)).into();
    let iv = [i as u8; 16];

    let mut dk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 1, &mut dk);
    let mut ct = sk.to_bytes().to_vec();
    Aes128Ctr::new_from_slices(&dk[..16], &iv)
        .expect("key and iv sizes")
        .apply_keystream(&mut ct);
    let checksum = Sha256::new()
        .chain_update(&dk[16..32])
        .chain_update(&ct)
        .finalize();

    let json = serde_json::json!({
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {"dklen": 32, "c": 1, "prf": "hmac-sha256", "salt": hex::encode(salt)},
                "message": "",
            },
            "checksum": {"function": "sha256", "params": {}, "message": hex::encode(checksum)},
            "cipher": {
                "function": "aes-128-ctr",
                "params": {"iv": hex::encode(iv)},
                "message": hex::encode(&ct),
            },
        },
        "description": "dvtee load test key (public seed, do not use)",
        "pubkey": hex::encode(pk),
        "path": "",
        "uuid": format!("00000000-0000-4000-8000-{i:012x}"),
        "version": 4,
    });
    Ok((json.to_string(), pk))
}

/// Writes `n` keystores to `<root>/keys-<n>/` unless already there, and
/// returns the directory.
pub fn ensure(root: &Path, n: usize) -> anyhow::Result<PathBuf> {
    let dir = root.join(format!("keys-{n}"));
    let done = dir.join(".complete");
    if done.exists() {
        return Ok(dir);
    }
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let started = std::time::Instant::now();
    let password = random_password()?;
    let password = password.as_str();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|t| {
                let dir = &dir;
                s.spawn(move || -> anyhow::Result<()> {
                    for i in (t..n).step_by(threads) {
                        let (json, _) = keystore_json(i, password)?;
                        std::fs::write(dir.join(format!("keystore-{i}.json")), json)?;
                        std::fs::write(dir.join(format!("keystore-{i}.txt")), password)?;
                    }
                    Ok(())
                })
            })
            .collect();
        handles
            .into_iter()
            .try_for_each(|h| h.join().expect("keygen thread panicked"))
    })?;
    std::fs::write(&done, b"")?;
    eprintln!(
        "wrote {n} keystores to {} in {:.1?}",
        dir.display(),
        started.elapsed()
    );
    Ok(dir)
}

#[cfg(test)]
mod tests {
    #[test]
    fn keystore_decrypts_with_the_signer() {
        let password = super::random_password().unwrap();
        let (json, pk) = super::keystore_json(7, &password).unwrap();
        let sk = dvtee::keystore::decrypt(&json, &password).unwrap();
        assert_eq!(sk.public_key(), pk);
    }
}
