//! EIP-2335 keystore decryption and BLS key handling.

use std::collections::BTreeMap;
use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

/// Proof-of-possession ciphersuite used by Ethereum consensus.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed keystore: {0}")]
    Malformed(String),
    #[error("wrong password (checksum mismatch)")]
    BadPassword,
    #[error("unsupported {0}")]
    Unsupported(String),
    #[error("invalid secret key")]
    BadKey,
    #[error("decrypted key does not match keystore pubkey")]
    PubkeyMismatch,
}

#[derive(Deserialize)]
struct Keystore {
    crypto: Crypto,
    #[serde(default)]
    pubkey: Option<String>,
    version: u32,
}

#[derive(Deserialize)]
struct Module<P> {
    function: String,
    params: P,
    message: String,
}

#[derive(Deserialize)]
struct Crypto {
    kdf: Module<serde_json::Value>,
    checksum: Module<serde_json::Value>,
    cipher: Module<CipherParams>,
}

#[derive(Deserialize)]
struct CipherParams {
    iv: String,
}

#[derive(Deserialize)]
struct ScryptParams {
    dklen: usize,
    n: u64,
    r: u32,
    p: u32,
    salt: String,
}

#[derive(Deserialize)]
struct Pbkdf2Params {
    dklen: usize,
    c: u32,
    prf: String,
    salt: String,
}

fn unhex(s: &str) -> Result<Vec<u8>, KeystoreError> {
    hex::decode(s.trim_start_matches("0x")).map_err(|e| KeystoreError::Malformed(e.to_string()))
}

/// EIP-2335 password processing: NFKD, then strip C0, C1 and DEL control codes.
fn normalize_password(password: &str) -> Zeroizing<Vec<u8>> {
    let s: String = password
        .nfkd()
        .filter(|c| !matches!(*c as u32, 0x00..=0x1f | 0x7f..=0x9f))
        .collect();
    Zeroizing::new(s.into_bytes())
}

fn derive_key(
    kdf: &Module<serde_json::Value>,
    password: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeystoreError> {
    let malformed = |e: serde_json::Error| KeystoreError::Malformed(format!("kdf params: {e}"));
    match kdf.function.as_str() {
        "scrypt" => {
            let p: ScryptParams = serde_json::from_value(kdf.params.clone()).map_err(malformed)?;
            if !p.n.is_power_of_two() || p.n < 2 {
                return Err(KeystoreError::Malformed(
                    "scrypt n must be a power of two".into(),
                ));
            }
            let params = scrypt::Params::new(p.n.trailing_zeros() as u8, p.r, p.p, p.dklen)
                .map_err(|e| KeystoreError::Malformed(format!("scrypt params: {e}")))?;
            let mut dk = Zeroizing::new(vec![0u8; p.dklen]);
            scrypt::scrypt(password, &unhex(&p.salt)?, &params, &mut dk)
                .map_err(|e| KeystoreError::Malformed(format!("scrypt: {e}")))?;
            Ok(dk)
        }
        "pbkdf2" => {
            let p: Pbkdf2Params = serde_json::from_value(kdf.params.clone()).map_err(malformed)?;
            if p.prf != "hmac-sha256" {
                return Err(KeystoreError::Unsupported(format!("pbkdf2 prf {}", p.prf)));
            }
            let mut dk = Zeroizing::new(vec![0u8; p.dklen]);
            pbkdf2::pbkdf2_hmac::<Sha256>(password, &unhex(&p.salt)?, p.c, &mut dk);
            Ok(dk)
        }
        other => Err(KeystoreError::Unsupported(format!("kdf {other}"))),
    }
}

/// Decrypts an EIP-2335 keystore and returns the BLS secret key.
pub fn decrypt(json: &str, password: &str) -> Result<SecretKey, KeystoreError> {
    let ks: Keystore =
        serde_json::from_str(json).map_err(|e| KeystoreError::Malformed(e.to_string()))?;
    if ks.version != 4 {
        return Err(KeystoreError::Unsupported(format!(
            "keystore version {}",
            ks.version
        )));
    }
    let c = &ks.crypto;
    if c.checksum.function != "sha256" {
        return Err(KeystoreError::Unsupported(format!(
            "checksum {}",
            c.checksum.function
        )));
    }
    if c.cipher.function != "aes-128-ctr" {
        return Err(KeystoreError::Unsupported(format!(
            "cipher {}",
            c.cipher.function
        )));
    }

    let dk = derive_key(&c.kdf, &normalize_password(password))?;
    if dk.len() < 32 {
        return Err(KeystoreError::Malformed("dklen must be at least 32".into()));
    }
    let ciphertext = unhex(&c.cipher.message)?;

    let mut h = Sha256::new();
    h.update(&dk[16..32]);
    h.update(&ciphertext);
    let checksum: [u8; 32] = h.finalize().into();
    if checksum.as_slice() != unhex(&c.checksum.message)?.as_slice() {
        return Err(KeystoreError::BadPassword);
    }

    let iv = unhex(&c.cipher.params.iv)?;
    let mut cipher = Aes128Ctr::new_from_slices(&dk[..16], &iv)
        .map_err(|e| KeystoreError::Malformed(format!("cipher params: {e}")))?;
    let mut secret = Zeroizing::new(ciphertext);
    cipher.apply_keystream(&mut secret);

    let sk = SecretKey::from_bytes(&secret)?;
    if let Some(pk) = &ks.pubkey
        && unhex(pk)? != sk.public_key()
    {
        return Err(KeystoreError::PubkeyMismatch);
    }
    Ok(sk)
}

/// BLS secret key. Deliberately not `Debug`; blst zeroizes it on drop.
pub struct SecretKey {
    inner: blst::min_pk::SecretKey,
    public: [u8; 48],
}

impl SecretKey {
    pub fn from_bytes(b: &[u8]) -> Result<Self, KeystoreError> {
        let inner = blst::min_pk::SecretKey::from_bytes(b).map_err(|_| KeystoreError::BadKey)?;
        let public = inner.sk_to_pk().to_bytes();
        Ok(Self { inner, public })
    }

    pub fn public_key(&self) -> [u8; 48] {
        self.public
    }

    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn sign(&self, root: &[u8; 32]) -> [u8; 96] {
        self.inner.sign(root, DST, &[]).to_bytes()
    }
}

/// Loads every `*.json` keystore in `dir` using the password in the sibling
/// `*.txt` file (the layout `charon dkg` writes to `validator_keys/`).
pub fn load_dir(dir: &Path) -> anyhow::Result<BTreeMap<[u8; 48], SecretKey>> {
    let mut keys = BTreeMap::new();
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    entries.sort();

    for path in entries {
        let pw_path = path.with_extension("txt");
        let password = Zeroizing::new(
            std::fs::read_to_string(&pw_path)
                .map_err(|e| anyhow::anyhow!("reading password {}: {e}", pw_path.display()))?,
        );
        let json = std::fs::read_to_string(&path)?;
        let sk = decrypt(&json, password.trim_end_matches(['\n', '\r']))
            .map_err(|e| anyhow::anyhow!("keystore {}: {e}", path.display()))?;
        tracing::info!(pubkey = %format!("0x{}", hex::encode(sk.public_key())), path = %path.display(), "loaded key");
        keys.insert(sk.public_key(), sk);
    }
    Ok(keys)
}

/// An EIP-2335 keystore for `sk` with a one-round pbkdf2 KDF (tests only).
#[cfg(test)]
pub(crate) fn tests_encrypt(sk: &SecretKey, password: &str) -> String {
    let salt = [7u8; 32];
    let iv = [9u8; 16];
    let mut dk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&normalize_password(password), &salt, 1, &mut dk);
    let mut ct = sk.to_bytes().to_vec();
    Aes128Ctr::new_from_slices(&dk[..16], &iv)
        .unwrap()
        .apply_keystream(&mut ct);
    let mut h = Sha256::new();
    h.update(&dk[16..32]);
    h.update(&ct);
    let checksum: [u8; 32] = h.finalize().into();
    serde_json::json!({
        "crypto": {
            "kdf": {"function": "pbkdf2", "params": {"dklen": 32, "c": 1, "prf": "hmac-sha256", "salt": hex::encode(salt)}, "message": ""},
            "checksum": {"function": "sha256", "params": {}, "message": hex::encode(checksum)},
            "cipher": {"function": "aes-128-ctr", "params": {"iv": hex::encode(iv)}, "message": hex::encode(&ct)},
        },
        "pubkey": hex::encode(sk.public_key()),
        "path": "", "uuid": "00000000-0000-4000-8000-000000000001", "version": 4,
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_normalization_strips_control_codes() {
        assert_eq!(
            normalize_password("a\u{7f}b\u{1}c\u{85}").as_slice(),
            b"abc"
        );
        // Fraktur letters NFKD-normalize to ASCII.
        assert_eq!(normalize_password("𝔱𝔢𝔰𝔱").as_slice(), b"test");
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/keystores");
        let json = std::fs::read_to_string(dir.join("keystore-0.json")).unwrap();
        assert!(matches!(
            decrypt(&json, "nope"),
            Err(KeystoreError::BadPassword)
        ));
    }
}
