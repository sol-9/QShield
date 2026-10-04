//! Encrypted key files (`docs/KEYSTORE.md`).
//!
//! The 32-byte ML-DSA seed is encrypted with XChaCha20-Poly1305 under a key
//! derived from a password with Argon2id. All public header fields are bound
//! as associated data, and after decryption the public key is re-derived and
//! compared with the file, so a tampered file cannot yield a different key.
//!
//! **This is software key storage.** It protects a key file at rest against
//! someone who does not know the password; it does not protect against
//! malware on the machine where the password is typed. It is not comparable
//! to a hardware wallet.

use argon2::{Algorithm as ArgonAlg, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use qshield_protocol::Bytes32;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::key::{LocalKey, PqSigner};
use crate::Error;

/// Format version.
pub const KEYSTORE_VERSION: u32 = 1;
/// Associated-data domain tag.
const AAD_DOMAIN: &[u8] = b"QSHIELD_KEYSTORE_V1";

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl KdfParams {
    /// Default for interactive use: 64 MiB, 3 passes, 1 lane.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 64 * 1024,
        t_cost: 3,
        p_cost: 1,
    };
    /// Cheap parameters **for tests and test vectors only**.
    pub const INSECURE_TEST: Self = Self {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    fn check(&self) -> Result<(), Error> {
        // Bound costs a file can demand (denial of service when opening an
        // untrusted file) while allowing the test parameters.
        if self.m_cost_kib < 8 * self.p_cost.max(1)
            || self.m_cost_kib > 2 * 1024 * 1024
            || self.t_cost == 0
            || self.t_cost > 64
            || self.p_cost == 0
            || self.p_cost > 16
        {
            return Err(Error::Keystore("unsupported KDF parameters"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct KdfSection {
    name: String,
    version: u32,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CipherSection {
    name: String,
    nonce: String,
}

/// An encrypted key file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keystore {
    qshield_keystore: u32,
    algorithm: String,
    /// Hex public key (public data, kept for convenience).
    pub public_key: String,
    /// Hex key id.
    pub key_id: String,
    kdf: KdfSection,
    cipher: CipherSection,
    ciphertext: String,
}

fn aad(key_id: &Bytes32, p: &KdfParams, salt: &[u8; 16]) -> Vec<u8> {
    let mut v = Vec::with_capacity(80);
    v.extend_from_slice(AAD_DOMAIN);
    v.push(1); // algorithm: ML-DSA-44
    v.extend_from_slice(key_id);
    v.extend_from_slice(&p.m_cost_kib.to_le_bytes());
    v.extend_from_slice(&p.t_cost.to_le_bytes());
    v.extend_from_slice(&p.p_cost.to_le_bytes());
    v.extend_from_slice(salt);
    v
}

fn derive(password: &str, salt: &[u8; 16], p: &KdfParams) -> Result<Zeroizing<[u8; 32]>, Error> {
    p.check()?;
    let params = Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))
        .map_err(|_| Error::Keystore("bad KDF parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(ArgonAlg::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, out.as_mut())
        .map_err(|_| Error::Keystore("key derivation failed"))?;
    Ok(out)
}

impl Keystore {
    /// Encrypts `key` under `password` with fresh random salt and nonce.
    pub fn encrypt(key: &LocalKey, password: &str, params: KdfParams) -> Result<Self, Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut salt).map_err(|_| Error::RandomnessUnavailable)?;
        getrandom::getrandom(&mut nonce).map_err(|_| Error::RandomnessUnavailable)?;
        Self::encrypt_with(key, password, params, salt, nonce)
    }

    /// Deterministic variant for test vectors. Never reuse a (password, salt, nonce).
    pub fn encrypt_with(
        key: &LocalKey,
        password: &str,
        params: KdfParams,
        salt: [u8; 16],
        nonce: [u8; 24],
    ) -> Result<Self, Error> {
        if password.is_empty() {
            return Err(Error::Keystore("empty password"));
        }
        let key_id = key.key_id();
        let k = derive(password, &salt, &params)?;
        let cipher = XChaCha20Poly1305::new(k.as_ref().into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: key.seed(),
                    aad: &aad(&key_id, &params, &salt),
                },
            )
            .map_err(|_| Error::Keystore("encryption failed"))?;
        Ok(Self {
            qshield_keystore: KEYSTORE_VERSION,
            algorithm: "ML-DSA-44".into(),
            public_key: hex::encode(key.public_key()),
            key_id: hex::encode(key_id),
            kdf: KdfSection {
                name: "argon2id".into(),
                version: 0x13,
                m_cost_kib: params.m_cost_kib,
                t_cost: params.t_cost,
                p_cost: params.p_cost,
                salt: hex::encode(salt),
            },
            cipher: CipherSection {
                name: "xchacha20-poly1305".into(),
                nonce: hex::encode(nonce),
            },
            ciphertext: hex::encode(ct),
        })
    }

    /// Decrypts and returns the key. Fails on a wrong password or any tampering.
    pub fn decrypt(&self, password: &str) -> Result<LocalKey, Error> {
        if self.qshield_keystore != KEYSTORE_VERSION
            || self.algorithm != "ML-DSA-44"
            || self.kdf.name != "argon2id"
            || self.kdf.version != 0x13
            || self.cipher.name != "xchacha20-poly1305"
        {
            return Err(Error::Keystore("unsupported keystore format"));
        }
        let params = KdfParams {
            m_cost_kib: self.kdf.m_cost_kib,
            t_cost: self.kdf.t_cost,
            p_cost: self.kdf.p_cost,
        };
        let salt: [u8; 16] = hex_array(&self.kdf.salt)?;
        let nonce: [u8; 24] = hex_array(&self.cipher.nonce)?;
        let key_id: Bytes32 = hex_array(&self.key_id)?;
        let ct = hex::decode(&self.ciphertext).map_err(|_| Error::Keystore("bad hex"))?;
        let k = derive(password, &salt, &params)?;
        let cipher = XChaCha20Poly1305::new(k.as_ref().into());
        let seed = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ct,
                        aad: &aad(&key_id, &params, &salt),
                    },
                )
                .map_err(|_| Error::Keystore("wrong password or corrupted file"))?,
        );
        let seed: &[u8; 32] = seed
            .as_slice()
            .try_into()
            .map_err(|_| Error::Keystore("bad seed length"))?;
        let key = LocalKey::from_seed(seed);
        if key.key_id() != key_id || hex::encode(key.public_key()) != self.public_key.to_lowercase()
        {
            return Err(Error::Keystore(
                "public key does not match the encrypted seed",
            ));
        }
        Ok(key)
    }

    /// Key id without decrypting (public data).
    pub fn key_id_bytes(&self) -> Result<Bytes32, Error> {
        hex_array(&self.key_id)
    }

    /// Public key without decrypting (public data).
    pub fn public_key_bytes(&self) -> Result<Vec<u8>, Error> {
        hex::decode(&self.public_key).map_err(|_| Error::Keystore("bad hex"))
    }

    /// Serializes to pretty JSON.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("serializable") + "\n"
    }

    /// Parses JSON.
    pub fn from_json(s: &str) -> Result<Self, Error> {
        serde_json::from_str(s).map_err(|_| Error::Keystore("invalid keystore JSON"))
    }
}

fn hex_array<const N: usize>(s: &str) -> Result<[u8; N], Error> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(Error::Keystore("bad hex field"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_tamper_detection() {
        let key = LocalKey::from_seed(&[5; 32]);
        let ks = Keystore::encrypt(&key, "correct horse", KdfParams::INSECURE_TEST).unwrap();
        let back = Keystore::from_json(&ks.to_json())
            .unwrap()
            .decrypt("correct horse")
            .unwrap();
        assert_eq!(back.seed(), key.seed());
        assert!(ks.decrypt("wrong").is_err());
        // Any change to authenticated header data breaks decryption.
        let mut t = ks.clone();
        t.kdf.t_cost = 2;
        assert!(t.decrypt("correct horse").is_err());
        let mut t = ks.clone();
        t.key_id = hex::encode([0u8; 32]);
        assert!(t.decrypt("correct horse").is_err());
        let mut t = ks.clone();
        t.public_key = hex::encode(LocalKey::from_seed(&[6; 32]).public_key());
        assert!(t.decrypt("correct horse").is_err());
        let mut t = ks.clone();
        let mut c = hex::decode(&t.ciphertext).unwrap();
        c[0] ^= 1;
        t.ciphertext = hex::encode(c);
        assert!(t.decrypt("correct horse").is_err());
        // DoS bounds.
        let mut t = ks;
        t.kdf.m_cost_kib = u32::MAX;
        assert!(t.decrypt("correct horse").is_err());
        assert!(Keystore::encrypt(&key, "", KdfParams::INSECURE_TEST).is_err());
    }
}
