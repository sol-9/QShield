//! Post-quantum signing keys.
//!
//! A QShield key is an ML-DSA-44 key pair derived deterministically from a
//! 32-byte seed `xi` (FIPS 204 `ML-DSA.KeyGen_internal(xi)`). Only the seed is
//! ever stored (encrypted, see [`crate::keystore`]); the expanded secret key
//! is recomputed when needed and zeroized on drop.

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use qshield_mldsa::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use qshield_protocol::v2::AuthorizationV2;
use qshield_protocol::{key_id, Algorithm, Authorization, Bytes32, ML_DSA_CONTEXT};
use zeroize::Zeroizing;

use crate::Error;

/// Anything that can produce QSP-1 signatures: a local key today; hardware
/// wallets, secure enclaves or offline (QR/air-gapped) signers later.
///
/// Implementations must sign exactly the 292 bytes given, with pure
/// ML-DSA-44 and context [`ML_DSA_CONTEXT`], and must never export the
/// secret key through this interface.
pub trait PqSigner {
    /// Signature algorithm.
    fn algorithm(&self) -> Algorithm {
        Algorithm::MlDsa44
    }
    /// Encoded public key (1,312 bytes).
    fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN];
    /// `SHA-256("QSHIELD_KEY_ID_V1" ‖ alg ‖ pk)`.
    fn key_id(&self) -> Bytes32 {
        key_id(self.algorithm(), self.public_key())
    }
    /// Signs a QSP-1 authorization (v1, 292 bytes, or v2, 317 bytes).
    /// Implementations must refuse anything that does not decode as one.
    fn sign_authorization(&self, auth: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error>;
}

/// An ML-DSA-44 key held in memory.
pub struct LocalKey {
    seed: Zeroizing<[u8; 32]>,
    sk: ml_dsa_44::PrivateKey,
    pk: [u8; PUBLIC_KEY_LEN],
}

impl LocalKey {
    /// Generates a new key from the operating system's CSPRNG. Fails (never
    /// falls back to a weaker source) if the CSPRNG is unavailable.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new([0u8; 32]);
        getrandom::getrandom(seed.as_mut()).map_err(|_| Error::RandomnessUnavailable)?;
        Ok(Self::from_seed(&seed))
    }

    /// Derives the key pair from a 32-byte seed (`ML-DSA.KeyGen_internal`).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(seed);
        Self {
            seed: Zeroizing::new(*seed),
            sk,
            pk: pk.into_bytes(),
        }
    }

    /// The seed. Handle with care: it is the whole secret.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl PqSigner for LocalKey {
    fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.pk
    }

    /// Hedged signing (fresh OS randomness per signature, FIPS 204 Algorithm 2).
    /// Only canonical QSP-1 v1/v2 authorizations are signed: the key is never
    /// used as a general-purpose signing oracle.
    fn sign_authorization(&self, auth: &[u8]) -> Result<[u8; SIGNATURE_LEN], Error> {
        if Authorization::decode(auth).is_err() && AuthorizationV2::decode(auth).is_err() {
            return Err(Error::InvalidInput(
                "refusing to sign: not a canonical QSP-1 authorization".into(),
            ));
        }
        self.sk
            .try_sign(auth, ML_DSA_CONTEXT)
            .map_err(|_| Error::RandomnessUnavailable)
    }
}

impl core::fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print secret material.
        f.debug_struct("LocalKey")
            .field("key_id", &hex::encode(self.key_id()))
            .finish_non_exhaustive()
    }
}

/// Verifies a QSP-1 signature off-chain with the same verifier the program uses.
pub fn verify_authorization(public_key: &[u8], auth: &[u8], signature: &[u8]) -> bool {
    let mut ws = qshield_mldsa::workspace_vec();
    let ws: &mut qshield_mldsa::Workspace = ws.as_mut_slice().try_into().expect("workspace size");
    qshield_mldsa::verify(public_key, auth, ML_DSA_CONTEXT, signature, ws).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let k = LocalKey::generate().unwrap();
        assert!(k.sign_authorization(&[3u8; 292]).is_err(), "not QSP-1");
        let auth = sample_auth();
        let s1 = k.sign_authorization(&auth).unwrap();
        let s2 = k.sign_authorization(&auth).unwrap();
        assert_ne!(s1, s2, "hedged signing must randomize");
        assert!(verify_authorization(k.public_key(), &auth, &s1));
        assert!(verify_authorization(k.public_key(), &auth, &s2));
        let mut bad = auth;
        bad[0] ^= 1;
        assert!(!verify_authorization(k.public_key(), &bad, &s1));
    }

    /// A canonical QSP-1 v1 authorization.
    pub(crate) fn sample_auth() -> [u8; qshield_protocol::AUTH_LEN] {
        use qshield_protocol::{cluster, Action, AssetType, ZERO32};
        Authorization {
            cluster_id: cluster::DEVNET,
            program_id: [1; 32],
            vault: [2; 32],
            action: Action::Pause,
            asset_type: AssetType::None,
            nonce: 0,
            valid_after: 0,
            expires_at: 0,
            mint: ZERO32,
            destination: ZERO32,
            amount: 0,
            decimals: 0,
            fee_recipient: ZERO32,
            fee_lamports: 0,
            new_key_id: ZERO32,
            new_algorithm: 0,
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn seed_determines_key() {
        let a = LocalKey::from_seed(&[9; 32]);
        let b = LocalKey::from_seed(&[9; 32]);
        assert_eq!(a.public_key(), b.public_key());
        assert!(!format!("{a:?}").contains(&hex::encode([9u8; 32])));
    }
}
