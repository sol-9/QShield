//! Verify-only, low-memory implementation of FIPS 204 **ML-DSA-44** signature
//! verification, designed to run inside the Solana SBF virtual machine.
//!
//! # Why a dedicated verifier?
//!
//! Existing Rust ML-DSA implementations (e.g. `fips204`, RustCrypto `ml-dsa`)
//! materialise the full expanded matrix `A_hat` (16 KiB for ML-DSA-44) and
//! several vectors of polynomials as stack values. The SBF runtime limits each
//! stack frame to 4 KiB, so those implementations fail `cargo build-sbf`'s
//! stack checks (measured: 10,880-byte frame for `fips204 0.4.6`). See
//! `docs/MLDSA_SOLANA_FEASIBILITY.md` for the measurements.
//!
//! This crate implements exactly the verification algorithm of FIPS 204
//! (Algorithm 3 `ML-DSA.Verify` and Algorithm 8 `ML-DSA.Verify_internal`), but
//! evaluates `w'_approx = NTT^-1(A_hat ∘ NTT(z) - NTT(c) ∘ NTT(t1 * 2^d))` one
//! row at a time, regenerating each `A_hat[r][s]` with `RejNTTPoly` on demand
//! and absorbing `w1Encode` of each row into the final hash as soon as it is
//! available. The mathematical result is identical; only the evaluation order
//! and memory footprint differ. All scratch memory lives in a caller-provided
//! [`Workspace`] (7 KiB) so it can be placed on the heap.
//!
//! The implementation is tested against the NIST ACVP vectors and
//! differentially against two independent implementations (`fips204` and
//! RustCrypto `ml-dsa`). It has **not** been independently audited.
//!
//! # Scope
//!
//! * Only ML-DSA-44 is implemented.
//! * Only *pure* ML-DSA (not HashML-DSA) is exposed for message verification.
//! * Signing and key generation are intentionally absent: private keys never
//!   touch this crate.
#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod encoding;
pub mod params;
pub mod poly;
pub mod sample;

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

use encoding::{decode_t1_shifted, decode_z, pack_w1, Hints};
use params::*;
pub use params::{C_TILDE_LEN, MAX_CONTEXT_LEN, MU_LEN, PUBLIC_KEY_LEN, SIGNATURE_LEN, TR_LEN};
use poly::{from_centered, inv_ntt, ntt, pointwise_mul_acc, pointwise_mul_sub, Poly};
use sample::{rej_ntt_poly, sample_in_ball};

/// Reasons a verification can fail. All of them mean "signature invalid";
/// they are distinguished only for diagnostics and testing. Verification only
/// processes public data, so exposing the reason leaks nothing secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The public key is not exactly [`PUBLIC_KEY_LEN`] bytes.
    PublicKeyLength,
    /// The signature is not exactly [`SIGNATURE_LEN`] bytes.
    SignatureLength,
    /// The context string is longer than 255 bytes.
    ContextTooLong,
    /// The packed hint is malformed (`HintBitUnpack` returned `⊥`).
    MalformedHint,
    /// `||z||_inf >= gamma1 - beta`.
    ZNormTooLarge,
    /// The recomputed commitment hash does not equal `c_tilde`.
    ChallengeMismatch,
}

/// Number of polynomials in a [`Workspace`].
pub const WORKSPACE_POLYS: usize = L + 3;

/// Scratch memory for one verification: `L` polynomials for `NTT(z)` plus
/// `NTT(c)`, an accumulator and a temporary (7 polynomials, 7 KiB).
///
/// On SBF this must not live on the stack (it exceeds the 4 KiB frame limit).
/// Allocate it on the heap, e.g. with [`workspace_vec`] (feature `alloc`):
///
/// ```ignore
/// let mut buf = qshield_mldsa::workspace_vec();
/// let ws: &mut qshield_mldsa::Workspace = (&mut buf[..]).try_into().unwrap();
/// ```
pub type Workspace = [Poly; WORKSPACE_POLYS];

/// Allocates a zeroed [`Workspace`] on the heap. Each element is built from a
/// 1 KiB template, so no stack frame ever holds the full 7 KiB.
#[cfg(feature = "alloc")]
pub fn workspace_vec() -> alloc::vec::Vec<Poly> {
    alloc::vec![[0u32; N]; WORKSPACE_POLYS]
}

#[cfg(feature = "alloc")]
extern crate alloc;

/// A public key together with its precomputed `tr = H(pk, 64)`.
///
/// Computing `tr` hashes the full 1,312-byte key; storing it alongside the key
/// (e.g. in the vault account at registration) saves that work on every
/// verification. `tr` is a deterministic function of `pk`, so a prepared key
/// can only be constructed through [`PreparedPublicKey::new`].
#[derive(Clone)]
pub struct PreparedPublicKey<'a> {
    pk: &'a [u8; PUBLIC_KEY_LEN],
    tr: [u8; TR_LEN],
}

impl<'a> PreparedPublicKey<'a> {
    /// Checks the key length and computes `tr`.
    pub fn new(pk: &'a [u8]) -> Result<Self, Error> {
        let pk: &[u8; PUBLIC_KEY_LEN] = pk.try_into().map_err(|_| Error::PublicKeyLength)?;
        Ok(Self {
            pk,
            tr: compute_tr(pk),
        })
    }

    /// Reuses a previously computed `tr`. The caller must guarantee that `tr`
    /// was produced by [`compute_tr`] over exactly this `pk` (for example
    /// because both are stored in the same program-owned account and were
    /// written together); otherwise verification results are meaningless.
    pub fn from_parts(pk: &'a [u8], tr: [u8; TR_LEN]) -> Result<Self, Error> {
        let pk: &[u8; PUBLIC_KEY_LEN] = pk.try_into().map_err(|_| Error::PublicKeyLength)?;
        Ok(Self { pk, tr })
    }

    /// Returns `tr = H(pk, 64)`.
    pub fn tr(&self) -> &[u8; TR_LEN] {
        &self.tr
    }

    /// Returns the encoded public key.
    pub fn bytes(&self) -> &[u8; PUBLIC_KEY_LEN] {
        self.pk
    }
}

/// Computes `tr = H(pk, 64)` with `H = SHAKE256`.
pub fn compute_tr(pk: &[u8; PUBLIC_KEY_LEN]) -> [u8; TR_LEN] {
    let mut h = Shake256::default();
    h.update(pk);
    let mut tr = [0u8; TR_LEN];
    h.finalize_xof().read(&mut tr);
    tr
}

/// Computes the message representative of *pure* ML-DSA
/// (FIPS 204, Algorithm 3 step 5 and Algorithm 8 step 7):
/// `mu = H(tr || 0x00 || |ctx| || ctx || M, 64)`.
pub fn compute_mu(tr: &[u8; TR_LEN], ctx: &[u8], msg: &[u8]) -> Result<[u8; MU_LEN], Error> {
    if ctx.len() > MAX_CONTEXT_LEN {
        return Err(Error::ContextTooLong);
    }
    let mut h = Shake256::default();
    h.update(tr);
    h.update(&[0u8, ctx.len() as u8]);
    h.update(ctx);
    h.update(msg);
    let mut mu = [0u8; MU_LEN];
    h.finalize_xof().read(&mut mu);
    Ok(mu)
}

/// Computes `mu = H(tr || M', 64)` for an already-formatted internal message `M'`
/// (FIPS 204, Algorithm 8 step 7). Only needed for `Verify_internal` test vectors.
pub fn compute_mu_internal(tr: &[u8; TR_LEN], m_prime: &[u8]) -> [u8; MU_LEN] {
    let mut h = Shake256::default();
    h.update(tr);
    h.update(m_prime);
    let mut mu = [0u8; MU_LEN];
    h.finalize_xof().read(&mut mu);
    mu
}

/// `ML-DSA.Verify(pk, M, sigma, ctx)` for ML-DSA-44 (FIPS 204, Algorithm 3).
pub fn verify(
    pk: &[u8],
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    let key = PreparedPublicKey::new(pk)?;
    verify_prepared(&key, msg, ctx, sig, ws)
}

/// Like [`verify`] but with a prepared key (precomputed `tr`).
pub fn verify_prepared(
    key: &PreparedPublicKey<'_>,
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::SignatureLength);
    }
    let mu = compute_mu(&key.tr, ctx, msg)?;
    verify_mu(key.pk, &mu, sig, ws)
}

/// Number of polynomials in the expanded matrix `A_hat` (`K * L`).
pub const A_HAT_POLYS: usize = K * L;

/// A public key in *expanded* form: `A_hat = ExpandA(rho)`, `t1_hat =
/// NTT(t1 * 2^d)` and `tr = H(pk, 64)`.
///
/// Every component is a deterministic function of the encoded public key, so
/// precomputing them does not change what is verified, only when the work is
/// done. Expansion is the dominant verification cost under SBF (each
/// Keccak-f[1600] permutation costs >10k CU), so QShield expands a key once,
/// stores the result in a program-owned account, and verifies against it.
///
/// **Integrity requirement:** the caller must guarantee that the expanded data
/// was produced by [`expand_a_entry`] / [`expand_t1_hat_row`] / [`compute_tr`]
/// over the intended public key (e.g. because only the on-chain program writes
/// it, from the key bytes, and marks it complete). Supplying an expansion that
/// does not match the intended key makes verification meaningless.
#[derive(Clone, Copy)]
pub struct ExpandedKey<'a> {
    /// `A_hat[r][s]` stored row-major at index `r * L + s`, coefficients in `[0, q)`.
    pub a_hat: &'a [Poly; A_HAT_POLYS],
    /// `NTT(t1[r] * 2^d)` for each row `r`, coefficients in `[0, q)`.
    pub t1_hat: &'a [Poly; K],
    /// `tr = H(pk, 64)`.
    pub tr: &'a [u8; TR_LEN],
}

/// Computes `A_hat[r][s] = RejNTTPoly(rho || s || r)` (FIPS 204, Algorithm 32).
pub fn expand_a_entry(out: &mut Poly, pk: &[u8; PUBLIC_KEY_LEN], r: usize, s: usize) {
    assert!(r < K && s < L);
    let rho: &[u8; 32] = pk[..32].try_into().expect("32-byte rho");
    rej_ntt_poly(out, rho, r as u8, s as u8);
}

/// Computes `NTT(t1[r] * 2^d)` for row `r` of the public key.
pub fn expand_t1_hat_row(out: &mut Poly, pk: &[u8; PUBLIC_KEY_LEN], r: usize) {
    assert!(r < K);
    decode_t1_shifted(out, &pk[32 + r * T1_POLY_LEN..32 + (r + 1) * T1_POLY_LEN]);
    ntt(out);
}

/// `ML-DSA.Verify(pk, M, sigma, ctx)` against an expanded key.
pub fn verify_expanded(
    key: &ExpandedKey<'_>,
    msg: &[u8],
    ctx: &[u8],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::SignatureLength);
    }
    let mu = compute_mu(key.tr, ctx, msg)?;
    verify_core(KeySource::Expanded(key), &mu, sig, ws)
}

/// `ML-DSA.Verify_internal` from `mu` against an expanded key.
pub fn verify_mu_expanded(
    key: &ExpandedKey<'_>,
    mu: &[u8; MU_LEN],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    verify_core(KeySource::Expanded(key), mu, sig, ws)
}

/// `ML-DSA.Verify_internal` starting from a message representative `mu`
/// (FIPS 204, Algorithm 8, steps 1-4 and 8-13; the "external mu" interface).
pub fn verify_mu(
    pk: &[u8],
    mu: &[u8; MU_LEN],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    let pk: &[u8; PUBLIC_KEY_LEN] = pk.try_into().map_err(|_| Error::PublicKeyLength)?;
    verify_core(KeySource::Compact(pk), mu, sig, ws)
}

enum KeySource<'a> {
    /// Encoded public key; `A_hat` and `NTT(t1 * 2^d)` are recomputed on the fly.
    Compact(&'a [u8; PUBLIC_KEY_LEN]),
    /// Precomputed expansion.
    Expanded(&'a ExpandedKey<'a>),
}

fn verify_core(
    key: KeySource<'_>,
    mu: &[u8; MU_LEN],
    sig: &[u8],
    ws: &mut Workspace,
) -> Result<(), Error> {
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::SignatureLength);
    }

    // Step 2: sigDecode.
    let c_tilde: &[u8; C_TILDE_LEN] = sig[..C_TILDE_LEN]
        .try_into()
        .map_err(|_| Error::SignatureLength)?;
    let z_bytes = &sig[C_TILDE_LEN..C_TILDE_LEN + L * Z_POLY_LEN];
    let h_bytes = &sig[C_TILDE_LEN + L * Z_POLY_LEN..];

    // Steps 3-4: reject a malformed hint.
    let hints = Hints::parse(h_bytes).ok_or(Error::MalformedHint)?;

    // Step 13 (norm part), checked early: ||z||_inf < gamma1 - beta.
    // Decode z, check its norm and transform it to the NTT domain.
    let [z0, z1, z2, z3, c_hat, acc, tmp] = ws;
    let mut z_hat = [z0, z1, z2, z3];
    let mut norm_ok = true;
    for (j, z_hat_j) in z_hat.iter_mut().enumerate() {
        decode_z(&z_bytes[j * Z_POLY_LEN..(j + 1) * Z_POLY_LEN], |i, z| {
            if z.unsigned_abs() >= (GAMMA1 - BETA) as u32 {
                norm_ok = false;
            }
            z_hat_j[i] = from_centered(z);
        });
        if !norm_ok {
            return Err(Error::ZNormTooLarge);
        }
        ntt(z_hat_j);
    }

    // Step 8: c <- SampleInBall(c_tilde); c_hat = NTT(c).
    sample_in_ball(c_hat, c_tilde);
    ntt(c_hat);

    // Step 12 is computed incrementally: c_tilde' = H(mu || w1Encode(w1'), lambda/4).
    let mut h = Shake256::default();
    h.update(mu);

    let mut w1_packed = [0u8; W1_POLY_LEN];
    for r in 0..K {
        // Steps 1, 5 and 9 for row r:
        //   acc = sum_s A_hat[r][s] ∘ z_hat[s] - c_hat ∘ NTT(t1[r] * 2^d)
        acc.fill(0);
        match key {
            KeySource::Compact(pk) => {
                for (s, z_hat_s) in z_hat.iter().enumerate() {
                    expand_a_entry(tmp, pk, r, s);
                    pointwise_mul_acc(acc, tmp, z_hat_s);
                }
                expand_t1_hat_row(tmp, pk, r);
                pointwise_mul_sub(acc, c_hat, tmp);
            }
            KeySource::Expanded(ek) => {
                for (s, z_hat_s) in z_hat.iter().enumerate() {
                    pointwise_mul_acc(acc, &ek.a_hat[r * L + s], z_hat_s);
                }
                pointwise_mul_sub(acc, c_hat, &ek.t1_hat[r]);
            }
        }
        inv_ntt(acc);

        // Step 10: w1' = UseHint(h, w'_approx).
        let acc: &Poly = acc;
        let mut hint_flags = [false; N];
        for &p in hints.row(r) {
            hint_flags[p as usize] = true;
        }
        pack_w1(&mut w1_packed, |i| use_hint(hint_flags[i], acc[i]));
        h.update(&w1_packed);
    }

    let mut c_tilde_prime = [0u8; C_TILDE_LEN];
    h.finalize_xof().read(&mut c_tilde_prime);

    // Step 13: c_tilde == c_tilde'. Verification handles only public data, so
    // a variable-time comparison is acceptable.
    if &c_tilde_prime == c_tilde {
        Ok(())
    } else {
        Err(Error::ChallengeMismatch)
    }
}

/// `Decompose(r)` (FIPS 204, Algorithm 36) for `gamma2 = (q-1)/88`; `r` in `[0, q)`.
#[inline(always)]
fn decompose(r: u32) -> (u32, i32) {
    let two_gamma2 = 2 * GAMMA2;
    let mut r0 = (r % two_gamma2 as u32) as i32;
    if r0 > GAMMA2 {
        r0 -= two_gamma2;
    }
    if (r as i32) - r0 == (Q as i32) - 1 {
        (0, r0 - 1)
    } else {
        ((((r as i32) - r0) / two_gamma2) as u32, r0)
    }
}

/// `UseHint(h, r)` (FIPS 204, Algorithm 40) for `gamma2 = (q-1)/88`.
#[inline(always)]
fn use_hint(hint: bool, r: u32) -> u32 {
    const M: u32 = (Q - 1) / (2 * GAMMA2 as u32); // 44
    let (r1, r0) = decompose(r);
    if !hint {
        r1
    } else if r0 > 0 {
        (r1 + 1) % M
    } else {
        (r1 + M - 1) % M
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_matches_definition() {
        // Exhaustively check r = r1 * 2*gamma2 + r0 (mod q) with r0 in the
        // FIPS 204 ranges, over every residue.
        let two_gamma2 = 2 * GAMMA2;
        for r in 0..Q {
            let (r1, r0) = decompose(r);
            assert!(r1 < 44);
            assert!(r0 > -GAMMA2 - 1 && r0 <= GAMMA2, "r={r} r0={r0}");
            let recon = (r1 as i64 * two_gamma2 as i64 + r0 as i64).rem_euclid(Q as i64);
            assert_eq!(recon, r as i64);
        }
    }

    #[test]
    fn workspace_size() {
        assert_eq!(core::mem::size_of::<Workspace>(), 7 * 1024);
    }
}
