//! Arithmetic in `R_q = Z_q[X]/(X^256 + 1)` and the number-theoretic transform.
//!
//! Every coefficient is kept fully reduced in `[0, q)` as a `u32`. Products are
//! formed in `u64` and reduced with `%`. On SBF every instruction (including
//! 64-bit multiply and remainder) costs one compute unit, so plain modular
//! reduction is both simpler to audit and competitive with Montgomery or Barrett
//! reduction. Verification handles only public data, so no constant-time
//! guarantees are required (see `docs/CRYPTOGRAPHY.md`).

use crate::params::{N, Q};

/// A polynomial with coefficients in `[0, q)`.
pub type Poly = [u32; N];

/// `zeta = 1753`, a primitive 512-th root of unity modulo `q` (FIPS 204, Section 7.5).
const ZETA: u64 = 1753;

/// `256^-1 mod q` (FIPS 204, Algorithm 42, step 21).
const N_INV: u64 = 8_347_681;

const fn pow_mod(base: u64, mut exp: u32) -> u64 {
    let mut result = 1u64;
    let mut b = base % Q as u64;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % Q as u64;
        }
        b = b * b % Q as u64;
        exp >>= 1;
    }
    result
}

const fn bit_rev8(x: u32) -> u32 {
    let mut r = 0u32;
    let mut i = 0;
    while i < 8 {
        r |= ((x >> i) & 1) << (7 - i);
        i += 1;
    }
    r
}

const fn compute_zetas() -> [u32; N] {
    let mut z = [0u32; N];
    let mut k = 0;
    while k < N {
        z[k] = pow_mod(ZETA, bit_rev8(k as u32)) as u32;
        k += 1;
    }
    z
}

/// `zetas[k] = zeta^BitRev8(k) mod q`, computed at compile time (FIPS 204, Appendix B).
pub(crate) static ZETAS: [u32; N] = compute_zetas();

// Sanity checks against values listed in FIPS 204, Appendix B.
const _: () = assert!(compute_zetas()[0] == 1);
const _: () = assert!(compute_zetas()[1] == 4_808_194);
const _: () = assert!(compute_zetas()[2] == 3_765_607);
const _: () = assert!(compute_zetas()[255] == 7_648_983);
const _: () = assert!(compute_zetas()[3] == 3_761_513);
const _: () = assert!(pow_mod(ZETA, 256) == Q as u64 - 1);
const _: () = assert!(N_INV * 256 % Q as u64 == 1);

#[inline(always)]
fn add_q(a: u32, b: u32) -> u32 {
    let s = a + b; // a, b < q < 2^23: no overflow
    if s >= Q {
        s - Q
    } else {
        s
    }
}

#[inline(always)]
fn sub_q(a: u32, b: u32) -> u32 {
    if a >= b {
        a - b
    } else {
        a + Q - b
    }
}

#[inline(always)]
fn mul_q(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % Q as u64) as u32
}

/// Forward NTT in place (FIPS 204, Algorithm 41).
pub fn ntt(w: &mut Poly) {
    let mut m = 0usize;
    let mut len = 128usize;
    while len >= 1 {
        let mut start = 0usize;
        while start < N {
            m += 1;
            let z = ZETAS[m];
            for j in start..start + len {
                let t = mul_q(z, w[j + len]);
                w[j + len] = sub_q(w[j], t);
                w[j] = add_q(w[j], t);
            }
            start += 2 * len;
        }
        len /= 2;
    }
}

/// Inverse NTT in place (FIPS 204, Algorithm 42).
pub fn inv_ntt(w: &mut Poly) {
    let mut m = N;
    let mut len = 1usize;
    while len < N {
        let mut start = 0usize;
        while start < N {
            m -= 1;
            let z = Q - ZETAS[m]; // -zetas[m] mod q
            for j in start..start + len {
                let t = w[j];
                w[j] = add_q(t, w[j + len]);
                w[j + len] = mul_q(z, sub_q(t, w[j + len]));
            }
            start += 2 * len;
        }
        len *= 2;
    }
    for c in w.iter_mut() {
        *c = ((*c as u64 * N_INV) % Q as u64) as u32;
    }
}

/// `acc += a ∘ b` (pointwise product in the NTT domain).
pub fn pointwise_mul_acc(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] = add_q(acc[i], mul_q(a[i], b[i]));
    }
}

/// `acc -= a ∘ b` (pointwise product in the NTT domain).
pub fn pointwise_mul_sub(acc: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N {
        acc[i] = sub_q(acc[i], mul_q(a[i], b[i]));
    }
}

/// Maps a centered integer `x` with `|x| < q` to `[0, q)`.
#[inline(always)]
pub fn from_centered(x: i32) -> u32 {
    if x < 0 {
        (x + Q as i32) as u32
    } else {
        x as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        // Negacyclic convolution modulo X^256 + 1.
        let mut r = [0u64; N];
        let mut neg = [0u64; N];
        for i in 0..N {
            for j in 0..N {
                let p = a[i] as u64 * b[j] as u64 % Q as u64;
                if i + j < N {
                    r[i + j] = (r[i + j] + p) % Q as u64;
                } else {
                    neg[i + j - N] = (neg[i + j - N] + p) % Q as u64;
                }
            }
        }
        let mut out = [0u32; N];
        for i in 0..N {
            out[i] = ((r[i] + Q as u64 - neg[i]) % Q as u64) as u32;
        }
        out
    }

    fn pseudo_random_poly(seed: u64) -> Poly {
        let mut s = seed;
        let mut p = [0u32; N];
        for c in p.iter_mut() {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *c = ((s >> 33) % Q as u64) as u32;
        }
        p
    }

    #[test]
    fn ntt_roundtrip() {
        for seed in 0..8 {
            let p = pseudo_random_poly(seed);
            let mut w = p;
            ntt(&mut w);
            inv_ntt(&mut w);
            assert_eq!(w, p);
        }
    }

    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        for seed in 0..4 {
            let a = pseudo_random_poly(seed);
            let b = pseudo_random_poly(seed + 100);
            let expected = schoolbook(&a, &b);
            let (mut ah, mut bh) = (a, b);
            ntt(&mut ah);
            ntt(&mut bh);
            let mut acc = [0u32; N];
            pointwise_mul_acc(&mut acc, &ah, &bh);
            inv_ntt(&mut acc);
            assert_eq!(acc, expected);
        }
    }

    #[test]
    fn edge_values_stay_reduced() {
        let mut w = [Q - 1; N];
        ntt(&mut w);
        assert!(w.iter().all(|&c| c < Q));
        inv_ntt(&mut w);
        assert_eq!(w, [Q - 1; N]);
    }
}
