//! Pseudorandom sampling used by verification (FIPS 204, Section 7.3).

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake256};

use crate::params::{C_TILDE_LEN, N, Q, TAU};
use crate::poly::Poly;

/// Size of one SHAKE128 output block (rate of Keccak[256]).
const SHAKE128_RATE: usize = 168;

/// `RejNTTPoly(rho || s || r)` (FIPS 204, Algorithm 30) writing `A_hat[r][s]` into `out`.
///
/// The caller passes the row index `r` and column index `s`; the seed is
/// `rho || IntegerToBytes(s, 1) || IntegerToBytes(r, 1)` as required by
/// `ExpandA` (FIPS 204, Algorithm 32, step 3).
pub fn rej_ntt_poly(out: &mut Poly, rho: &[u8; 32], r: u8, s: u8) {
    let mut xof = Shake128::default();
    xof.update(rho);
    xof.update(&[s, r]);
    let mut reader = xof.finalize_xof();

    // A block of 168 bytes holds exactly 56 three-byte candidates.
    let mut block = [0u8; SHAKE128_RATE];
    let mut j = 0usize;
    while j < N {
        reader.read(&mut block);
        let mut pos = 0usize;
        while pos < SHAKE128_RATE && j < N {
            // CoeffFromThreeBytes (FIPS 204, Algorithm 14).
            let b2 = (block[pos + 2] & 0x7F) as u32;
            let coeff = (block[pos] as u32) | ((block[pos + 1] as u32) << 8) | (b2 << 16);
            pos += 3;
            if coeff < Q {
                out[j] = coeff;
                j += 1;
            }
        }
    }
}

/// `SampleInBall(c_tilde)` (FIPS 204, Algorithm 29).
///
/// Writes a polynomial with exactly `tau` coefficients in `{-1, +1}` (represented
/// as `q - 1` and `1`) and all others zero.
pub fn sample_in_ball(out: &mut Poly, c_tilde: &[u8; C_TILDE_LEN]) {
    let mut xof = Shake256::default();
    xof.update(c_tilde);
    let mut reader = xof.finalize_xof();

    let mut s = [0u8; 8];
    reader.read(&mut s);
    let signs = u64::from_le_bytes(s);

    for c in out.iter_mut() {
        *c = 0;
    }
    let mut byte = [0u8; 1];
    for i in (N - TAU)..N {
        let j = loop {
            reader.read(&mut byte);
            if (byte[0] as usize) <= i {
                break byte[0] as usize;
            }
        };
        out[i] = out[j];
        // h[i + tau - 256] is bit (i + tau - 256) of the 64-bit little-endian string.
        let bit = (signs >> (i + TAU - N)) & 1;
        out[j] = if bit == 1 { Q - 1 } else { 1 };
    }
}
