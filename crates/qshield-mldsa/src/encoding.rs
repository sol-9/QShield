//! Bit packing used by verification (FIPS 204, Section 7.1 and 7.2).
//!
//! All packings are little-endian at the bit level: coefficient `i` occupies
//! bits `[i*b, (i+1)*b)` of the byte string, where bit `k` is bit `k mod 8` of
//! byte `k / 8` (FIPS 204, Algorithms 10–19).

use crate::params::{GAMMA1, K, N, OMEGA, T1_POLY_LEN, W1_POLY_LEN, Z_POLY_LEN};
use crate::poly::Poly;

/// Unpacks `N` coefficients of `BITS` bits each from `bytes` and passes each
/// raw value to `f(index, value)`.
#[inline(always)]
fn unpack_bits<const BITS: u32>(bytes: &[u8], mut f: impl FnMut(usize, u32)) {
    debug_assert_eq!(bytes.len(), N * BITS as usize / 8);
    let mask = (1u64 << BITS) - 1;
    let mut acc = 0u64;
    let mut acc_bits = 0u32;
    let mut byte_idx = 0usize;
    for i in 0..N {
        while acc_bits < BITS {
            acc |= (bytes[byte_idx] as u64) << acc_bits;
            byte_idx += 1;
            acc_bits += 8;
        }
        f(i, (acc & mask) as u32);
        acc >>= BITS;
        acc_bits -= BITS;
    }
}

/// Decodes row `i` of `t1` from the packed public key body (`SimpleBitUnpack(·, 2^10 - 1)`)
/// and multiplies each coefficient by `2^d`.
///
/// `t1_bytes` must be exactly `T1_POLY_LEN` bytes.
pub fn decode_t1_shifted(out: &mut Poly, t1_bytes: &[u8]) {
    debug_assert_eq!(t1_bytes.len(), T1_POLY_LEN);
    // t1 < 2^10, so t1 * 2^13 <= (2^10 - 1) * 2^13 = q - 1: no reduction required.
    unpack_bits::<10>(t1_bytes, |i, v| out[i] = v << crate::params::D);
}

/// Decodes one `z` polynomial (`BitUnpack(·, gamma1 - 1, gamma1)`, FIPS 204, Algorithm 19)
/// into centered representatives in `[-(gamma1 - 1), gamma1]`, calling `f(index, z)`.
pub fn decode_z(z_bytes: &[u8], f: impl FnMut(usize, i32)) {
    debug_assert_eq!(z_bytes.len(), Z_POLY_LEN);
    let mut f = f;
    unpack_bits::<18>(z_bytes, |i, v| f(i, GAMMA1 - v as i32));
}

/// Packs one `w1` polynomial with 6 bits per coefficient (`SimpleBitPack(·, 43)`,
/// FIPS 204, Algorithm 16). Coefficients must be `< 64`.
pub fn pack_w1(out: &mut [u8; W1_POLY_LEN], w1: impl Fn(usize) -> u32) {
    // 4 coefficients per 3 bytes.
    for g in 0..N / 4 {
        let a = w1(4 * g);
        let b = w1(4 * g + 1);
        let c = w1(4 * g + 2);
        let d = w1(4 * g + 3);
        out[3 * g] = (a | (b << 6)) as u8;
        out[3 * g + 1] = ((b >> 2) | (c << 4)) as u8;
        out[3 * g + 2] = ((c >> 4) | (d << 2)) as u8;
    }
}

/// Validated layout of the packed hint `h` (FIPS 204, Algorithm 21, `HintBitUnpack`).
///
/// Instead of materialising `h` as `k` polynomials, the verifier keeps the
/// packed bytes and the per-row end offsets; within each row the positions are
/// strictly increasing, so they can be consumed in order while scanning
/// coefficients.
#[derive(Clone, Copy, Debug)]
pub struct Hints<'a> {
    bytes: &'a [u8],
    ends: [u8; K],
}

impl<'a> Hints<'a> {
    /// Validates a packed hint of `OMEGA + K` bytes. Returns `None` exactly when
    /// `HintBitUnpack` returns `⊥`.
    pub fn parse(y: &'a [u8]) -> Option<Self> {
        if y.len() != OMEGA + K {
            return None;
        }
        let mut ends = [0u8; K];
        let mut index = 0usize;
        for (i, end_slot) in ends.iter_mut().enumerate() {
            let end = y[OMEGA + i] as usize;
            // Step 4: y[omega + i] < Index or y[omega + i] > omega => ⊥
            if end < index || end > OMEGA {
                return None;
            }
            let first = index;
            while index < end {
                // Step 7: positions within a row must be strictly increasing.
                if index > first && y[index - 1] >= y[index] {
                    return None;
                }
                index += 1;
            }
            *end_slot = end as u8;
        }
        // Steps 12-14: unused position slots must be zero.
        if y[index..OMEGA].iter().any(|&b| b != 0) {
            return None;
        }
        Some(Self { bytes: y, ends })
    }

    /// Returns the strictly increasing hint positions of row `i`.
    pub fn row(&self, i: usize) -> &'a [u8] {
        let start = if i == 0 { 0 } else { self.ends[i - 1] as usize };
        &self.bytes[start..self.ends[i] as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn w1_pack_matches_generic_bitpack() {
        let w1 = |i: usize| ((i * 37 + 11) % 44) as u32;
        let mut packed = [0u8; W1_POLY_LEN];
        pack_w1(&mut packed, w1);
        let mut seen = 0;
        unpack_bits::<6>(&packed, |i, v| {
            assert_eq!(v, w1(i));
            seen += 1;
        });
        assert_eq!(seen, N);
    }

    #[test]
    fn hints_reject_unsorted_and_trailing_garbage() {
        let mut y = [0u8; OMEGA + K];
        assert!(Hints::parse(&y).is_some());
        // Row 0 holds positions [5, 3]: not increasing.
        y[0] = 5;
        y[1] = 3;
        y[OMEGA] = 2;
        y[OMEGA + 1] = 2;
        y[OMEGA + 2] = 2;
        y[OMEGA + 3] = 2;
        assert!(Hints::parse(&y).is_none());
        y[1] = 6;
        assert!(Hints::parse(&y).is_some());
        // Non-zero byte after the last used position.
        y[10] = 1;
        assert!(Hints::parse(&y).is_none());
        y[10] = 0;
        // Decreasing row ends.
        y[OMEGA + 2] = 1;
        assert!(Hints::parse(&y).is_none());
        // End beyond omega.
        y[OMEGA + 2] = 2;
        y[OMEGA + 3] = (OMEGA + 1) as u8;
        assert!(Hints::parse(&y).is_none());
    }
}
