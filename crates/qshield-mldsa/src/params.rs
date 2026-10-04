//! ML-DSA-44 parameter set (FIPS 204, Table 1 and Table 2).

/// Polynomial degree `n`.
pub const N: usize = 256;
/// Modulus `q = 2^23 - 2^13 + 1`.
pub const Q: u32 = 8_380_417;
/// Dropped bits from `t`.
pub const D: u32 = 13;
/// Number of ±1 coefficients in the challenge polynomial.
pub const TAU: usize = 39;
/// Collision strength of `c_tilde` in bits.
pub const LAMBDA: usize = 128;
/// Coefficient range of `y`.
pub const GAMMA1: i32 = 1 << 17;
/// Low-order rounding range.
pub const GAMMA2: i32 = ((Q - 1) / 88) as i32;
/// Rows of `A`.
pub const K: usize = 4;
/// Columns of `A`.
pub const L: usize = 4;
/// Private key range.
pub const ETA: i32 = 2;
/// `beta = tau * eta`.
pub const BETA: i32 = (TAU as i32) * ETA;
/// Maximum number of ones in the hint `h`.
pub const OMEGA: usize = 80;

/// Length of `c_tilde` in bytes (`lambda / 4`).
pub const C_TILDE_LEN: usize = LAMBDA / 4;
/// Bytes per packed `t1` polynomial (10 bits per coefficient).
pub const T1_POLY_LEN: usize = 320;
/// Bytes per packed `z` polynomial (`1 + bitlen(gamma1 - 1)` = 18 bits per coefficient).
pub const Z_POLY_LEN: usize = 576;
/// Bytes per packed `w1` polynomial (`bitlen((q-1)/(2*gamma2) - 1)` = 6 bits per coefficient).
pub const W1_POLY_LEN: usize = 192;

/// Encoded public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32 + K * T1_POLY_LEN;
/// Encoded signature length in bytes.
pub const SIGNATURE_LEN: usize = C_TILDE_LEN + L * Z_POLY_LEN + OMEGA + K;
/// Length of `tr = H(pk, 64)`.
pub const TR_LEN: usize = 64;
/// Length of the message representative `mu`.
pub const MU_LEN: usize = 64;
/// Maximum context string length (FIPS 204, Algorithm 3, step 1).
pub const MAX_CONTEXT_LEN: usize = 255;

const _: () = assert!(PUBLIC_KEY_LEN == 1312);
const _: () = assert!(SIGNATURE_LEN == 2420);
const _: () = assert!(GAMMA2 == 95_232);
const _: () = assert!(BETA == 78);
