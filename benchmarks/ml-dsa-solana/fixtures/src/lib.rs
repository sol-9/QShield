//! Shared fixtures for the ML-DSA-44 Solana benchmark binaries.

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer as _};
use qshield_mldsa::{compute_tr, expand_a_entry, expand_t1_hat_row, PUBLIC_KEY_LEN};
use rand::Rng;
use rand_chacha::ChaCha20Rng;

pub const LEGACY_PACKET_LIMIT: usize = 1232;
pub const V1_TX_LIMIT: usize = 4096;
pub const MAX_TX_CU: u32 = 1_400_000;
/// Representative size of a QSP-1 authorization message (see docs/QSP-1.md).
pub const MSG_LEN: usize = 210;
pub const CTX: &[u8] = b"QSHIELD-QSP1";

#[derive(Clone)]
pub struct Fixture {
    pub pk: Vec<u8>,
    pub sig: Vec<u8>,
    pub msg: Vec<u8>,
}

pub fn fixture(rng: &mut ChaCha20Rng) -> Fixture {
    let xi: [u8; 32] = rng.gen();
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&xi);
    let msg: Vec<u8> = (0..MSG_LEN).map(|_| rng.gen()).collect();
    let rnd: [u8; 32] = rng.gen();
    let sig = sk.try_sign_with_seed(&rnd, &msg, CTX).expect("sign");
    Fixture {
        pk: pk.into_bytes().to_vec(),
        sig: sig.to_vec(),
        msg,
    }
}

/// Expanded key account bytes: A_hat ‖ t1_hat ‖ tr (see the program docs).
pub fn expanded_key_bytes(pk: &[u8]) -> Vec<u8> {
    let pk: &[u8; PUBLIC_KEY_LEN] = pk.try_into().unwrap();
    let mut out = Vec::with_capacity(20 * 1024 + 64);
    let mut poly = [0u32; 256];
    for r in 0..4 {
        for s in 0..4 {
            expand_a_entry(&mut poly, pk, r, s);
            out.extend(poly.iter().flat_map(|c| c.to_le_bytes()));
        }
    }
    for r in 0..4 {
        expand_t1_hat_row(&mut poly, pk, r);
        out.extend(poly.iter().flat_map(|c| c.to_le_bytes()));
    }
    out.extend_from_slice(&compute_tr(pk));
    out
}

pub fn ctx_msg(msg: &[u8]) -> Vec<u8> {
    let mut v = vec![CTX.len() as u8];
    v.extend_from_slice(CTX);
    v.extend_from_slice(msg);
    v
}

pub fn with_op(op: u8, parts: &[&[u8]]) -> Vec<u8> {
    let mut v = vec![op];
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}
