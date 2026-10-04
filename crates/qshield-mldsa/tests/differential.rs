//! Differential tests: `qshield-mldsa` must accept and reject exactly the same
//! (public key, message, context, signature) tuples as two independent ML-DSA-44
//! implementations, `fips204` (IntegrityChain) and `ml-dsa` (RustCrypto).

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};
use ml_dsa::{
    EncodedVerifyingKey, MlDsa44, Signature as RcSignature, VerifyingKey as RcVerifyingKey,
};
use proptest::prelude::*;
use qshield_mldsa::{
    compute_tr, expand_a_entry, expand_t1_hat_row, verify, verify_expanded, Error, ExpandedKey,
    Workspace, PUBLIC_KEY_LEN, SIGNATURE_LEN,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

fn ours(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<(), Error> {
    let mut ws: Workspace = [[0u32; 256]; 7];
    let compact = verify(pk, msg, ctx, sig, &mut ws);
    // The expanded-key path must give the identical result.
    if let Ok(pk) = <&[u8; PUBLIC_KEY_LEN]>::try_from(pk) {
        let mut a_hat = [[0u32; 256]; 16];
        let mut t1_hat = [[0u32; 256]; 4];
        for r in 0..4 {
            for s in 0..4 {
                expand_a_entry(&mut a_hat[r * 4 + s], pk, r, s);
            }
            expand_t1_hat_row(&mut t1_hat[r], pk, r);
        }
        let tr = compute_tr(pk);
        let ek = ExpandedKey {
            a_hat: &a_hat,
            t1_hat: &t1_hat,
            tr: &tr,
        };
        assert_eq!(
            verify_expanded(&ek, msg, ctx, sig, &mut ws),
            compact,
            "expanded vs compact"
        );
    }
    compact
}

fn fips204_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(pk): Result<[u8; PUBLIC_KEY_LEN], _> = pk.try_into() else {
        return false;
    };
    let Ok(sig): Result<[u8; SIGNATURE_LEN], _> = sig.try_into() else {
        return false;
    };
    let Ok(pk) = ml_dsa_44::PublicKey::try_from_bytes(pk) else {
        return false;
    };
    pk.verify(msg, &sig, ctx)
}

fn rustcrypto_verify(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let Ok(enc) = EncodedVerifyingKey::<MlDsa44>::try_from(pk) else {
        return false;
    };
    let vk = RcVerifyingKey::<MlDsa44>::decode(&enc);
    let Ok(sig) = RcSignature::<MlDsa44>::try_from(sig) else {
        return false;
    };
    vk.verify_with_context(msg, ctx, &sig)
}

fn all_agree(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let a = ours(pk, msg, ctx, sig).is_ok();
    let b = fips204_verify(pk, msg, ctx, sig);
    let c = rustcrypto_verify(pk, msg, ctx, sig);
    assert_eq!(a, b, "qshield vs fips204 disagree");
    assert_eq!(a, c, "qshield vs RustCrypto disagree");
    a
}

struct Fixture {
    pk: Vec<u8>,
    sig: Vec<u8>,
    msg: Vec<u8>,
    ctx: Vec<u8>,
}

fn fixture(seed: u64) -> Fixture {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let xi: [u8; 32] = rng.gen();
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&xi);
    let msg_len = rng.gen_range(0..300);
    let msg: Vec<u8> = (0..msg_len).map(|_| rng.gen()).collect();
    let ctx_len = rng.gen_range(0..40);
    let ctx: Vec<u8> = (0..ctx_len).map(|_| rng.gen()).collect();
    let rnd: [u8; 32] = rng.gen();
    let sig = sk.try_sign_with_seed(&rnd, &msg, &ctx).unwrap();
    Fixture {
        pk: pk.into_bytes().to_vec(),
        sig: sig.to_vec(),
        msg,
        ctx,
    }
}

#[test]
fn valid_signatures_from_fips204_verify_everywhere() {
    for seed in 0..64 {
        let f = fixture(seed);
        assert!(all_agree(&f.pk, &f.msg, &f.ctx, &f.sig), "seed {seed}");
    }
}

#[test]
fn valid_signatures_from_rustcrypto_verify() {
    for seed in 0u8..32 {
        let sk = ml_dsa::SigningKey::<MlDsa44>::from_seed(&[seed; 32].into());
        let vk = sk.expanded_key().verifying_key().encode();
        let msg = vec![seed; seed as usize * 7];
        let ctx = b"qshield-differential";
        let sig = sk
            .expanded_key()
            .sign_deterministic(&msg, ctx)
            .unwrap()
            .encode();
        assert!(all_agree(&vk, &msg, ctx, &sig), "seed {seed}");
    }
}

#[test]
fn context_handling() {
    let f = fixture(7);
    // Wrong context.
    assert!(!all_agree(&f.pk, &f.msg, b"other", &f.sig));
    // Over-long context is rejected before any other work.
    let long = vec![0u8; 256];
    assert_eq!(
        ours(&f.pk, &f.msg, &long, &f.sig),
        Err(Error::ContextTooLong)
    );
    assert!(!fips204_verify(&f.pk, &f.msg, &long, &f.sig));
    assert!(!rustcrypto_verify(&f.pk, &f.msg, &long, &f.sig));
}

#[test]
fn length_errors() {
    let f = fixture(3);
    assert_eq!(
        ours(&f.pk[..1311], &f.msg, &f.ctx, &f.sig),
        Err(Error::PublicKeyLength)
    );
    let mut long_pk = f.pk.clone();
    long_pk.push(0);
    assert_eq!(
        ours(&long_pk, &f.msg, &f.ctx, &f.sig),
        Err(Error::PublicKeyLength)
    );
    assert_eq!(
        ours(&f.pk, &f.msg, &f.ctx, &f.sig[..2419]),
        Err(Error::SignatureLength)
    );
    let mut long_sig = f.sig.clone();
    long_sig.push(0);
    assert_eq!(
        ours(&f.pk, &f.msg, &f.ctx, &long_sig),
        Err(Error::SignatureLength)
    );
    // ML-DSA-65 sized inputs (wrong parameter set).
    assert_eq!(
        ours(&vec![0u8; 1952], &f.msg, &f.ctx, &f.sig),
        Err(Error::PublicKeyLength)
    );
    assert_eq!(
        ours(&f.pk, &f.msg, &f.ctx, &vec![0u8; 3309]),
        Err(Error::SignatureLength)
    );
    assert!(ours(&[], &[], &[], &[]).is_err());
}

#[test]
fn degenerate_inputs_are_rejected_consistently() {
    let f = fixture(11);
    let zero_pk = vec![0u8; PUBLIC_KEY_LEN];
    let zero_sig = vec![0u8; SIGNATURE_LEN];
    let ff_pk = vec![0xffu8; PUBLIC_KEY_LEN];
    let ff_sig = vec![0xffu8; SIGNATURE_LEN];
    for (pk, sig) in [
        (&zero_pk, &zero_sig),
        (&f.pk, &zero_sig),
        (&zero_pk, &f.sig),
        (&ff_pk, &ff_sig),
        (&f.pk, &ff_sig),
        (&ff_pk, &f.sig),
    ] {
        assert!(!all_agree(pk, &f.msg, &f.ctx, sig));
    }
    // All-zero signature: z = gamma1 everywhere, violating the norm bound.
    assert_eq!(
        ours(&f.pk, &f.msg, &f.ctx, &zero_sig),
        Err(Error::ZNormTooLarge)
    );
}

#[test]
fn z_norm_boundary() {
    // Construct a signature whose first z coefficient is exactly gamma1 - beta
    // (must be rejected) by editing the packed bits; everything else
    // unchanged. 18-bit field value v encodes z = gamma1 - v.
    let f = fixture(5);
    let mut sig = f.sig.clone();
    let off = 32; // c_tilde
    let v: u32 = 78; // z = 131072 - 78 = gamma1 - beta
    sig[off] = v as u8;
    sig[off + 1] = (v >> 8) as u8;
    sig[off + 2] = (sig[off + 2] & !0x03) | ((v >> 16) as u8 & 0x03);
    assert_eq!(ours(&f.pk, &f.msg, &f.ctx, &sig), Err(Error::ZNormTooLarge));
    assert!(!all_agree(&f.pk, &f.msg, &f.ctx, &sig));
    // z = gamma1 - beta - 1 passes the norm check (and then fails the hash).
    let v: u32 = 79;
    sig[off] = v as u8;
    sig[off + 1] = (v >> 8) as u8;
    assert_ne!(ours(&f.pk, &f.msg, &f.ctx, &sig), Err(Error::ZNormTooLarge));
}

#[test]
fn every_single_bit_flip_in_hint_and_c_tilde_is_handled_identically() {
    let f = fixture(9);
    let hint_start = SIGNATURE_LEN - 84;
    for byte in (0..32).chain(hint_start..SIGNATURE_LEN) {
        for bit in 0..8 {
            let mut sig = f.sig.clone();
            sig[byte] ^= 1 << bit;
            assert!(
                !all_agree(&f.pk, &f.msg, &f.ctx, &sig),
                "byte {byte} bit {bit}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn random_mutations_agree(seed in 0u64..16, which in 0u8..4, pos in any::<usize>(), val in any::<u8>()) {
        let mut f = fixture(seed);
        match which {
            0 => { let i = pos % f.sig.len(); f.sig[i] ^= val | 1; }
            1 => { let i = pos % f.pk.len(); f.pk[i] ^= val | 1; }
            2 => { if f.msg.is_empty() { f.msg.push(val) } else { let i = pos % f.msg.len(); f.msg[i] ^= val | 1; } }
            _ => { f.ctx.push(val); }
        }
        prop_assert!(!all_agree(&f.pk, &f.msg, &f.ctx, &f.sig));
    }

    #[test]
    fn random_garbage_agrees(sig in proptest::collection::vec(any::<u8>(), SIGNATURE_LEN), seed in 0u64..4) {
        let f = fixture(seed);
        prop_assert!(!all_agree(&f.pk, &f.msg, &f.ctx, &sig));
    }
}
