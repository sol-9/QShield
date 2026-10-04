//! Property-based fuzzing of every parser the program exposes to untrusted
//! input: instruction decoding and account-state loading. These run on stable
//! Rust in CI; `tests/fuzz` has the equivalent coverage-guided cargo-fuzz targets.

use proptest::prelude::*;
use qshield_vault::instruction::{tag, VaultInstruction};
use qshield_vault::state::{BufferState, KeyHeader, KeyState, SigBuffer, Vault, VaultStatus};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn instruction_unpack_never_panics(data in proptest::collection::vec(any::<u8>(), 0..3000)) {
        let _ = VaultInstruction::unpack(&data);
    }

    #[test]
    fn instruction_unpack_rejects_wrong_lengths(t in 0u8..12, len in 0usize..3000) {
        let mut data = vec![t];
        data.extend(std::iter::repeat_n(1u8, len));
        let ok = VaultInstruction::unpack(&data).is_ok();
        let expected = match t {
            tag::CREATE_KEY => len == 65,
            tag::WRITE_KEY => len >= 3,
            tag::FINALIZE_KEY | tag::CLOSE_KEY | tag::CLOSE_SIG_BUFFER => len == 0,
            tag::EXPAND_KEY => len == 1,
            tag::INITIALIZE_VAULT => len == 32,
            tag::DEPOSIT_SOL => len == 8,
            tag::EXECUTE => len == 292 + 2420,
            tag::CREATE_SIG_BUFFER => len == 40,
            // offset(2) + finalize flag(1; the filler value 1 = true) + bytes
            tag::WRITE_SIG_BUFFER => len >= 3,
            tag::EXECUTE_WITH_BUFFER => len == 292,
            _ => false,
        };
        prop_assert_eq!(ok, expected);
    }

    #[test]
    fn account_loaders_never_panic(data in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = Vault::load(&data);
        let _ = SigBuffer::load(&data);
    }

    #[test]
    fn account_loaders_never_panic_at_exact_sizes(fill in any::<u8>(), disc in any::<bool>(), b9 in any::<u8>()) {
        let mut v = vec![fill; Vault::LEN];
        let mut k = vec![fill; KeyHeader::LEN];
        let mut s = vec![fill; SigBuffer::LEN];
        if disc {
            v[..8].copy_from_slice(&Vault::DISCRIMINATOR);
            k[..8].copy_from_slice(&KeyHeader::DISCRIMINATOR);
            s[..8].copy_from_slice(&SigBuffer::DISCRIMINATOR);
            v[8] = 1; k[8] = 1; s[8] = 1;
            v[9] = b9; k[10] = b9; s[9] = b9;
        }
        let _ = Vault::load(&v);
        let _ = KeyHeader::load(&k);
        let _ = SigBuffer::load(&s);
    }

    #[test]
    fn vault_roundtrip(nonce in any::<u64>(), key_id in any::<[u8; 32]>(), seed in any::<[u8; 32]>(), st in 1u8..=3, slot in any::<u64>(), ts in any::<i64>(), pm in 0u8..=1) {
        let status = match st { 1 => VaultStatus::Active, 2 => VaultStatus::Paused, _ => VaultStatus::Closed };
        let v = Vault { status, bump: 254, pq_algorithm: 1, nonce, key_id, key_account: seed, initial_key_id: key_id, vault_seed: seed, created_slot: slot, created_at: ts, policy_mode: pm };
        let mut d = vec![0u8; Vault::LEN];
        v.store(&mut d).unwrap();
        prop_assert_eq!(Vault::load(&d).unwrap(), v);
    }

    #[test]
    fn key_header_roundtrip(st in 1u8..=3, in_use in any::<bool>(), g in any::<bool>(), expanded in 0u8..=20, a in any::<[u8; 32]>(), b in any::<[u8; 32]>()) {
        let state = match st { 1 => KeyState::Writing, 2 => KeyState::Expanding, _ => KeyState::Ready };
        let h = KeyHeader { algorithm: 1, state, bump: 0, in_use, guardian: in_use && g, expanded, vault: a, key_id: b, creator: a };
        let mut d = vec![0xAAu8; KeyHeader::LEN];
        h.store(&mut d).unwrap();
        prop_assert_eq!(KeyHeader::load(&d).unwrap(), h);
        prop_assert!(d[qshield_vault::state::key_off::PK..].iter().all(|&x| x == 0xAA), "store must not touch the key body");
    }

    #[test]
    fn sig_buffer_roundtrip(fin in any::<bool>(), id in any::<u64>(), a in any::<[u8; 32]>()) {
        let b = SigBuffer { state: if fin { BufferState::Finalized } else { BufferState::Writing }, bump: 7, vault: a, creator: a, buffer_id: id };
        let mut d = vec![0u8; SigBuffer::LEN];
        b.store(&mut d).unwrap();
        prop_assert_eq!(SigBuffer::load(&d).unwrap(), b);
    }
}
