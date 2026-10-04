//! Property tests for the QSP-1 encoding.

use proptest::prelude::*;
use qshield_protocol::*;

fn arb_bytes32() -> impl Strategy<Value = Bytes32> {
    prop_oneof![Just(ZERO32), any::<[u8; 32]>()]
}

prop_compose! {
    fn arb_auth()(
        cluster_id in any::<[u8; 32]>(),
        program_id in any::<[u8; 32]>(),
        vault in any::<[u8; 32]>(),
        action in 1u8..=6,
        asset_type in 0u8..=3,
        nonce in any::<u64>(),
        valid_after in prop_oneof![Just(0i64), 0i64..i64::MAX / 2],
        expires_at in prop_oneof![Just(0i64), 0i64..i64::MAX],
        mint in arb_bytes32(),
        destination in arb_bytes32(),
        amount in prop_oneof![Just(0u64), any::<u64>()],
        decimals in prop_oneof![Just(0u8), any::<u8>()],
        fee_recipient in arb_bytes32(),
        fee_lamports in prop_oneof![Just(0u64), any::<u64>()],
        new_key_id in arb_bytes32(),
        new_algorithm in 0u8..=2,
    ) -> Authorization {
        Authorization {
            cluster_id, program_id, vault,
            action: Action::from_u8(action).unwrap(),
            asset_type: AssetType::from_u8(asset_type).unwrap(),
            nonce, valid_after, expires_at, mint, destination, amount, decimals,
            fee_recipient, fee_lamports, new_key_id, new_algorithm,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Decoding arbitrary bytes never panics.
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        let _ = Authorization::decode(&bytes);
    }

    /// Decoding arbitrary 292-byte strings: success implies canonical re-encoding.
    #[test]
    fn decode_implies_canonical(mut bytes in any::<[u8; 32]>().prop_flat_map(|_| proptest::collection::vec(any::<u8>(), AUTH_LEN))) {
        bytes[..22].copy_from_slice(&DOMAIN);
        bytes[22..24].copy_from_slice(&PROTOCOL_VERSION.to_le_bytes());
        if let Ok(a) = Authorization::decode(&bytes) {
            prop_assert_eq!(a.encode().unwrap().to_vec(), bytes);
        }
    }

    /// Encode/decode round trip for every valid authorization; validity is
    /// decided identically by `encode` and `decode`.
    #[test]
    fn roundtrip(a in arb_auth()) {
        match a.encode() {
            Ok(b) => prop_assert_eq!(Authorization::decode(&b).unwrap(), a),
            Err(e) => prop_assert_eq!(a.validate(), Err(e)),
        }
    }

    /// Changing any single byte of a valid encoding either makes it invalid
    /// or decodes to a different authorization (no two encodings of one value).
    #[test]
    fn single_byte_change_changes_meaning(a in arb_auth(), pos in 0usize..AUTH_LEN, delta in 1u8..=255) {
        if let Ok(b) = a.encode() {
            let mut m = b;
            m[pos] = m[pos].wrapping_add(delta);
            if let Ok(d) = Authorization::decode(&m) {
                prop_assert_ne!(d, a);
            }
        }
    }
}

#[test]
fn rejects_wrong_lengths_domain_version() {
    let a = Authorization {
        cluster_id: cluster::LOCALNET,
        program_id: [9; 32],
        vault: [8; 32],
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
    };
    let b = a.encode().unwrap();
    assert_eq!(Authorization::decode(&b[..291]), Err(Error::Length));
    let mut long = b.to_vec();
    long.push(0);
    assert_eq!(Authorization::decode(&long), Err(Error::Length));
    let mut m = b;
    m[0] ^= 1;
    assert_eq!(Authorization::decode(&m), Err(Error::Domain));
    let mut m = b;
    m[22] = 2;
    assert_eq!(Authorization::decode(&m), Err(Error::Version));
    let mut m = b;
    m[offsets::ACTION] = 0;
    assert_eq!(Authorization::decode(&m), Err(Error::Action));
    let mut m = b;
    m[offsets::ACTION] = 7;
    assert_eq!(Authorization::decode(&m), Err(Error::Action));
    let mut m = b;
    m[offsets::ASSET_TYPE] = 4;
    assert_eq!(Authorization::decode(&m), Err(Error::AssetType));
    // Pause with a non-zero amount is non-canonical.
    let mut m = b;
    m[offsets::AMOUNT] = 1;
    assert_eq!(Authorization::decode(&m), Err(Error::NonCanonical));
    // Fee recipient without fee is non-canonical.
    let mut m = b;
    m[offsets::FEE_RECIPIENT] = 1;
    assert_eq!(Authorization::decode(&m), Err(Error::NonCanonical));
    // Expiry not after valid_after.
    let mut x = a;
    x.valid_after = 100;
    x.expires_at = 100;
    assert_eq!(x.encode(), Err(Error::Window));
}

#[test]
fn liveness_window() {
    let mut a = Authorization {
        cluster_id: cluster::LOCALNET,
        program_id: [9; 32],
        vault: [8; 32],
        action: Action::Pause,
        asset_type: AssetType::None,
        nonce: 0,
        valid_after: 100,
        expires_at: 200,
        mint: ZERO32,
        destination: ZERO32,
        amount: 0,
        decimals: 0,
        fee_recipient: ZERO32,
        fee_lamports: 0,
        new_key_id: ZERO32,
        new_algorithm: 0,
    };
    assert!(!a.is_live_at(99));
    assert!(a.is_live_at(100));
    assert!(a.is_live_at(199));
    assert!(!a.is_live_at(200));
    a.valid_after = 0;
    a.expires_at = 0;
    assert!(a.is_live_at(i64::MIN) && a.is_live_at(i64::MAX));
}
