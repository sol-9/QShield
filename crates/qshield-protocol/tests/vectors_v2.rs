//! QSP-1 v2 known-answer vectors (`tests/vectors/qsp1/qsp1-v2-vectors.json`):
//! one canonical encoding per action plus rejected variants, with
//! deterministic ML-DSA-44 signatures (rnd = 0) so other implementations can
//! check encoding, decoding and verification.
//! Regenerate with `QSP1_REGENERATE=1 cargo test -p qshield-protocol --test vectors_v2`.

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use qshield_mldsa::{verify, Workspace};
use qshield_protocol::v2::*;
use qshield_protocol::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/qsp1/qsp1-v2-vectors.json"
);

fn h(tag: &str) -> Bytes32 {
    Sha256::digest(tag.as_bytes()).into()
}

fn base(action: ActionV2, role: Role) -> AuthorizationV2 {
    AuthorizationV2 {
        cluster_id: cluster::DEVNET,
        program_id: h("example program id"),
        vault: h("example vault"),
        action,
        asset_type: AssetType::None,
        nonce: 7,
        valid_after: 0,
        expires_at: 1_800_000_000,
        mint: ZERO32,
        destination: ZERO32,
        amount: 0,
        decimals: 0,
        fee_recipient: ZERO32,
        fee_lamports: 0,
        new_key_id: ZERO32,
        new_algorithm: 0,
        role,
        ref_id: 0,
        limit_lamports: 0,
        limit_period: 0,
    }
}

fn fields(a: &AuthorizationV2) -> Value {
    json!({
        "cluster_id": hex::encode(a.cluster_id),
        "program_id": hex::encode(a.program_id),
        "vault": hex::encode(a.vault),
        "action": a.action as u8,
        "asset_type": a.asset_type as u8,
        "nonce": a.nonce.to_string(),
        "valid_after": a.valid_after.to_string(),
        "expires_at": a.expires_at.to_string(),
        "mint": hex::encode(a.mint),
        "destination": hex::encode(a.destination),
        "amount": a.amount.to_string(),
        "decimals": a.decimals,
        "fee_recipient": hex::encode(a.fee_recipient),
        "fee_lamports": a.fee_lamports.to_string(),
        "new_key_id": hex::encode(a.new_key_id),
        "new_algorithm": a.new_algorithm,
        "role": a.role as u8,
        "ref_id": a.ref_id.to_string(),
        "limit_lamports": a.limit_lamports.to_string(),
        "limit_period": a.limit_period.to_string(),
    })
}

#[test]
fn qsp1_v2_vectors() {
    let xi = h("QSP-1 v2 test key");
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&xi);
    let pk = pk.into_bytes();
    use ActionV2::*;
    let sol = |a: ActionV2, r: Role| AuthorizationV2 {
        asset_type: AssetType::Sol,
        destination: h("example destination"),
        amount: 2_500_000_000,
        fee_lamports: 5_000,
        ..base(a, r)
    };
    let key = |a: ActionV2| AuthorizationV2 {
        new_key_id: h("example new key id"),
        new_algorithm: 1,
        ..base(a, Role::Guardian)
    };
    let valid: Vec<(&str, AuthorizationV2)> = vec![
        ("withdraw_sol", sol(WithdrawSol, Role::Everyday)),
        (
            "withdraw_spl",
            AuthorizationV2 {
                asset_type: AssetType::Token2022,
                mint: h("example mint"),
                decimals: 6,
                ..sol(WithdrawSpl, Role::Everyday)
            },
        ),
        ("propose_withdraw", sol(ProposeWithdraw, Role::Everyday)),
        (
            "approve_withdraw",
            AuthorizationV2 {
                ref_id: 6,
                fee_lamports: 0,
                ..sol(ApproveWithdraw, Role::Guardian)
            },
        ),
        (
            "cancel_proposal",
            AuthorizationV2 {
                ref_id: 6,
                ..base(CancelProposal, Role::Guardian)
            },
        ),
        ("rotate_key", key(RotateKey)),
        ("rotate_guardian", key(RotateGuardian)),
        ("pause_everyday", base(Pause, Role::Everyday)),
        ("unpause", base(Unpause, Role::Guardian)),
        (
            "enable_policy",
            AuthorizationV2 {
                limit_lamports: 1_000_000_000,
                limit_period: 86_400,
                role: Role::Everyday,
                ..key(EnablePolicy)
            },
        ),
        (
            "set_limit",
            AuthorizationV2 {
                limit_lamports: 0,
                limit_period: 3_600,
                ..base(SetLimit, Role::Everyday)
            },
        ),
        (
            "add_address",
            AuthorizationV2 {
                destination: h("example saved address"),
                ..base(AddAddress, Role::Guardian)
            },
        ),
        (
            "remove_address",
            AuthorizationV2 {
                destination: h("example saved address"),
                ..base(RemoveAddress, Role::Everyday)
            },
        ),
        ("disable_policy", base(DisablePolicy, Role::Guardian)),
    ];
    let mut vectors = vec![];
    for (name, a) in &valid {
        let b = a.encode().unwrap();
        assert_eq!(AuthorizationV2::decode(&b).unwrap(), *a);
        let sig = sk
            .try_sign_with_seed(&[0u8; 32], &b, ML_DSA_CONTEXT)
            .unwrap();
        let mut ws: Workspace = [[0u32; 256]; 7];
        assert!(verify(&pk, &b, ML_DSA_CONTEXT, &sig, &mut ws).is_ok());
        vectors.push(json!({
            "name": name,
            "fields": fields(a),
            "auth_hex": hex::encode(b),
            "signature_hex": hex::encode(sig),
            "expected": "ok",
        }));
    }
    // Rejected encodings (bytes derived from a valid one).
    let good = sol(WithdrawSol, Role::Everyday).encode().unwrap();
    let mutate = |f: &dyn Fn(&mut [u8; AUTH_V2_LEN])| {
        let mut b = good;
        f(&mut b);
        b
    };
    let invalid: Vec<(&str, Vec<u8>)> = vec![
        (
            "guardian_withdraw",
            mutate(&|b| b[offsets_v2::ROLE] = 2).to_vec(),
        ),
        (
            "unknown_role",
            mutate(&|b| b[offsets_v2::ROLE] = 0).to_vec(),
        ),
        (
            "close_vault_not_v2",
            mutate(&|b| b[offsets::ACTION] = 6).to_vec(),
        ),
        (
            "ref_id_on_withdraw",
            mutate(&|b| b[offsets_v2::REF_ID] = 1).to_vec(),
        ),
        (
            "limit_on_withdraw",
            mutate(&|b| b[offsets_v2::LIMIT_PERIOD] = 1).to_vec(),
        ),
        (
            "v1_domain",
            mutate(&|b| b[..22].copy_from_slice(&DOMAIN)).to_vec(),
        ),
        ("version_1", mutate(&|b| b[22] = 1).to_vec()),
        ("truncated", good[..316].to_vec()),
        ("v1_length", good[..AUTH_LEN].to_vec()),
    ];
    for (name, b) in &invalid {
        let e = AuthorizationV2::decode(b).expect_err(name);
        vectors.push(
            json!({ "name": name, "auth_hex": hex::encode(b), "expected": format!("{e:?}") }),
        );
    }
    let doc = json!({
        "description": "QSP-1 version 2 vectors (ADR-0018). Signatures: deterministic ML-DSA-44 (rnd = 0), context QSHIELD/QSP-1. Generated by crates/qshield-protocol/tests/vectors_v2.rs.",
        "key": { "xi_hex": hex::encode(xi), "public_key_hex": hex::encode(pk), "key_id_hex": hex::encode(Sha256::new().chain_update(KEY_ID_DOMAIN).chain_update([1u8]).chain_update(pk).finalize()) },
        "vectors": vectors,
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("QSP1_REGENERATE").is_ok() {
        std::fs::write(PATH, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(PATH).expect("vector file"), text);
}
