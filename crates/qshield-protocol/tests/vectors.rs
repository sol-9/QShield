//! QSP-1 known-answer vectors (`tests/vectors/qsp1/qsp1-vectors.json`).
//!
//! The vectors are generated deterministically:
//! * keys: `ML-DSA.KeyGen_internal(xi)` with `xi = SHA-256("QSP-1 test key " ‖ index)`,
//! * signatures: deterministic ML-DSA (`rnd = 0^32`, FIPS 204 Algorithm 2
//!   deterministic variant) — real wallets should use hedged signing; any
//!   valid signature verifies identically.
//!
//! Regenerate with `QSP1_REGENERATE=1 cargo test -p qshield-protocol --test vectors`.
//! Without the variable the test checks the committed file byte-for-byte and
//! verifies every signature with `qshield-mldsa` (independent of the signer).

use fips204::ml_dsa_44;
use fips204::traits::{KeyGen, SerDes, Signer};
use qshield_mldsa::{compute_mu, compute_tr, verify, Workspace, PUBLIC_KEY_LEN};
use qshield_protocol::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/qsp1/qsp1-vectors.json"
);

struct Key {
    pk: Vec<u8>,
    sk: ml_dsa_44::PrivateKey,
    xi: [u8; 32],
}

fn key(i: u8) -> Key {
    let mut h = Sha256::new();
    h.update(b"QSP-1 test key ");
    h.update([i]);
    let xi: [u8; 32] = h.finalize().into();
    let (pk, sk) = ml_dsa_44::KG::keygen_from_seed(&xi);
    Key {
        pk: pk.into_bytes().to_vec(),
        sk,
        xi,
    }
}

fn sign(k: &Key, msg: &[u8], ctx: &[u8]) -> Vec<u8> {
    k.sk.try_sign_with_seed(&[0u8; 32], msg, ctx)
        .unwrap()
        .to_vec()
}

fn sig_valid(pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> bool {
    let mut ws: Workspace = [[0u32; 256]; 7];
    verify(pk, msg, ctx, sig, &mut ws).is_ok()
}

fn addr(tag: &str) -> Bytes32 {
    Sha256::digest(tag.as_bytes()).into()
}

fn base() -> Authorization {
    Authorization {
        cluster_id: cluster::DEVNET,
        program_id: addr("example program id"),
        vault: addr("example vault"),
        action: Action::WithdrawSol,
        asset_type: AssetType::Sol,
        nonce: 10,
        valid_after: 0,
        expires_at: 1_800_000_000,
        mint: ZERO32,
        destination: addr("example destination"),
        amount: 10_000_000,
        decimals: 0,
        fee_recipient: ZERO32,
        fee_lamports: 0,
        new_key_id: ZERO32,
        new_algorithm: 0,
    }
}

fn fields(a: &Authorization) -> Value {
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
    })
}

fn generate() -> Value {
    let k0 = key(0);
    let k1 = key(1);
    let mut vectors = vec![];

    let mut push_valid = |name: &str, desc: &str, a: Authorization, k: &Key| {
        let bytes = a.encode().unwrap();
        let sig = sign(k, &bytes, ML_DSA_CONTEXT);
        let tr = compute_tr(k.pk.as_slice().try_into().unwrap());
        let mu = compute_mu(&tr, ML_DSA_CONTEXT, &bytes).unwrap();
        assert!(sig_valid(&k.pk, &bytes, ML_DSA_CONTEXT, &sig));
        vectors.push(json!({
            "name": name, "description": desc, "key": if std::ptr::eq(k, &k0) { 0 } else { 1 },
            "fields": fields(&a),
            "auth_hex": hex::encode(bytes),
            "auth_sha256": hex::encode(Sha256::digest(bytes)),
            "mu_hex": hex::encode(mu),
            "signature_hex": hex::encode(&sig),
            "expected": { "decode": "ok", "signature_valid": true }
        }));
    };

    push_valid(
        "withdraw_sol",
        "Withdraw 0.01 SOL, no relayer fee, nonce 10, devnet.",
        base(),
        &k0,
    );
    push_valid(
        "withdraw_sol_with_fee",
        "Withdraw with an explicit 5000-lamport relayer fee to a named recipient and a validity window.",
        Authorization { fee_lamports: 5_000, fee_recipient: addr("example relayer"), valid_after: 1_700_000_000, ..base() },
        &k0,
    );
    push_valid(
        "withdraw_sol_fee_to_fee_payer",
        "Fee paid to whichever account pays the transaction fee (fee_recipient all-zero).",
        Authorization {
            fee_lamports: 7_500,
            ..base()
        },
        &k0,
    );
    push_valid(
        "rotate_key",
        "Rotate to key 1 (new_key_id = SHA-256(KEY_ID_DOMAIN || 0x01 || pk1)).",
        Authorization {
            action: Action::RotateKey,
            asset_type: AssetType::None,
            destination: ZERO32,
            amount: 0,
            new_key_id: key_id_sha(&k1.pk),
            new_algorithm: 1,
            ..base()
        },
        &k0,
    );
    push_valid(
        "pause",
        "Pause withdrawals.",
        Authorization {
            action: Action::Pause,
            asset_type: AssetType::None,
            destination: ZERO32,
            amount: 0,
            ..base()
        },
        &k0,
    );
    push_valid(
        "unpause_mainnet",
        "Unpause on mainnet-beta, nonce 0, no expiry.",
        Authorization {
            action: Action::Unpause,
            asset_type: AssetType::None,
            destination: ZERO32,
            amount: 0,
            cluster_id: cluster::MAINNET_BETA,
            nonce: 0,
            expires_at: 0,
            ..base()
        },
        &k1,
    );
    push_valid(
        "close_vault",
        "Close the vault, sending all lamports above the tombstone reserve to destination.",
        Authorization {
            action: Action::CloseVault,
            amount: 0,
            ..base()
        },
        &k1,
    );
    push_valid(
        "withdraw_spl_reserved",
        "WithdrawSpl encoding (the vector name predates SPL support and is kept stable; executed by program v0.3+, ADR-0015).",
        Authorization {
            action: Action::WithdrawSpl,
            asset_type: AssetType::SplToken,
            mint: addr("example mint"),
            decimals: 6,
            amount: 10_000_000,
            ..base()
        },
        &k0,
    );

    // Negative vectors.
    let good = base().encode().unwrap();
    let good_sig = sign(&k0, &good, ML_DSA_CONTEXT);
    let mut neg = |name: &str, desc: &str, auth: Vec<u8>, sig: Vec<u8>, k: &Key| {
        let decode = match Authorization::decode(&auth) {
            Ok(_) => "ok".to_string(),
            Err(e) => format!("{e:?}"),
        };
        let valid = sig_valid(&k.pk, &auth, ML_DSA_CONTEXT, &sig);
        vectors.push(json!({
            "name": name, "description": desc, "key": if std::ptr::eq(k, &k0) { 0 } else { 1 },
            "auth_hex": hex::encode(&auth),
            "signature_hex": hex::encode(&sig),
            "expected": { "decode": decode, "signature_valid": valid }
        }));
    };
    let mut m = good;
    m[offsets::AMOUNT] ^= 0x01;
    neg(
        "neg_amount_modified",
        "Amount changed after signing.",
        m.to_vec(),
        good_sig.clone(),
        &k0,
    );
    let mut m = good;
    m[offsets::DESTINATION] ^= 0x80;
    neg(
        "neg_destination_modified",
        "Destination changed after signing.",
        m.to_vec(),
        good_sig.clone(),
        &k0,
    );
    let mut m = good;
    m[offsets::NONCE] = 11;
    neg(
        "neg_nonce_modified",
        "Nonce changed after signing.",
        m.to_vec(),
        good_sig.clone(),
        &k0,
    );
    let mut m = good;
    m[offsets::CLUSTER_ID..offsets::CLUSTER_ID + 32].copy_from_slice(&cluster::MAINNET_BETA);
    neg(
        "neg_cluster_modified",
        "Devnet authorization relabelled as mainnet.",
        m.to_vec(),
        good_sig.clone(),
        &k0,
    );
    neg(
        "neg_wrong_key",
        "Valid signature by key 0 checked against key 1.",
        good.to_vec(),
        good_sig.clone(),
        &k1,
    );
    neg(
        "neg_empty_context",
        "Signed with an empty ML-DSA context instead of QSHIELD/QSP-1.",
        good.to_vec(),
        sign(&k0, &good, b""),
        &k0,
    );
    let mut s = good_sig.clone();
    s[0] ^= 1;
    neg(
        "neg_signature_bitflip",
        "One bit of c_tilde flipped.",
        good.to_vec(),
        s,
        &k0,
    );
    neg(
        "neg_signature_truncated",
        "Signature one byte short.",
        good.to_vec(),
        good_sig[..2419].to_vec(),
        &k0,
    );
    let mut s = good_sig.clone();
    s.push(0);
    neg(
        "neg_signature_padded",
        "Signature with one trailing byte.",
        good.to_vec(),
        s,
        &k0,
    );
    let mut m = good;
    m[0] = b'X';
    neg(
        "neg_domain",
        "Wrong domain tag (signature by key 0 over these exact bytes is still valid ML-DSA).",
        m.to_vec(),
        sign(&k0, &m, ML_DSA_CONTEXT),
        &k0,
    );
    let mut m = good;
    m[offsets::VERSION] = 2;
    neg(
        "neg_version",
        "Unsupported protocol version.",
        m.to_vec(),
        sign(&k0, &m, ML_DSA_CONTEXT),
        &k0,
    );
    let mut m = good;
    m[offsets::MINT] = 1;
    neg(
        "neg_noncanonical",
        "WithdrawSol with a non-zero mint (non-canonical).",
        m.to_vec(),
        sign(&k0, &m, ML_DSA_CONTEXT),
        &k0,
    );
    neg(
        "neg_truncated_auth",
        "Authorization of 291 bytes.",
        good[..291].to_vec(),
        sign(&k0, &good[..291], ML_DSA_CONTEXT),
        &k0,
    );

    json!({
        "spec": "QSP-1 (docs/QSP-1.md)",
        "ml_dsa": "ML-DSA-44 (FIPS 204), pure, context \"QSHIELD/QSP-1\"",
        "signing": "deterministic (rnd = 0^32) for reproducibility",
        "keys": [
            { "xi_hex": hex::encode(k0.xi), "public_key_hex": hex::encode(&k0.pk), "key_id_hex": hex::encode(key_id_sha(&k0.pk)) },
            { "xi_hex": hex::encode(k1.xi), "public_key_hex": hex::encode(&k1.pk), "key_id_hex": hex::encode(key_id_sha(&k1.pk)) },
        ],
        "vectors": vectors,
    })
}

fn key_id_sha(pk: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(KEY_ID_DOMAIN);
    h.update([Algorithm::MlDsa44 as u8]);
    h.update(pk);
    h.finalize().into()
}

#[test]
fn qsp1_vectors() {
    let generated = generate();
    let text = serde_json::to_string_pretty(&generated).unwrap() + "\n";
    if std::env::var("QSP1_REGENERATE").is_ok() {
        std::fs::write(PATH, &text).unwrap();
    }
    let committed =
        std::fs::read_to_string(PATH).expect("vector file (regenerate with QSP1_REGENERATE=1)");
    assert_eq!(
        committed, text,
        "committed QSP-1 vectors differ from the reference implementation"
    );

    // Independent re-check from the committed JSON only.
    let v: Value = serde_json::from_str(&committed).unwrap();
    let keys: Vec<Vec<u8>> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| hex::decode(k["public_key_hex"].as_str().unwrap()).unwrap())
        .collect();
    for k in v["keys"].as_array().unwrap() {
        let pk = hex::decode(k["public_key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(pk.len(), PUBLIC_KEY_LEN);
        assert_eq!(
            hex::encode(key_id_sha(&pk)),
            k["key_id_hex"].as_str().unwrap()
        );
    }
    for t in v["vectors"].as_array().unwrap() {
        let auth = hex::decode(t["auth_hex"].as_str().unwrap()).unwrap();
        let sig = hex::decode(t["signature_hex"].as_str().unwrap()).unwrap();
        let pk = &keys[t["key"].as_u64().unwrap() as usize];
        let decode = match Authorization::decode(&auth) {
            Ok(a) => {
                if let Some(f) = t.get("fields") {
                    assert_eq!(&fields(&a), f);
                }
                "ok".to_string()
            }
            Err(e) => format!("{e:?}"),
        };
        assert_eq!(
            decode,
            t["expected"]["decode"].as_str().unwrap(),
            "{}",
            t["name"]
        );
        assert_eq!(
            sig_valid(pk, &auth, ML_DSA_CONTEXT, &sig),
            t["expected"]["signature_valid"].as_bool().unwrap(),
            "{}",
            t["name"]
        );
    }
}
