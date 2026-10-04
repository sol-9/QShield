//! SDK interoperability vectors (`tests/vectors/sdk/interop-v1.json`): PDA
//! derivations, account layouts and a signed authorization envelope, so other
//! SDKs (TypeScript) can check they derive, parse and render identically.
//! Regenerate with `QSHIELD_REGENERATE=1 cargo test -p qshield-client --test interop_vectors`.

use fips204::traits::{KeyGen as _, Signer as _};
use qshield_client::envelope::{describe, Hints};
use qshield_client::protocol::{cluster, Action, AssetType, Authorization, ML_DSA_CONTEXT, ZERO32};
use qshield_client::{Envelope, LocalKey, PqSigner};
use qshield_vault::instruction::build;
use qshield_vault::state::{BufferState, KeyHeader, KeyState, SigBuffer, Vault, VaultStatus};
use qshield_vault::token;
use serde_json::json;
use sha2::{Digest, Sha256};
use solana_pubkey::Pubkey;

const PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/vectors/sdk/interop-v1.json"
);

fn h(tag: &str) -> [u8; 32] {
    Sha256::digest(tag.as_bytes()).into()
}

#[test]
fn interop_vectors() {
    let program = Pubkey::new_from_array(h("interop program"));
    let key = LocalKey::from_seed(&h("interop key"));
    let key_id = key.key_id();
    let seed = h("interop vault seed");
    let (vault, vault_bump) = build::vault_address(&program, &key_id, &seed);
    let creator = Pubkey::new_from_array(h("interop relayer"));
    let (buf, buf_bump) =
        build::sig_buffer_address(&program, &vault, &creator, 0x0102_0304_0506_0708);

    let v = Vault {
        status: VaultStatus::Paused,
        bump: vault_bump,
        pq_algorithm: 1,
        nonce: 42,
        key_id,
        key_account: h("interop key account"),
        initial_key_id: key_id,
        vault_seed: seed,
        created_slot: 123_456_789,
        created_at: 1_790_000_000,
        policy_mode: 0,
    };
    let mut vd = vec![0u8; Vault::LEN];
    v.store(&mut vd).unwrap();
    let kh = KeyHeader {
        algorithm: 1,
        state: KeyState::Ready,
        bump: 0,
        in_use: true,
        guardian: false,
        expanded: 20,
        vault: vault.to_bytes(),
        key_id,
        creator: creator.to_bytes(),
    };
    let mut kd = vec![0u8; KeyHeader::LEN];
    kh.store(&mut kd).unwrap();
    kd[qshield_vault::state::key_off::PK..qshield_vault::state::key_off::TR]
        .copy_from_slice(key.public_key());
    let sb = SigBuffer {
        state: BufferState::Finalized,
        bump: buf_bump,
        vault: vault.to_bytes(),
        creator: creator.to_bytes(),
        buffer_id: 0x0102_0304_0506_0708,
    };
    let mut sd = vec![0u8; SigBuffer::LEN];
    sb.store(&mut sd).unwrap();

    // Envelope with a deterministic signature and a fee, rendered fields included.
    let auth = Authorization {
        cluster_id: cluster::DEVNET,
        program_id: program.to_bytes(),
        vault: vault.to_bytes(),
        action: Action::WithdrawSol,
        asset_type: AssetType::Sol,
        nonce: 42,
        valid_after: 1_790_000_000,
        expires_at: 1_790_003_600,
        mint: ZERO32,
        destination: h("interop destination"),
        amount: 1_234_567_890,
        decimals: 0,
        fee_recipient: ZERO32,
        fee_lamports: 5_000,
        new_key_id: ZERO32,
        new_algorithm: 0,
    };
    let mut env = Envelope::new(&auth, &key_id).unwrap();
    let (_, sk) = fips204::ml_dsa_44::KG::keygen_from_seed(&h("interop key"));
    let sig = sk
        .try_sign_with_seed(&[0u8; 32], &env.auth_bytes().unwrap(), ML_DSA_CONTEXT)
        .unwrap();
    env.attach_signature(key.public_key(), &sig).unwrap();
    env.hints = Hints::default();
    let rotate = Authorization {
        action: Action::RotateKey,
        asset_type: AssetType::None,
        destination: ZERO32,
        amount: 0,
        fee_lamports: 0,
        new_key_id: h("new key id"),
        new_algorithm: 1,
        valid_after: 0,
        expires_at: 0,
        ..auth
    };
    let close = Authorization {
        action: Action::CloseVault,
        amount: 0,
        fee_recipient: creator.to_bytes(),
        ..auth
    };

    let spl = Authorization {
        action: Action::WithdrawSpl,
        asset_type: AssetType::Token2022,
        mint: h("interop mint"),
        destination: h("interop token destination"),
        amount: 1_500_000,
        decimals: 6,
        ..auth
    };
    let mint = Pubkey::new_from_array(h("interop mint"));
    let ata_spl = token::associated_token_address(&vault, &mint, &token::TOKEN_PROGRAM);
    let ata_2022 = token::associated_token_address(&vault, &mint, &token::TOKEN_2022_PROGRAM);

    // Mint-policy samples: base mints and Token-2022 mints with extensions.
    let base_mint = |decimals: u8| {
        let mut d = vec![0u8; token::MINT_LEN];
        d[0] = 1;
        d[4..36].copy_from_slice(&h("interop mint authority"));
        d[36..44].copy_from_slice(&1_000_000_000u64.to_le_bytes());
        d[44] = decimals;
        d[45] = 1;
        d
    };
    let with_exts = |exts: &[(u16, usize)]| {
        let mut d = base_mint(9);
        d.resize(token::ACCOUNT_LEN, 0);
        d.push(1);
        for &(t, len) in exts {
            d.extend_from_slice(&t.to_le_bytes());
            d.extend_from_slice(&(len as u16).to_le_bytes());
            d.extend(std::iter::repeat_n(0x11u8, len));
        }
        d
    };
    let policy = |program: &Pubkey, d: Vec<u8>| {
        let r = token::parse_mint(program, &d);
        json!({
            "token_program": program.to_string(),
            "data_hex": hex::encode(&d),
            "result": match r {
                Ok(m) => json!({"ok": true, "decimals": m.decimals}),
                Err(e) => json!({"ok": false, "error": format!("{e:?}"), "code": e as u32}),
            },
        })
    };
    let mint_policy = vec![
        policy(&token::TOKEN_PROGRAM, base_mint(6)),
        policy(&token::TOKEN_2022_PROGRAM, base_mint(0)),
        policy(&token::TOKEN_2022_PROGRAM, with_exts(&[])),
        policy(
            &token::TOKEN_2022_PROGRAM,
            with_exts(&[(3, 32), (18, 64), (19, 77)]),
        ),
        policy(&token::TOKEN_2022_PROGRAM, with_exts(&[(18, 64), (12, 32)])),
        policy(&token::TOKEN_2022_PROGRAM, with_exts(&[(1, 108)])),
        policy(&token::TOKEN_2022_PROGRAM, with_exts(&[(14, 64)])),
        policy(&token::TOKEN_2022_PROGRAM, with_exts(&[(500, 4)])),
        policy(&token::TOKEN_PROGRAM, with_exts(&[])),
        policy(&token::TOKEN_2022_PROGRAM, {
            let mut d = with_exts(&[(18, 64)]);
            d.pop();
            d
        }),
    ];

    // A legacy transaction (compute budget + DepositSol + CreateKey) signed by
    // deterministic keypairs: checks message compilation, account ordering,
    // wire format and Ed25519 signing in other SDKs.
    let payer = solana_keypair::Keypair::new_from_array(h("interop payer"));
    let key_kp = solana_keypair::Keypair::new_from_array(h("interop key account kp"));
    use solana_signer::Signer as _;
    let tx_ixs = vec![
        solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(300_000),
        build::deposit_sol(&program, &payer.pubkey(), &vault, 123_456_789),
        build::create_key(
            &program,
            &payer.pubkey(),
            &key_kp.pubkey(),
            &vault,
            &key_id,
            1,
        ),
    ];
    let blockhash = solana_hash::Hash::new_from_array(h("interop blockhash"));
    let msg =
        solana_message::Message::new_with_blockhash(&tx_ixs, Some(&payer.pubkey()), &blockhash);
    let tx = solana_transaction::Transaction::new(&[&payer, &key_kp], msg.clone(), blockhash);
    let wire = qshield_client::rpc::serialize_tx(&tx.into()).unwrap();
    let ix_json: Vec<serde_json::Value> = tx_ixs
        .iter()
        .map(|ix| {
            json!({
                "program_id": ix.program_id.to_string(),
                "accounts": ix.accounts.iter().map(|a| json!({"pubkey": a.pubkey.to_string(), "signer": a.is_signer, "writable": a.is_writable})).collect::<Vec<_>>(),
                "data_hex": hex::encode(&ix.data),
            })
        })
        .collect();

    // v2 (guardian policy) renderings.
    use qshield_client::protocol::v2::{ActionV2, AuthorizationV2, Role};
    let v2 = |action, role, f: &dyn Fn(&mut AuthorizationV2)| {
        let mut a = AuthorizationV2 {
            cluster_id: cluster::DEVNET,
            program_id: program.to_bytes(),
            vault: vault.to_bytes(),
            action,
            asset_type: AssetType::None,
            nonce: 3,
            valid_after: 0,
            expires_at: 1_790_003_600,
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
        };
        f(&mut a);
        json!({ "auth_hex": hex::encode(a.encode().unwrap()), "fields": qshield_client::envelope::describe_v2(&a) })
    };
    let renderings_v2 = vec![
        v2(ActionV2::ProposeWithdraw, Role::Everyday, &|a| {
            a.asset_type = AssetType::Sol;
            a.destination = h("interop destination");
            a.amount = 2_000_000_000;
            a.fee_lamports = 5_000;
        }),
        v2(ActionV2::ApproveWithdraw, Role::Guardian, &|a| {
            a.asset_type = AssetType::SplToken;
            a.mint = h("interop mint");
            a.destination = h("interop token destination");
            a.amount = 1_500_000;
            a.decimals = 6;
            a.ref_id = 2;
        }),
        v2(ActionV2::EnablePolicy, Role::Everyday, &|a| {
            a.new_key_id = h("guardian key id");
            a.new_algorithm = 1;
            a.limit_lamports = 1_000_000_000;
            a.limit_period = 86_400;
        }),
        v2(ActionV2::AddAddress, Role::Guardian, &|a| {
            a.destination = h("saved address")
        }),
        v2(ActionV2::CancelProposal, Role::Everyday, &|a| a.ref_id = 9),
        v2(ActionV2::Pause, Role::Guardian, &|_| {}),
    ];

    let doc = json!({
        "description": "QShield SDK interoperability vectors v1 (generated by crates/qshield-client/tests/interop_vectors.rs)",
        "program_id": program.to_string(),
        "key_seed_hex": hex::encode(h("interop key")),
        "key_id_hex": hex::encode(key_id),
        "vault_seed_hex": hex::encode(seed),
        "vault_address": vault.to_string(),
        "vault_bump": vault_bump,
        "sig_buffer": { "creator": creator.to_string(), "buffer_id": "72623859790382856", "address": buf.to_string(), "bump": buf_bump },
        "accounts": {
            "vault_hex": hex::encode(&vd),
            "key_account_header_hex": hex::encode(&kd[..qshield_vault::state::key_off::TR]),
            "sig_buffer_header_hex": hex::encode(&sd[..SigBuffer::DATA]),
        },
        "envelope": serde_json::from_str::<serde_json::Value>(&env.to_json()).unwrap(),
        "renderings": [
            { "auth_hex": hex::encode(rotate.encode().unwrap()), "fields": describe(&rotate) },
            { "auth_hex": hex::encode(close.encode().unwrap()), "fields": describe(&close) },
            { "auth_hex": hex::encode(spl.encode().unwrap()), "fields": describe(&spl) },
        ],
        "vault_token_accounts": {
            "mint": mint.to_string(),
            "spl_token": ata_spl.to_string(),
            "token_2022": ata_2022.to_string(),
        },
        "mint_policy": mint_policy,
        "renderings_v2": renderings_v2,
        "legacy_transaction": {
            "payer_seed_hex": hex::encode(h("interop payer")),
            "key_account_seed_hex": hex::encode(h("interop key account kp")),
            "blockhash": blockhash.to_string(),
            "instructions": ix_json,
            "message_hex": hex::encode(msg.serialize()),
            "transaction_hex": hex::encode(&wire),
        },
    });
    let text = serde_json::to_string_pretty(&doc).unwrap() + "\n";
    if std::env::var("QSHIELD_REGENERATE").is_ok() {
        std::fs::write(PATH, &text).unwrap();
    }
    assert_eq!(std::fs::read_to_string(PATH).expect("vector file"), text);
    assert_eq!(
        Envelope::from_json(&serde_json::to_string(&doc["envelope"]).unwrap()).unwrap(),
        env
    );
}
