//! Measures the compute-unit cost of every instruction in a realistic flow.
//! Run with `--nocapture` to print a JSON report; set `QSHIELD_COSTS_OUT=<path>`
//! to also write it to a file.

// LiteSVM's FailedTransactionMetadata is large; boxing it in tests buys nothing.
#![allow(clippy::result_large_err)]

mod common;

use std::collections::BTreeMap;

use common::*;
use qshield_protocol::{Action, Authorization};
use qshield_vault::instruction::build;
use qshield_vault::state::{KeyHeader, SigBuffer, Vault};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;

#[test]
fn instruction_costs() {
    let mut env = Env::new();
    let program = env.program;
    let wallet = env.wallet.insecure_clone();
    let relayer = env.relayer.insecure_clone();
    let key = PqKey::from_seed(77);
    let seed = [77u8; 32];
    let (vault, _) = build::vault_address(&program, &key.key_id, &seed);
    let mut cu: BTreeMap<String, u64> = BTreeMap::new();
    let mut put = |k: &str, v: u64| {
        cu.insert(k.to_string(), v);
    };

    // Key setup, measured step by step.
    let key_kp = Keypair::new();
    let rent = env.svm.minimum_balance_for_rent_exemption(KeyHeader::LEN);
    let alloc = solana_system_interface::instruction::create_account(
        &wallet.pubkey(),
        &key_kp.pubkey(),
        rent,
        KeyHeader::LEN as u64,
        &program,
    );
    let init = build::create_key(
        &program,
        &wallet.pubkey(),
        &key_kp.pubkey(),
        &vault,
        &key.key_id,
        1,
    );
    put(
        "create_key_tx (system alloc + create_key)",
        env.legacy(&[alloc, init], &wallet, &[&key_kp])
            .unwrap()
            .compute_units_consumed,
    );
    let mut total_write = 0;
    for (i, c) in key.pk.chunks(900).enumerate() {
        total_write += env
            .legacy(
                &[build::write_key(
                    &program,
                    &wallet.pubkey(),
                    &key_kp.pubkey(),
                    (i * 900) as u16,
                    c,
                )],
                &wallet,
                &[],
            )
            .unwrap()
            .compute_units_consumed;
    }
    put("write_key_total (2 legacy txs)", total_write);
    put(
        "finalize_key (sha256 key id + tr)",
        env.legacy(
            &[build::finalize_key(
                &program,
                &wallet.pubkey(),
                &key_kp.pubkey(),
            )],
            &wallet,
            &[],
        )
        .unwrap()
        .compute_units_consumed,
    );
    let mut expand = vec![];
    for _ in 0..2 {
        expand.push(
            env.legacy(
                &[build::expand_key(&program, &key_kp.pubkey(), 10)],
                &wallet,
                &[],
            )
            .unwrap()
            .compute_units_consumed,
        );
    }
    put("expand_key_polys_0_9", expand[0]);
    put("expand_key_polys_10_19", expand[1]);
    put(
        "initialize_vault",
        env.legacy(
            &[build::initialize_vault(
                &program,
                &wallet.pubkey(),
                &vault,
                &key_kp.pubkey(),
                &seed,
            )],
            &wallet,
            &[],
        )
        .unwrap()
        .compute_units_consumed,
    );
    put(
        "deposit_sol",
        env.legacy(
            &[build::deposit_sol(
                &program,
                &wallet.pubkey(),
                &vault,
                LAMPORTS_PER_SOL,
            )],
            &wallet,
            &[],
        )
        .unwrap()
        .compute_units_consumed,
    );
    let key_acct = key_kp.pubkey();
    let dest = Pubkey::new_unique();

    // Withdrawals.
    let a = env
        .withdraw_auth(&vault, 0, &dest, 1_000_000)
        .encode()
        .unwrap();
    let sig0 = key.sign(&a);
    let ix = build::execute(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &[w(&dest)],
        &a,
        &sig0,
    );
    put(
        "tx_bytes_withdraw_sol_inline_v1",
        v1_tx_size(&env, &relayer, ix),
    );
    put(
        "withdraw_sol_inline_v1",
        env.execute_v1(&relayer, &vault, &key_acct, &[w(&dest)], &a, &sig0)
            .unwrap()
            .compute_units_consumed,
    );
    let a = env
        .withdraw_auth(&vault, 1, &dest, 1_000_000)
        .encode()
        .unwrap();
    let s = key.sign(&a);
    put("create_sig_buffer", {
        env.legacy(
            &[build::create_sig_buffer(
                &program,
                &relayer.pubkey(),
                &vault,
                1,
            )],
            &relayer,
            &[],
        )
        .unwrap()
        .compute_units_consumed
    });
    let (buf, _) = build::sig_buffer_address(&program, &vault, &relayer.pubkey(), 1);
    let mut wsum = 0;
    for (i, c) in s.chunks(SIG_CHUNK).enumerate() {
        let fin = (i + 1) * SIG_CHUNK >= s.len();
        wsum += env
            .legacy(
                &[build::write_sig_buffer(
                    &program,
                    &relayer.pubkey(),
                    &buf,
                    (i * SIG_CHUNK) as u16,
                    fin,
                    c,
                )],
                &relayer,
                &[],
            )
            .unwrap()
            .compute_units_consumed;
    }
    put("write_sig_buffer_total (3 legacy txs)", wsum);
    let ix = build::execute_with_buffer(
        &program,
        &relayer.pubkey(),
        &vault,
        &key_acct,
        &buf,
        &relayer.pubkey(),
        &[w(&dest)],
        &a,
    );
    put(
        "tx_bytes_withdraw_sol_with_buffer_legacy",
        legacy_tx_size(&env, &relayer, ix.clone()),
    );
    put(
        "withdraw_sol_with_buffer_legacy",
        env.legacy(&[ix], &relayer, &[])
            .unwrap()
            .compute_units_consumed,
    );

    // Pause / unpause / rotate / close.
    let p = env.auth(&vault, 2).encode().unwrap();
    put(
        "pause",
        env.execute_v1(&relayer, &vault, &key_acct, &[], &p, &key.sign(&p))
            .unwrap()
            .compute_units_consumed,
    );
    let u = Authorization {
        action: Action::Unpause,
        ..env.auth(&vault, 3)
    }
    .encode()
    .unwrap();
    put(
        "unpause",
        env.execute_v1(&relayer, &vault, &key_acct, &[], &u, &key.sign(&u))
            .unwrap()
            .compute_units_consumed,
    );
    let new = PqKey::from_seed(78);
    let new_acct = env.setup_key(&wallet, &vault, &new);
    let r = Authorization {
        action: Action::RotateKey,
        new_key_id: new.key_id,
        new_algorithm: 1,
        ..env.auth(&vault, 4)
    }
    .encode()
    .unwrap();
    put(
        "rotate_key",
        env.execute_v1(
            &relayer,
            &vault,
            &key_acct,
            &[w(&new_acct), w(&wallet.pubkey())],
            &r,
            &key.sign(&r),
        )
        .unwrap()
        .compute_units_consumed,
    );

    let mut rent_map = BTreeMap::new();
    rent_map.insert(
        "vault_256B",
        env.svm.minimum_balance_for_rent_exemption(Vault::LEN),
    );
    rent_map.insert(
        "key_account_21976B",
        env.svm.minimum_balance_for_rent_exemption(KeyHeader::LEN),
    );
    rent_map.insert(
        "sig_buffer_2508B",
        env.svm.minimum_balance_for_rent_exemption(SigBuffer::LEN),
    );

    let mut report = String::from("{\n  \"measurements\": {\n");
    let n = cu.len();
    for (i, (k, v)) in cu.iter().enumerate() {
        report += &format!("    \"{k}\": {v}{}\n", if i + 1 < n { "," } else { "" });
    }
    report += "  },\n  \"rent_exempt_lamports\": {\n";
    let n = rent_map.len();
    for (i, (k, v)) in rent_map.iter().enumerate() {
        report += &format!("    \"{k}\": {v}{}\n", if i + 1 < n { "," } else { "" });
    }
    report += "  }\n}\n";
    println!("{report}");
    if let Ok(path) = std::env::var("QSHIELD_COSTS_OUT") {
        // Relative paths are resolved against the workspace root (tests run
        // with the crate directory as their working directory).
        let path = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).join(path);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(&path, &report).unwrap();
    }
    for (k, v) in cu.iter().filter(|(k, _)| !k.starts_with("tx_bytes")) {
        assert!(*v <= 1_400_000, "{k} exceeds the transaction CU cap");
    }
}

fn v1_tx_size(env: &Env, payer: &Keypair, ix: solana_instruction::Instruction) -> u64 {
    let msg = solana_message::v1::Message::try_compile_with_config(
        &payer.pubkey(),
        &[ix],
        env.svm.latest_blockhash(),
        solana_message::v1::TransactionConfig::empty()
            .with_compute_unit_limit(1_400_000)
            .with_loaded_accounts_data_size_limit(1 << 20),
    )
    .unwrap();
    let tx = solana_transaction::versioned::VersionedTransaction::try_new(
        solana_message::VersionedMessage::V1(msg),
        &[payer],
    )
    .unwrap();
    bincode::serialize(&tx).unwrap().len() as u64
}

fn legacy_tx_size(env: &Env, payer: &Keypair, ix: solana_instruction::Instruction) -> u64 {
    let cb = solana_compute_budget_interface::ComputeBudgetInstruction::set_compute_unit_limit(
        1_400_000,
    );
    let msg = solana_message::Message::new_with_blockhash(
        &[cb, ix],
        Some(&payer.pubkey()),
        &env.svm.latest_blockhash(),
    );
    let tx = solana_transaction::Transaction::new(&[payer], msg, env.svm.latest_blockhash());
    bincode::serialize(&tx).unwrap().len() as u64
}
