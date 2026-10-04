//! Runs the ML-DSA-44 benchmark program against a real `solana-test-validator`
//! (or any cluster) over JSON-RPC and measures what a user would experience:
//! real transaction serialization, RPC acceptance of large (v1) transactions,
//! compute units and fees reported by the runtime, and end-to-end latency.
//!
//! The expanded key account is uploaded from an off-chain expansion here; in
//! the vault program the expansion is computed on-chain (see
//! docs/MLDSA_SOLANA_FEASIBILITY.md). This binary measures *verification*.
//!
//! Usage (see scripts/bench-validator.sh):
//!   mldsa-bench-validator --rpc http://127.0.0.1:8899 --program <ID> --payer <keypair.json> [--keys N] [--out DIR]

use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant};

use mldsa_bench_fixtures::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use solana_commitment_config::CommitmentConfig;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::{read_keypair_file, Keypair};
use solana_message::{v1, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_rpc_client::rpc_client::RpcClient;
use solana_rpc_client_api::config::RpcTransactionConfig;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;
use solana_transaction_status_client_types::option_serializer::OptionSerializer;
use solana_transaction_status_client_types::UiTransactionEncoding;

const CHUNK: usize = 1024;

struct Ctx {
    rpc: RpcClient,
    program: Pubkey,
    payer: Keypair,
}

#[derive(Serialize, Clone, Debug)]
struct TxResult {
    ok: bool,
    size: usize,
    cu: Option<u64>,
    fee: u64,
    latency_ms: u128,
    err: Option<String>,
}

impl Ctx {
    fn send(&self, tx: VersionedTransaction) -> TxResult {
        let size = bincode::serialize(&tx).unwrap().len();
        let start = Instant::now();
        let res = self.rpc.send_and_confirm_transaction(&tx);
        let latency_ms = start.elapsed().as_millis();
        match res {
            Ok(sig) => {
                let cfg = RpcTransactionConfig {
                    encoding: Some(UiTransactionEncoding::Base64),
                    commitment: Some(CommitmentConfig::confirmed()),
                    max_supported_transaction_version: Some(1),
                };
                let mut meta = None;
                for _ in 0..20 {
                    if let Ok(t) = self.rpc.get_transaction_with_config(&sig, cfg) {
                        meta = t.transaction.meta;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
                let meta = meta.expect("transaction meta");
                let cu = match meta.compute_units_consumed {
                    OptionSerializer::Some(c) => Some(c),
                    _ => None,
                };
                TxResult {
                    ok: meta.err.is_none(),
                    size,
                    cu,
                    fee: meta.fee,
                    latency_ms,
                    err: None,
                }
            }
            Err(e) => TxResult {
                ok: false,
                size,
                cu: None,
                fee: 0,
                latency_ms,
                err: Some(e.to_string()),
            },
        }
    }

    fn legacy(&self, ixs: &[Instruction], extra_signers: &[&Keypair]) -> VersionedTransaction {
        let bh = self.rpc.get_latest_blockhash().unwrap();
        let msg = Message::new_with_blockhash(ixs, Some(&self.payer.pubkey()), &bh);
        let mut signers: Vec<&Keypair> = vec![&self.payer];
        signers.extend_from_slice(extra_signers);
        Transaction::new(&signers, msg, bh).into()
    }

    fn v1(&self, ix: Instruction) -> VersionedTransaction {
        let bh = self.rpc.get_latest_blockhash().unwrap();
        let msg = v1::Message::try_compile_with_config(
            &self.payer.pubkey(),
            &[ix],
            bh,
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(MAX_TX_CU)
                .with_loaded_accounts_data_size_limit(1 << 20),
        )
        .unwrap();
        VersionedTransaction::try_new(VersionedMessage::V1(msg), &[&self.payer]).unwrap()
    }

    /// Creates a program-owned account of `len` bytes and uploads `data` in
    /// legacy-sized chunks. Returns the account and the per-tx results.
    fn create_and_upload(&self, data: &[u8]) -> (Pubkey, Vec<TxResult>) {
        let acct = Keypair::new();
        let lamports = self
            .rpc
            .get_minimum_balance_for_rent_exemption(data.len())
            .unwrap();
        let create = solana_system_interface::instruction::create_account(
            &self.payer.pubkey(),
            &acct.pubkey(),
            lamports,
            data.len() as u64,
            &self.program,
        );
        let mut results = vec![self.send(self.legacy(&[create], &[&acct]))];
        assert!(results[0].ok, "create account failed: {:?}", results[0]);
        for (i, chunk) in data.chunks(CHUNK).enumerate() {
            let off = ((i * CHUNK) as u32).to_le_bytes();
            let ix = Instruction::new_with_bytes(
                self.program,
                &with_op(5, &[&off, chunk]),
                vec![AccountMeta::new(acct.pubkey(), false)],
            );
            let r = self.send(self.legacy(&[ix], &[]));
            assert!(r.ok, "upload failed: {r:?}");
            assert!(r.size <= LEGACY_PACKET_LIMIT);
            results.push(r);
        }
        (acct.pubkey(), results)
    }
}

#[derive(Serialize)]
struct KeyRun {
    architecture_b_upload_txs: usize,
    architecture_b_upload_latency_ms: u128,
    architecture_b_verify: TxResult,
    architecture_b_total_latency_ms: u128,
    architecture_b_total_fees_lamports: u64,
    architecture_a_verify_v1: TxResult,
    negative_modified_message_v1: TxResult,
}

#[derive(Serialize)]
struct Report {
    generated_by: &'static str,
    rpc: String,
    cluster_version: String,
    tx_v1_feature_active: Option<bool>,
    keys: usize,
    runs: Vec<KeyRun>,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut rpc, mut program, mut payer, mut keys) =
        (String::new(), String::new(), String::new(), 3usize);
    let mut out = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../results"));
    while let Some(a) = args.next() {
        let v = args.next().expect("value");
        match a.as_str() {
            "--rpc" => rpc = v,
            "--program" => program = v,
            "--payer" => payer = v,
            "--keys" => keys = v.parse().unwrap(),
            "--out" => out = PathBuf::from(v),
            _ => panic!("unknown arg {a}"),
        }
    }
    let ctx = Ctx {
        rpc: RpcClient::new_with_commitment(rpc.clone(), CommitmentConfig::confirmed()),
        program: Pubkey::from_str(&program).unwrap(),
        payer: read_keypair_file(&payer).expect("payer keypair"),
    };
    let version = ctx
        .rpc
        .get_version()
        .map(|v| v.solana_core)
        .unwrap_or_default();
    let feature = Pubkey::from_str("txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL").unwrap();
    // A feature account exists (owned by the feature program) once activated or pending.
    let tx_v1_feature_active = ctx
        .rpc
        .get_account(&feature)
        .ok()
        .map(|a| a.data.len() > 1 && a.data[0] == 1);

    let mut rng = ChaCha20Rng::seed_from_u64(0x5153_4849_454c_4401);
    let mut runs = vec![];
    for _ in 0..keys {
        let f = fixture(&mut rng);
        let (key_acct, _) = ctx.create_and_upload(&expanded_key_bytes(&f.pk));

        // Architecture B: signature uploaded to a buffer in legacy txs, then verified.
        let t0 = Instant::now();
        let (sig_acct, uploads) = ctx.create_and_upload(&f.sig);
        let upload_latency = t0.elapsed().as_millis();
        let cb = ComputeBudgetInstruction::set_compute_unit_limit(MAX_TX_CU);
        let verify_ix = Instruction::new_with_bytes(
            ctx.program,
            &with_op(8, &[&ctx_msg(&f.msg)]),
            vec![
                AccountMeta::new_readonly(key_acct, false),
                AccountMeta::new_readonly(sig_acct, false),
            ],
        );
        let b_verify = ctx.send(ctx.legacy(&[cb, verify_ix], &[]));
        let b_total = t0.elapsed().as_millis();
        assert!(b_verify.ok, "architecture B verify failed: {b_verify:?}");
        let b_fees = uploads.iter().map(|r| r.fee).sum::<u64>() + b_verify.fee;

        // Architecture A: one v1 transaction carrying the signature inline.
        let a_ix = Instruction::new_with_bytes(
            ctx.program,
            &with_op(9, &[&f.sig, &ctx_msg(&f.msg)]),
            vec![AccountMeta::new_readonly(key_acct, false)],
        );
        let a_verify = ctx.send(ctx.v1(a_ix));
        assert!(a_verify.ok, "architecture A verify failed: {a_verify:?}");

        // Negative: modified message must be rejected on-chain.
        let mut bad = f.msg.clone();
        bad[0] ^= 1;
        let n_ix = Instruction::new_with_bytes(
            ctx.program,
            &with_op(9, &[&f.sig, &ctx_msg(&bad)]),
            vec![AccountMeta::new_readonly(key_acct, false)],
        );
        let neg = ctx.send(ctx.v1(n_ix));
        assert!(!neg.ok, "modified message accepted!");

        runs.push(KeyRun {
            architecture_b_upload_txs: uploads.len(),
            architecture_b_upload_latency_ms: upload_latency,
            architecture_b_verify: b_verify,
            architecture_b_total_latency_ms: b_total,
            architecture_b_total_fees_lamports: b_fees,
            architecture_a_verify_v1: a_verify,
            negative_modified_message_v1: neg,
        });
    }
    let report = Report {
        generated_by: "benchmarks/ml-dsa-solana/validator",
        rpc,
        cluster_version: version,
        tx_v1_feature_active,
        keys,
        runs,
    };
    std::fs::create_dir_all(&out).unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(out.join("validator-report.json"), &json).unwrap();
    println!("{json}");
}
