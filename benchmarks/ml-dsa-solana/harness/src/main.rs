//! ML-DSA-44 on Solana feasibility benchmark harness.
//!
//! Loads `target/deploy/mldsa_bench_program.so` into LiteSVM (Agave 4.3 SVM
//! crates, mainnet feature-set snapshot) and measures:
//!
//! * compute units (CU) for verification with each key strategy and transport,
//! * the CU distribution across many random keys/signatures (rejection
//!   sampling makes the cost data-dependent),
//! * CU of rejected (malformed / forged) inputs,
//! * a per-primitive CU profile,
//! * the heap high-water mark,
//! * serialized transaction sizes for each transport option (legacy vs v1),
//! * the number of buffer-upload transactions needed with legacy transactions.
//!
//! Usage: `cargo run --release -p mldsa-bench-harness -- [--keys N] [--out DIR]`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use litesvm::LiteSVM;
use mldsa_bench_fixtures::*;
use qshield_mldsa::{compute_tr, PUBLIC_KEY_LEN, SIGNATURE_LEN};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use solana_account::Account;
use solana_compute_budget::compute_budget::ComputeBudget;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::{v1, Message, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;
use solana_transaction::Transaction;

struct Bench {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
}

#[derive(Debug, Clone, Serialize)]
struct RunResult {
    ok: bool,
    /// CU consumed by the whole transaction (as reported by the runtime).
    cu: u64,
    heap_peak: Option<u64>,
    tx_size: usize,
    err: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    logs: Vec<String>,
}

impl Bench {
    fn new(so_path: &Path, uncapped: bool) -> Self {
        let mut svm = LiteSVM::new().with_mainnet_features().with_sigverify(true);
        if uncapped {
            // Measurement only: lets us observe the true cost of strategies
            // that exceed the 1.4M CU transaction cap.
            let mut budget = ComputeBudget::new_with_defaults(false);
            budget.compute_unit_limit = 20_000_000;
            svm = svm.with_compute_budget(budget);
        }
        let program_id = Pubkey::new_unique();
        svm.add_program_from_file(program_id, so_path)
            .expect("load program");
        let payer = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).unwrap();
        Self {
            svm,
            program_id,
            payer,
        }
    }

    fn put_account(&mut self, data: Vec<u8>) -> Pubkey {
        let key = Pubkey::new_unique();
        let lamports = self.svm.minimum_balance_for_rent_exemption(data.len());
        self.svm
            .set_account(
                key,
                Account {
                    lamports,
                    data,
                    owner: self.program_id,
                    executable: false,
                    rent_epoch: 0,
                },
            )
            .unwrap();
        key
    }

    fn ix(&self, data: Vec<u8>, accounts: &[Pubkey]) -> Instruction {
        Instruction::new_with_bytes(
            self.program_id,
            &data,
            accounts
                .iter()
                .map(|k| AccountMeta::new_readonly(*k, false))
                .collect(),
        )
    }

    fn legacy_tx(&mut self, ix: Instruction) -> VersionedTransaction {
        self.svm.expire_blockhash();
        let cb = ComputeBudgetInstruction::set_compute_unit_limit(MAX_TX_CU);
        let msg = Message::new_with_blockhash(
            &[cb, ix],
            Some(&self.payer.pubkey()),
            &self.svm.latest_blockhash(),
        );
        Transaction::new(&[&self.payer], msg, self.svm.latest_blockhash()).into()
    }

    fn v1_tx(&mut self, ix: Instruction) -> VersionedTransaction {
        self.svm.expire_blockhash();
        let msg = v1::Message::try_compile_with_config(
            &self.payer.pubkey(),
            &[ix],
            self.svm.latest_blockhash(),
            v1::TransactionConfig::empty()
                .with_compute_unit_limit(MAX_TX_CU)
                .with_loaded_accounts_data_size_limit(1 << 20),
        )
        .expect("compile v1");
        VersionedTransaction::try_new(VersionedMessage::V1(msg), &[&self.payer]).expect("sign v1")
    }

    fn run(&mut self, tx: VersionedTransaction) -> RunResult {
        let tx_size = bincode::serialize(&tx).unwrap().len();
        let (ok, meta, err) = match self.svm.send_transaction(tx) {
            Ok(m) => (true, m, None),
            Err(f) => (false, f.meta, Some(format!("{:?}", f.err))),
        };
        let heap_peak = meta.logs.iter().find_map(|l| {
            l.split("heap_peak=")
                .nth(1)
                .and_then(|v| v.trim().parse().ok())
        });
        RunResult {
            ok,
            cu: meta.compute_units_consumed,
            heap_peak,
            tx_size,
            err,
            logs: meta.logs,
        }
    }
}

/// Compact key (pk in account, tr recomputed) + signature in account; legacy tx.
fn compact_accounts(b: &mut Bench, f: &Fixture) -> RunResult {
    let pk = b.put_account(f.pk.clone());
    let sig = b.put_account(f.sig.clone());
    let tx = b.legacy_tx(b.ix(with_op(2, &[&ctx_msg(&f.msg)]), &[pk, sig]));
    b.run(tx)
}

/// Compact key with stored tr + signature in account; legacy tx.
fn compact_prepared(b: &mut Bench, f: &Fixture) -> RunResult {
    let mut key = f.pk.clone();
    key.extend_from_slice(&compute_tr(f.pk.as_slice().try_into().unwrap()));
    let key = b.put_account(key);
    let sig = b.put_account(f.sig.clone());
    let tx = b.legacy_tx(b.ix(with_op(3, &[&ctx_msg(&f.msg)]), &[key, sig]));
    b.run(tx)
}

/// Expanded key + signature in a buffer account; legacy tx (Architecture B execute step).
fn expanded_accounts(b: &mut Bench, f: &Fixture) -> RunResult {
    let key = b.put_account(expanded_key_bytes(&f.pk));
    let sig = b.put_account(f.sig.clone());
    let tx = b.legacy_tx(b.ix(with_op(8, &[&ctx_msg(&f.msg)]), &[key, sig]));
    b.run(tx)
}

/// Expanded key + signature inline in a v1 transaction (Architecture A).
fn expanded_inline_v1(b: &mut Bench, f: &Fixture) -> RunResult {
    let key = b.put_account(expanded_key_bytes(&f.pk));
    let tx = b.v1_tx(b.ix(with_op(9, &[&f.sig, &ctx_msg(&f.msg)]), &[key]));
    b.run(tx)
}

#[derive(Serialize, Default)]
struct Stats {
    n: usize,
    min: u64,
    median: u64,
    mean: f64,
    p99: u64,
    max: u64,
}

fn stats(mut v: Vec<u64>) -> Stats {
    v.sort_unstable();
    let n = v.len();
    Stats {
        n,
        min: v[0],
        median: v[n / 2],
        mean: (v.iter().sum::<u64>() as f64 / n as f64).round(),
        p99: v[((n as f64) * 0.99).ceil() as usize - 1],
        max: v[n - 1],
    }
}

/// Largest payload chunk that fits a legacy transaction writing to a buffer:
/// one signer (fee payer), accounts [payer, buffer, program], instruction data
/// = opcode(1) + offset(4) + chunk, no compute-budget instruction.
fn max_legacy_chunk(b: &mut Bench) -> usize {
    let buf = Pubkey::new_unique();
    for chunk in (800..LEGACY_PACKET_LIMIT).rev() {
        let data = with_op(5, &[&0u32.to_le_bytes(), &vec![0u8; chunk]]);
        let ix =
            Instruction::new_with_bytes(b.program_id, &data, vec![AccountMeta::new(buf, false)]);
        let msg =
            Message::new_with_blockhash(&[ix], Some(&b.payer.pubkey()), &b.svm.latest_blockhash());
        let tx = Transaction::new(&[&b.payer], msg, b.svm.latest_blockhash());
        if bincode::serialize(&tx).unwrap().len() <= LEGACY_PACKET_LIMIT {
            return chunk;
        }
    }
    0
}

#[derive(Serialize)]
struct Report {
    generated_by: &'static str,
    runtime: &'static str,
    feature_set: &'static str,
    max_tx_compute_units: u32,
    program_so_bytes: u64,
    keys_sampled: usize,
    message_len: usize,
    context: String,
    noop_tx_cu: u64,
    /// Strategy 1: compact public key, recompute everything (uncapped measurement).
    compact_cu_uncapped: Stats,
    /// Strategy 1 under the real 1.4M cap.
    compact_fits_under_cap: bool,
    /// Strategy 2: compact public key with stored tr (uncapped measurement).
    compact_prepared_cu_uncapped: Stats,
    compact_prepared_fits_under_cap: bool,
    /// Strategy 3: expanded key, signature in buffer account, legacy tx.
    expanded_buffer_legacy_cu: Stats,
    /// Strategy 3: expanded key, signature inline, v1 tx.
    expanded_inline_v1_cu: Stats,
    heap_peak_bytes: u64,
    expanded_key_account_bytes: usize,
    /// Rent-exempt minimum balances (lamports) under the mainnet feature set.
    rent_exempt_lamports: BTreeMap<String, u64>,
    negative_cases: BTreeMap<String, RunResult>,
    profile_cu: BTreeMap<String, u64>,
    transport: Transport,
}

#[derive(Serialize)]
struct Transport {
    legacy_packet_limit: usize,
    v1_tx_limit: usize,
    legacy_tx_pk_and_sig_inline_bytes: usize,
    legacy_tx_sig_inline_bytes: usize,
    legacy_tx_verify_from_accounts_bytes: usize,
    v1_tx_sig_inline_bytes: usize,
    v1_tx_pk_and_sig_inline_bytes: usize,
    legacy_max_chunk_payload: usize,
    legacy_upload_txs_for_signature: usize,
    legacy_upload_txs_for_public_key: usize,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut keys = 200usize;
    let mut out = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../results"));
    while let Some(a) = args.next() {
        match a.as_str() {
            "--keys" => keys = args.next().unwrap().parse().unwrap(),
            "--out" => out = PathBuf::from(args.next().unwrap()),
            _ => panic!("unknown arg {a}"),
        }
    }
    let so = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../target/deploy/mldsa_bench_program.so"
    ));
    let so_bytes = std::fs::metadata(&so)
        .expect("build the program first: cargo build-sbf")
        .len();

    let mut b = Bench::new(&so, false);
    let mut u = Bench::new(&so, true);
    let mut rng = ChaCha20Rng::seed_from_u64(0x5153_4849_454c_4400); // "QSHIELD\0"

    let noop = {
        let tx = b.legacy_tx(b.ix(vec![0], &[]));
        b.run(tx)
    };
    assert!(noop.ok);

    // --- Per-primitive profile -------------------------------------------
    let f0 = fixture(&mut rng);
    let prof = {
        let tx = b.v1_tx(b.ix(with_op(4, &[&f0.pk, &f0.sig]), &[]));
        b.run(tx)
    };
    assert!(prof.ok, "{:?} {:#?}", prof.err, prof.logs);
    let mut profile_cu = BTreeMap::new();
    let remaining = |l: &str| -> Option<u64> {
        l.split("Program consumption: ")
            .nth(1)?
            .split(' ')
            .next()?
            .parse()
            .ok()
    };
    for (i, l) in prof.logs.iter().enumerate() {
        if let Some(name) = l.split("profile:").nth(1) {
            let before = remaining(&prof.logs[i + 1]).expect("cu log");
            let after = remaining(&prof.logs[i + 2]).expect("cu log");
            profile_cu.insert(name.trim().to_string(), before - after);
        }
    }
    let overhead = profile_cu.remove("empty").unwrap();
    for v in profile_cu.values_mut() {
        *v -= overhead;
    }
    profile_cu.insert("measurement_overhead".into(), overhead);

    // --- Distributions ----------------------------------------------------
    let compact_keys = keys.min(20);
    let (mut c1, mut c2, mut e1, mut e2) = (vec![], vec![], vec![], vec![]);
    let (mut c1_capped_ok, mut c2_capped_ok) = (true, true);
    let mut heap_peak = 0u64;
    let mut sizes = (0usize, 0usize);
    let mut first = None;
    for i in 0..keys {
        let f = fixture(&mut rng);
        if i < compact_keys {
            let r = compact_accounts(&mut u, &f);
            assert!(r.ok, "{:?}", r.err);
            c1.push(r.cu);
            c1_capped_ok &= compact_accounts(&mut b, &f).ok;
            let r = compact_prepared(&mut u, &f);
            assert!(r.ok, "{:?}", r.err);
            c2.push(r.cu);
            c2_capped_ok &= compact_prepared(&mut b, &f).ok;
        }
        let r = expanded_accounts(&mut b, &f);
        assert!(
            r.ok,
            "expanded/buffer rejected valid signature: {:?} {:#?}",
            r.err, r.logs
        );
        e1.push(r.cu);
        heap_peak = heap_peak.max(r.heap_peak.unwrap_or(0));
        if i == 0 {
            sizes.0 = r.tx_size;
        }
        let r = expanded_inline_v1(&mut b, &f);
        assert!(
            r.ok,
            "expanded/v1 rejected valid signature: {:?} {:#?}",
            r.err, r.logs
        );
        e2.push(r.cu);
        if i == 0 {
            sizes.1 = r.tx_size;
            first = Some(f);
        }
    }
    let f = first.unwrap();
    // Regression gate: the strategy QShield uses must stay under the cap.
    for (name, v) in [("expanded/buffer", &e1), ("expanded/v1", &e2)] {
        let max = *v.iter().max().unwrap();
        assert!(
            max <= MAX_TX_CU as u64,
            "{name}: {max} CU exceeds the {MAX_TX_CU} CU transaction cap"
        );
    }

    // --- Transport sizes --------------------------------------------------
    let all_inline_v1 = {
        let tx = b.v1_tx(b.ix(with_op(1, &[&f.pk, &f.sig, &ctx_msg(&f.msg)]), &[]));
        bincode::serialize(&tx).unwrap().len()
    };
    let legacy_size = |b: &mut Bench, data: Vec<u8>, accts: &[Pubkey]| {
        let tx = b.legacy_tx(b.ix(data, accts));
        bincode::serialize(&tx).unwrap().len()
    };
    let legacy_all_inline =
        legacy_size(&mut b, with_op(1, &[&f.pk, &f.sig, &ctx_msg(&f.msg)]), &[]);
    let k = Pubkey::new_unique();
    let legacy_sig_inline = legacy_size(&mut b, with_op(9, &[&f.sig, &ctx_msg(&f.msg)]), &[k]);
    let chunk = max_legacy_chunk(&mut b);

    // --- Negative cases (expanded key, signature in buffer) ---------------
    let mut neg = BTreeMap::new();
    let mut case = |name: &str, m: Fixture, b: &mut Bench| {
        let key = b.put_account(expanded_key_bytes(&f.pk));
        let sig = b.put_account(m.sig.clone());
        let tx = b.legacy_tx(b.ix(with_op(8, &[&ctx_msg(&m.msg)]), &[key, sig]));
        let r = b.run(tx);
        assert!(!r.ok, "{name} unexpectedly verified");
        let logs = r
            .logs
            .iter()
            .filter(|l| l.contains("verify="))
            .cloned()
            .collect();
        neg.insert(name.to_string(), RunResult { logs, ..r });
    };
    let mutate = |g: &dyn Fn(&mut Fixture)| {
        let mut m = f.clone();
        g(&mut m);
        m
    };
    case("modified_message", mutate(&|m| m.msg[0] ^= 1), &mut b);
    case("modified_c_tilde", mutate(&|m| m.sig[0] ^= 1), &mut b);
    case("modified_z", mutate(&|m| m.sig[100] ^= 0x10), &mut b);
    case(
        "malformed_hint",
        mutate(&|m| m.sig[SIGNATURE_LEN - 1] = 0xff),
        &mut b,
    );
    case(
        "zero_signature",
        mutate(&|m| m.sig = vec![0; SIGNATURE_LEN]),
        &mut b,
    );
    case(
        "all_ff_signature",
        mutate(&|m| m.sig = vec![0xff; SIGNATURE_LEN]),
        &mut b,
    );
    let random_sig: Vec<u8> = (0..SIGNATURE_LEN).map(|_| rng.gen()).collect();
    case(
        "random_signature",
        mutate(&|m| m.sig = random_sig.clone()),
        &mut b,
    );
    case(
        "truncated_signature_account",
        mutate(&|m| m.sig.truncate(SIGNATURE_LEN - 1)),
        &mut b,
    );
    // Signature from a different key against this key.
    let other = fixture(&mut rng);
    case(
        "signature_from_other_key",
        mutate(&|m| m.sig = other.sig.clone()),
        &mut b,
    );
    // Wrong public key: verify f's signature against other's expanded key.
    {
        let key = b.put_account(expanded_key_bytes(&other.pk));
        let sig = b.put_account(f.sig.clone());
        let tx = b.legacy_tx(b.ix(with_op(8, &[&ctx_msg(&f.msg)]), &[key, sig]));
        let r = b.run(tx);
        assert!(!r.ok);
        neg.insert("wrong_public_key".into(), RunResult { logs: vec![], ..r });
    }
    // Oversized inline signature: one extra byte shifts every later field.
    {
        let key = b.put_account(expanded_key_bytes(&f.pk));
        let tx = b.v1_tx(b.ix(with_op(9, &[&f.sig, &[0], &ctx_msg(&f.msg)]), &[key]));
        let r = b.run(tx);
        assert!(!r.ok);
        neg.insert(
            "oversized_signature_inline_v1".into(),
            RunResult { logs: vec![], ..r },
        );
    }
    // Compact path, malformed public keys.
    for (name, pk) in [
        ("zero_public_key_compact", vec![0u8; PUBLIC_KEY_LEN]),
        (
            "truncated_public_key_compact",
            f.pk[..PUBLIC_KEY_LEN - 1].to_vec(),
        ),
    ] {
        let m = Fixture { pk, ..f.clone() };
        let r = compact_accounts(&mut u, &m);
        assert!(!r.ok);
        let logs = r
            .logs
            .iter()
            .filter(|l| l.contains("verify="))
            .cloned()
            .collect();
        neg.insert(name.into(), RunResult { logs, ..r });
    }

    let transport = Transport {
        legacy_packet_limit: LEGACY_PACKET_LIMIT,
        v1_tx_limit: V1_TX_LIMIT,
        legacy_tx_pk_and_sig_inline_bytes: legacy_all_inline,
        legacy_tx_sig_inline_bytes: legacy_sig_inline,
        legacy_tx_verify_from_accounts_bytes: sizes.0,
        v1_tx_sig_inline_bytes: sizes.1,
        v1_tx_pk_and_sig_inline_bytes: all_inline_v1,
        legacy_max_chunk_payload: chunk,
        legacy_upload_txs_for_signature: SIGNATURE_LEN.div_ceil(chunk),
        legacy_upload_txs_for_public_key: PUBLIC_KEY_LEN.div_ceil(chunk),
    };

    let report = Report {
        generated_by: "benchmarks/ml-dsa-solana/harness",
        runtime: "LiteSVM 0.17.0 (Agave 4.3 SVM crates)",
        feature_set:
            "LiteSVM::mainnet_feature_set() (snapshot sourced from mainnet-beta on 2026-09-27)",
        max_tx_compute_units: MAX_TX_CU,
        program_so_bytes: so_bytes,
        keys_sampled: keys,
        message_len: MSG_LEN,
        context: String::from_utf8_lossy(CTX).into(),
        noop_tx_cu: noop.cu,
        compact_cu_uncapped: stats(c1),
        compact_fits_under_cap: c1_capped_ok,
        compact_prepared_cu_uncapped: stats(c2),
        compact_prepared_fits_under_cap: c2_capped_ok,
        expanded_buffer_legacy_cu: stats(e1),
        expanded_inline_v1_cu: stats(e2),
        heap_peak_bytes: heap_peak,
        expanded_key_account_bytes: expanded_key_bytes(&f.pk).len(),
        rent_exempt_lamports: [
            ("signature_buffer_2420B", 2420usize),
            ("public_key_1312B", 1312),
            ("expanded_key_20544B", 20544),
            ("zero_data_account", 0),
        ]
        .into_iter()
        .map(|(k, n)| (k.to_string(), b.svm.minimum_balance_for_rent_exemption(n)))
        .collect(),
        negative_cases: neg,
        profile_cu,
        transport,
    };
    std::fs::create_dir_all(&out).unwrap();
    let json = serde_json::to_string_pretty(&report).unwrap();
    std::fs::write(out.join("litesvm-report.json"), &json).unwrap();
    println!("{json}");
}
