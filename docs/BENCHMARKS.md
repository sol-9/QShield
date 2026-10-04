# Benchmarks

Performance numbers QShield tracks (spec §49), their current values, and how to
regenerate them. Analysis and context: `docs/MLDSA_SOLANA_FEASIBILITY.md`.

## Current values (v0.1, Agave 4.3 SVM, SBPF v3)

| Metric | Value | Source |
|--------|-------|--------|
| PQ verification CU (expanded key), median / max over 200 keys | 828,104 / 830,543 | `results/litesvm-report.json` |
| PQ verification CU (compact key, for reference) | 2,296,339 (does not fit) | `results/litesvm-report.json` |
| Vault initialization CU | 8,443 | `results/vault-costs.json` |
| Key setup CU (finalize + 2 × expand) | 129,510 + 779,927 + 649,928 | `results/vault-costs.json` |
| SOL withdrawal CU (v1 inline / legacy buffered) | ≈ 830,000 / ≈ 830,500 | `results/vault-costs.json` |
| SPL withdrawal CU (SPL Token v1 inline incl. SOL fee / legacy buffered; Token-2022 v1 inline) | 833,295 / 832,609; 835,562 | `programs/qshield-vault/tests/spl.rs` (`--nocapture`) |
| Signature transport bytes | v1 withdrawal tx 3,010 bytes; legacy: 3 × ≤ 900-byte chunks + 637-byte execute tx | `results/vault-costs.json` |
| Transactions per withdrawal | 1 (v1) / 5 (legacy) | |
| End-to-end latency (local test validator, incl. confirmation) | ≈ 0.5 s (v1) / ≈ 2.5 s (legacy, sequential) | `results/validator-report.json` |
| Relayer cost per withdrawal | 5,000 lamports (v1) / ≈ 25,000 lamports + temporary 0.0183 SOL buffer rent (legacy), plus priority fees | |
| Rent: vault / key account / signature buffer | 2,672,640 / 153,843,840 / 18,346,560 lamports | `results/vault-costs.json` |
| Heap peak during verification | 7,424 bytes | `results/litesvm-report.json` |
| Largest stack frame (v0 build) | 1,504 bytes | `results/stack-report-sbpf-v0.json` |
| Program size (vault, SBPF v3) | 97,872 bytes (v0.3, with SPL support) | |

All paths are relative to `benchmarks/ml-dsa-solana/`.

## Regenerating

```bash
# 1. Benchmark program
cargo build-sbf --arch v3 --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
cargo run --release -p mldsa-bench-harness           # -> results/litesvm-report.json
scripts/bench-validator.sh                            # -> results/validator-report.json

# 2. Stack report (static analysis needs an SBPF v0 build)
cargo build-sbf --arch v0 --sbf-out-dir target/deploy-v0 \
  --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
scripts/sbf-stack-report.py target/deploy-v0/mldsa_bench_program.so > benchmarks/ml-dsa-solana/results/stack-report-sbpf-v0.json

# 3. Vault program costs
cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml
QSHIELD_COSTS_OUT=benchmarks/ml-dsa-solana/results/vault-costs.json \
  cargo test --release -p qshield-vault --test costs -- --nocapture
```

CI runs steps 1 (LiteSVM part) and 3 on every change and fails if any
verification-carrying instruction exceeds 1,400,000 CU. The committed result
files are the reference for review; regenerate them in any PR that changes the
verifier or the program and comment on differences.

## Methodology notes

* CU are reported by the runtime for the whole transaction (including the
  compute-budget instruction where present).
* Fixtures are deterministic (ChaCha20 seeded); keys are generated with
  `fips204`, signatures are hedged.
* LiteSVM runs with `LiteSVM::mainnet_feature_set()`. The validator harness runs
  a real `solana-test-validator`, which enables all features (including some
  not yet active on mainnet, e.g. SIMD-0500).
* Latency numbers come from a local validator and are indicative only.
