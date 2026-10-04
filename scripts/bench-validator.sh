#!/usr/bin/env bash
# End-to-end ML-DSA-44 verification benchmark against a local solana-test-validator.
#
# Requires the Agave CLI tools (solana, solana-test-validator, cargo-build-sbf)
# on PATH. Writes benchmarks/ml-dsa-solana/results/validator-report.json.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$ROOT/target/bench-validator}"
RPC="${RPC:-http://127.0.0.1:8899}"
KEYS="${KEYS:-3}"
mkdir -p "$WORK"

# SBPF v3: Agave 4.3 includes SIMD-0500 (disable deployment of SBPF v0-v2).
cargo build-sbf --arch "${SBF_ARCH:-v3}" --manifest-path "$ROOT/benchmarks/ml-dsa-solana/program/Cargo.toml"

STARTED=0
if ! solana -u "$RPC" cluster-version >/dev/null 2>&1; then
  solana-test-validator --reset --quiet --ledger "$WORK/ledger" >"$WORK/validator.log" 2>&1 &
  VPID=$!
  STARTED=1
  trap '[ "$STARTED" = 1 ] && kill $VPID 2>/dev/null || true' EXIT
  for _ in $(seq 1 60); do solana -u "$RPC" cluster-version >/dev/null 2>&1 && break; sleep 1; done
fi

PAYER="$WORK/payer.json"
[ -f "$PAYER" ] || solana-keygen new --no-bip39-passphrase --silent -o "$PAYER"
solana -u "$RPC" airdrop 100 "$(solana-keygen pubkey "$PAYER")" >/dev/null
PROGRAM_KP="$WORK/program-keypair.json"
[ -f "$PROGRAM_KP" ] || solana-keygen new --no-bip39-passphrase --silent -o "$PROGRAM_KP"
solana -u "$RPC" program deploy --keypair "$PAYER" --program-id "$PROGRAM_KP" \
  "$ROOT/target/deploy/mldsa_bench_program.so" >/dev/null
PROGRAM_ID="$(solana-keygen pubkey "$PROGRAM_KP")"

cargo run --release --manifest-path "$ROOT/benchmarks/ml-dsa-solana/validator/Cargo.toml" -- \
  --rpc "$RPC" --program "$PROGRAM_ID" --payer "$PAYER" --keys "$KEYS" \
  --out "$ROOT/benchmarks/ml-dsa-solana/results"
