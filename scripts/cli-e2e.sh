#!/usr/bin/env bash
# End-to-end test of the qshield CLI against a local solana-test-validator:
# the MVP flow (spec §59) driven entirely through the CLI, including an
# offline-signed authorization, buffered submission, key rotation and close.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$ROOT/target/cli-e2e}"
RPC="${RPC:-http://127.0.0.1:8899}"
rm -rf "$WORK" && mkdir -p "$WORK"
cd "$WORK"

cargo build-sbf --arch v3 --features cluster-localnet --manifest-path "$ROOT/programs/qshield-vault/Cargo.toml"
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p qshield-cli
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p qshield-client --example spl_test_util
cargo build --release --manifest-path "$ROOT/Cargo.toml" -p qshield-relayer
Q="$ROOT/target/release/qshield"
T() { "$ROOT/target/release/examples/spl_test_util" "$RPC" "$@"; }

STARTED=0
if ! solana -u "$RPC" cluster-version >/dev/null 2>&1; then
  solana-test-validator --reset --quiet --ledger "$WORK/ledger" >"$WORK/validator.log" 2>&1 &
  VPID=$!; STARTED=1
  trap '[ "$STARTED" = 1 ] && kill $VPID 2>/dev/null || true' EXIT
  for _ in $(seq 1 60); do solana -u "$RPC" cluster-version >/dev/null 2>&1 && break; sleep 1; done
fi

solana-keygen new --no-bip39-passphrase --silent -o wallet.json
solana-keygen new --no-bip39-passphrase --silent -o relayer.json
solana-keygen new --no-bip39-passphrase --silent -o program.json
solana -u "$RPC" airdrop 50 "$(solana-keygen pubkey wallet.json)" >/dev/null
solana -u "$RPC" airdrop 10 "$(solana-keygen pubkey relayer.json)" >/dev/null
solana -u "$RPC" program deploy --keypair wallet.json --program-id program.json "$ROOT/target/deploy/qshield_vault.so" >/dev/null
# Newly deployed programs become executable in the next slot.
SLOT="$(solana -u "$RPC" slot)"; while [ "$(solana -u "$RPC" slot)" -le $((SLOT + 1)) ]; do sleep 0.5; done

export QSHIELD_RPC_URL="$RPC" QSHIELD_PROGRAM_ID="$(solana-keygen pubkey program.json)" QSHIELD_CLUSTER=localnet PW="e2e password"
solana-keygen new --no-bip39-passphrase --silent -o dest.json
DEST="$(solana-keygen pubkey dest.json)"
bal() { solana -u "$RPC" balance --lamports "$1" | cut -d' ' -f1; }

echo "== 1. generate PQ key locally"
$Q --password-env PW keygen --out key.json
echo "== 2. create vault (wallet pays)"
VAULT="$($Q --password-env PW vault create --key key.json --payer wallet.json)"
echo "vault $VAULT"
echo "== 3. deposit 0.1 SOL"
$Q deposit-sol --vault "$VAULT" --payer wallet.json --amount 0.1 --key key.json >/dev/null
$Q vault info "$VAULT" --key key.json
echo "== 4-10. withdraw 0.01 SOL; relayer pays (v1 inline)"
$Q --password-env PW withdraw --key key.json --vault "$VAULT" --to "$DEST" --amount 0.01 --payer relayer.json --yes
[ "$(bal "$DEST")" = 10000000 ] || { echo "destination balance wrong"; exit 1; }
echo "== 11-12. replay fails"
$Q --password-env PW auth withdraw-sol --vault "$VAULT" --to "$DEST" --amount 0.01 --key key.json --out a1.json
$Q --password-env PW sign a1.json --key key.json --yes
$Q submit a1.json --payer relayer.json
if $Q submit a1.json --payer relayer.json 2>/dev/null; then echo "REPLAY ACCEPTED"; exit 1; fi
echo "== 13. edited amount fails"
$Q --password-env PW auth withdraw-sol --vault "$VAULT" --to "$DEST" --amount 0.01 --key key.json --out a2.json
$Q --password-env PW sign a2.json --key key.json --yes
python3 - <<'PY'
import json
e = json.load(open("a2.json"))
b = bytearray.fromhex(e["auth_hex"]); b[210] ^= 0x40           # amount
e["auth_hex"] = b.hex(); e["fields"]["amount"] = "x"
json.dump(e, open("a2-tampered.json", "w"))
PY
if $Q submit a2-tampered.json --payer relayer.json 2>/dev/null; then echo "TAMPERED ACCEPTED"; exit 1; fi
echo "== offline flow: unsigned file -> offline sign -> buffered (legacy) submission"
NONCE="$($Q vault info "$VAULT" | awk '/^nonce/ {print $2}')"
KEYID="$($Q key info key.json | awk '/^key_id/ {print $2}')"
QSHIELD_RPC_URL=http://127.0.0.1:9 $Q auth withdraw-sol --vault "$VAULT" --to "$DEST" --amount 0.02 \
  --nonce "$NONCE" --signer-key-id "$KEYID" --out offline.json
QSHIELD_RPC_URL=http://127.0.0.1:9 $Q --password-env PW sign offline.json --key key.json --yes
$Q submit offline.json --payer relayer.json --transport buffered
[ "$(bal "$DEST")" = 40000000 ] || { echo "destination balance wrong after offline flow"; exit 1; }
echo "== 16. the Solana wallet alone cannot withdraw: wallet signs with a different PQ key"
$Q --password-env PW keygen --out attacker.json
$Q --password-env PW auth withdraw-sol --vault "$VAULT" --to "$(solana-keygen pubkey wallet.json)" --amount 0.05 \
  --signer-key-id "$($Q key info attacker.json | awk '/^key_id/ {print $2}')" --nonce "$(( NONCE + 1 ))" --out steal.json
$Q --password-env PW sign steal.json --key attacker.json --yes
if $Q submit steal.json --payer wallet.json 2>/dev/null; then echo "THEFT ACCEPTED"; exit 1; fi
echo "== relayer: gas-sponsored submission over HTTP (relayer holds no PQ key)"
solana-keygen new --no-bip39-passphrase --silent -o relayer-svc.json
solana -u "$RPC" airdrop 5 "$(solana-keygen pubkey relayer-svc.json)" >/dev/null
"$ROOT/target/release/qshield-relayer" --bind 127.0.0.1:8787 --url "$RPC" --keypair relayer-svc.json \
  --program-id "$QSHIELD_PROGRAM_ID" >relayer.log 2>&1 &
RPID=$!
trap '[ "$STARTED" = 1 ] && kill $VPID 2>/dev/null; kill $RPID 2>/dev/null || true' EXIT
for _ in $(seq 1 50); do curl -sf http://127.0.0.1:8787/health >/dev/null && break; sleep 0.2; done
curl -sf http://127.0.0.1:8787/v1/info | grep -q '"cluster":"localnet"'
BEFORE="$(bal "$DEST")"
$Q --password-env PW auth withdraw-sol --vault "$VAULT" --to "$DEST" --amount 0.003 --key key.json --out r1.json
$Q --password-env PW sign r1.json --key key.json --yes
$Q submit r1.json --relayer http://127.0.0.1:8787
[ "$(bal "$DEST")" = $(( BEFORE + 3000000 )) ] || { echo "relayed withdrawal missing"; exit 1; }
if $Q submit a2-tampered.json --relayer http://127.0.0.1:8787 2>/dev/null; then echo "RELAYER ACCEPTED TAMPERED"; exit 1; fi
if $Q submit r1.json --relayer http://127.0.0.1:8787 >/dev/null 2>&1 && [ "$(bal "$DEST")" != $(( BEFORE + 3000000 )) ]; then
  echo "RELAYER REPLAYED"; exit 1; fi
curl -sf http://127.0.0.1:8787/health | grep -q '"submitted":1'
echo "== guardian policy: instant sends within the limit, guardian approval beyond it, freeze, saved addresses"
$Q --password-env PW keygen --out ek.json
$Q --password-env PW keygen --out gk.json
GV="$($Q --password-env PW vault create --key ek.json --payer wallet.json --label guarded)"
$Q deposit-sol --vault "$GV" --payer wallet.json --amount 0.5 --key ek.json >/dev/null
$Q --password-env PW guardian enable --key ek.json --guardian gk.json --vault "$GV" --key-payer wallet.json \
  --limit 0.1 --period-hours 24 --payer relayer.json --yes
$Q guardian show "$GV" | grep -q "limit           0.100000000 SOL per 24 h"
solana-keygen new --no-bip39-passphrase --silent -o gdest.json
GD="$(solana-keygen pubkey gdest.json)"
$Q --password-env PW send --key ek.json --vault "$GV" --to "$GD" --amount 0.05 --relayer http://127.0.0.1:8787 --yes
[ "$(bal "$GD")" = 50000000 ] || { echo "instant send missing"; exit 1; }
# Over the limit: a proposal; the guardian approves it offline (unsigned file -> offline sign -> submit).
$Q --password-env PW send --key ek.json --vault "$GV" --to "$GD" --amount 0.2 --payer relayer.json --yes 2>send.log
[ "$(bal "$GD")" = 50000000 ] || { echo "proposal moved funds"; exit 1; }
PROP="$(grep -o 'creates proposal [0-9]*' send.log | awk '{print $3}')"
$Q guardian approve --key gk.json --vault "$GV" --proposal "$PROP" --out approve.json
QSHIELD_RPC_URL=http://127.0.0.1:9 $Q --password-env PW sign approve.json --key gk.json --yes
$Q submit approve.json --relayer http://127.0.0.1:8787
[ "$(bal "$GD")" = 250000000 ] || { echo "approved send missing"; exit 1; }
# The everyday key cannot sign for the guardian, nor use v1.
if $Q --password-env PW guardian unfreeze --key ek.json --vault "$GV" --payer relayer.json --yes 2>/dev/null; then echo "EVERYDAY KEY UNFROZE"; exit 1; fi
if $Q --password-env PW withdraw --key ek.json --vault "$GV" --to "$GD" --amount 0.01 --payer relayer.json --yes 2>/dev/null; then echo "V1 BYPASS"; exit 1; fi
# Freeze with the everyday key, unfreeze with the guardian; save an address, then large sends to it are instant.
$Q --password-env PW guardian freeze --key ek.json --vault "$GV" --payer relayer.json --yes
if $Q --password-env PW send --key ek.json --vault "$GV" --to "$GD" --amount 0.01 --payer relayer.json --yes 2>/dev/null; then echo "SENT WHILE FROZEN"; exit 1; fi
$Q --password-env PW guardian unfreeze --key gk.json --vault "$GV" --payer relayer.json --yes
$Q --password-env PW guardian add-address --key gk.json --vault "$GV" --address "$GD" --payer relayer.json --yes
$Q --password-env PW send --key ek.json --vault "$GV" --to "$GD" --amount 0.15 --payer relayer.json --yes
[ "$(bal "$GD")" = 400000000 ] || { echo "saved-address send missing"; exit 1; }
echo "== TypeScript SDK: vault creation from a browser-style payer, relayed withdrawal, rotation"
if [ -d "$ROOT/sdk/typescript/node_modules" ]; then
  (cd "$ROOT/sdk/typescript" && QSHIELD_E2E_RPC="$RPC" QSHIELD_E2E_PROGRAM="$QSHIELD_PROGRAM_ID" \
    QSHIELD_E2E_RELAYER=http://127.0.0.1:8787 npx vitest run test/e2e.validator.test.ts)
elif [ -n "${CI:-}" ]; then
  echo "sdk/typescript/node_modules missing in CI"; exit 1
else
  echo "(skipped: run npm ci in sdk/typescript)"
fi
echo "== web wallet (Playwright, Chromium): key + verified backup, vault, deposit, relayed send, rotation"
if [ -d "$ROOT/apps/web/node_modules" ]; then
  (cd "$ROOT/apps/web" && QSHIELD_E2E_RPC="$RPC" QSHIELD_E2E_PROGRAM="$QSHIELD_PROGRAM_ID" \
    QSHIELD_E2E_RELAYER=http://127.0.0.1:8787 npx playwright test)
elif [ -n "${CI:-}" ]; then
  echo "apps/web/node_modules missing in CI"; exit 1
else
  echo "(skipped: run npm ci in apps/web)"
fi
echo "== SPL Token: deposit, withdraw inline to a new recipient, offline buffered withdrawal"
WALLET="$(solana-keygen pubkey wallet.json)"
MINT="$(T create-mint wallet.json spl 6 "$WALLET" 10000000)"
$Q deposit-spl --vault "$VAULT" --payer wallet.json --mint "$MINT" --amount 4 --key key.json >/dev/null
VAULT_TA="$(T ata "$VAULT" "$MINT" spl)"
[ "$(T balance "$VAULT_TA" spl)" = 4000000 ] || { echo "vault token balance wrong"; exit 1; }
$Q vault info "$VAULT" >info.txt
grep -q "4.000000 of mint $MINT" info.txt || { echo "vault info lacks tokens"; exit 1; }
$Q --password-env PW withdraw-spl --key key.json --vault "$VAULT" --mint "$MINT" --to "$DEST" --amount 1.5 --payer relayer.json --yes
DEST_TA="$(T ata "$DEST" "$MINT" spl)"
[ "$(T balance "$DEST_TA" spl)" = 1500000 ] || { echo "token destination balance wrong"; exit 1; }
NONCE="$($Q vault info "$VAULT" | awk '/^nonce/ {print $2}')"
QSHIELD_RPC_URL=http://127.0.0.1:9 $Q auth withdraw-spl --vault "$VAULT" --mint "$MINT" --to "$DEST" --amount 0.5 \
  --decimals 6 --token-program spl --nonce "$NONCE" --signer-key-id "$KEYID" --out spl-offline.json
QSHIELD_RPC_URL=http://127.0.0.1:9 $Q --password-env PW sign spl-offline.json --key key.json --yes
$Q submit spl-offline.json --payer relayer.json --transport buffered
[ "$(T balance "$DEST_TA" spl)" = 2000000 ] || { echo "token destination balance wrong after offline flow"; exit 1; }
echo "== Token-2022: deposit and withdraw"
MINT22="$(T create-mint wallet.json token2022 9 "$WALLET" 5000000000)"
$Q deposit-spl --vault "$VAULT" --payer wallet.json --mint "$MINT22" --amount 2.25 >/dev/null
$Q --password-env PW withdraw-spl --key key.json --vault "$VAULT" --mint "$MINT22" --to "$DEST" --amount 2.25 --payer relayer.json --yes --transport buffered
[ "$(T balance "$(T ata "$DEST" "$MINT22" token2022)" token2022)" = 2250000000 ] || { echo "Token-2022 balance wrong"; exit 1; }
echo "== rotate key, then close with the new key"
$Q --password-env PW keygen --out key2.json
$Q --password-env PW rotate-key --key key.json --new-key key2.json --vault "$VAULT" --payer wallet.json --yes
if $Q --password-env PW withdraw --key key.json --vault "$VAULT" --to "$DEST" --amount 0.001 --payer relayer.json --yes 2>/dev/null; then
  echo "OLD KEY ACCEPTED"; exit 1; fi
echo "== close is refused while the vault holds tokens"
if $Q --password-env PW auth close --vault "$VAULT" --to "$DEST" --key key2.json --out close.json 2>/dev/null; then
  echo "CLOSE WITH TOKENS ALLOWED"; exit 1; fi
$Q --password-env PW withdraw-spl --key key2.json --vault "$VAULT" --mint "$MINT" --to "$DEST" --amount 2 --payer relayer.json --yes
$Q --password-env PW auth close --vault "$VAULT" --to "$DEST" --key key2.json --out close.json
$Q --password-env PW sign close.json --key key2.json --yes
$Q submit close.json --payer relayer.json
$Q vault info "$VAULT" >info.txt
grep -q "Closed" info.txt
echo "CLI end-to-end: OK"
