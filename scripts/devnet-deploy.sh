#!/usr/bin/env bash
# Deploys (or upgrades) the QShield vault program on devnet and funds the relayer.
#
#   scripts/devnet-deploy.sh            build, check balances, deploy
#   AIRDROP=1 scripts/devnet-deploy.sh  also try the devnet faucet for the authority
#
# Upgrading an existing program (keys kept where they are):
#   AUTHORITY_KEYPAIR=~/.config/solana/qshield-devnet/deployer.json \
#   PROGRAM_ID=3X4xqLweQD692RDR2dpHA52bsWici14f8T9qNZYPvhi1 scripts/devnet-deploy.sh
#
# Keys default to deploy-keys/devnet/ (git-ignored; back them up):
#   authority.json  pays for the deploy and is the program's UPGRADE AUTHORITY
#   program.json    the program address (first deploy only; unused with PROGRAM_ID)
#   relayer.json    the relayer's fee payer (goes to Fly as a secret)
# The public result is written to deploy/devnet.json.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KEYS="$ROOT/deploy-keys/devnet"
URL="${DEVNET_RPC:-https://api.devnet.solana.com}"
MIN_AUTHORITY_SOL="${MIN_AUTHORITY_SOL:-3}"
RELAYER_FUND_SOL="${RELAYER_FUND_SOL:-1}"
SO="$ROOT/target/devnet/qshield_vault.so"

mkdir -p "$KEYS"
chmod 700 "$ROOT/deploy-keys" "$KEYS"
AUTH_KEY="${AUTHORITY_KEYPAIR:-$KEYS/authority.json}"
RELAYER_KEY="${RELAYER_KEYPAIR:-$KEYS/relayer.json}"
new_key() {
  if [ ! -f "$1" ]; then
    solana-keygen new --no-bip39-passphrase --silent -o "$1"
    chmod 600 "$1"
    echo "created $1"
  fi
}
new_key "$AUTH_KEY"
new_key "$RELAYER_KEY"
if [ -n "${PROGRAM_ID:-}" ]; then
  PROGRAM="$PROGRAM_ID"
  PROGRAM_ARG="$PROGRAM_ID"
else
  new_key "$KEYS/program.json"
  PROGRAM="$(solana-keygen pubkey "$KEYS/program.json")"
  PROGRAM_ARG="$KEYS/program.json"
fi
AUTHORITY="$(solana-keygen pubkey "$AUTH_KEY")"
RELAYER="$(solana-keygen pubkey "$RELAYER_KEY")"
echo "upgrade authority $AUTHORITY"
echo "program id        $PROGRAM"
echo "relayer payer     $RELAYER"

[ "$(solana genesis-hash -u "$URL")" = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" ] || { echo "RPC $URL is not devnet"; exit 1; }

echo "== build (cluster-devnet, SBPF v3)"
# Separate output directory: target/deploy keeps the localnet build the tests use.
cargo build-sbf --arch v3 --features cluster-devnet --manifest-path "$ROOT/programs/qshield-vault/Cargo.toml" \
  --sbf-out-dir "$(dirname "$SO")" -- --locked
SHA="$(sha256sum "$SO" | cut -d' ' -f1)"
echo "binary sha256 $SHA"

sol() { solana balance -u "$URL" --lamports "$1" | cut -d' ' -f1; }
if [ "${AIRDROP:-0}" = 1 ]; then
  for _ in 1 2; do solana airdrop -u "$URL" 2 "$AUTHORITY" || true; done
fi
NEED=$(( MIN_AUTHORITY_SOL * 1000000000 ))
HAVE="$(sol "$AUTHORITY")"
if [ "$HAVE" -lt "$NEED" ]; then
  echo
  echo "The upgrade authority holds $(( HAVE / 1000000 ))e-3 SOL; the deploy needs about $MIN_AUTHORITY_SOL devnet SOL."
  echo "Fund it at https://faucet.solana.com (address: $AUTHORITY), or rerun with AIRDROP=1."
  exit 2
fi

# An upgrade needs room for the new binary: extend the program data first.
SIZE="$(stat -c %s "$SO")"
CURRENT="$(solana program show -u "$URL" --keypair "$AUTH_KEY" "$PROGRAM" 2>/dev/null | awk '/Data Length/ {print $3}' || true)"
if [ -n "$CURRENT" ] && [ "$SIZE" -gt "$CURRENT" ]; then
  echo "== extend program data by $(( SIZE - CURRENT )) bytes"
  solana program extend -u "$URL" --keypair "$AUTH_KEY" "$PROGRAM" "$(( SIZE - CURRENT ))"
fi

echo "== deploy"
solana program deploy -u "$URL" \
  --keypair "$AUTH_KEY" \
  --upgrade-authority "$AUTH_KEY" \
  --program-id "$PROGRAM_ARG" \
  --max-sign-attempts 60 \
  ${USE_TPU:+--use-tpu-client} \
  "$SO"
solana program show -u "$URL" --keypair "$AUTH_KEY" "$PROGRAM"
echo "== verify: on-chain bytes equal the build"
solana program dump -u "$URL" --keypair "$AUTH_KEY" "$PROGRAM" "$ROOT/target/devnet/onchain.so" >/dev/null
python3 - "$SO" "$ROOT/target/devnet/onchain.so" <<'PY'
import sys
built, chain = (open(p, 'rb').read() for p in sys.argv[1:])
# Program data is zero-padded to its allocated size.
assert chain[:len(built)] == built and not chain[len(built):].strip(b'\0'), 'on-chain program differs from the build'
print('on-chain program matches the build byte for byte')
PY

if [ "$(sol "$RELAYER")" -lt 500000000 ]; then
  echo "== fund relayer with $RELAYER_FUND_SOL SOL"
  solana transfer -u "$URL" --keypair "$AUTH_KEY" --allow-unfunded-recipient "$RELAYER" "$RELAYER_FUND_SOL"
fi

cat > "$ROOT/deploy/devnet.json" <<EOF
{
  "cluster": "devnet",
  "program_id": "$PROGRAM",
  "upgrade_authority": "$AUTHORITY",
  "relayer_fee_payer": "$RELAYER",
  "binary_sha256": "$SHA",
  "source_commit": "$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)",
  "agave": "$(cargo-build-sbf --version | head -1)",
  "deployed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
sed -i "s/^  QSHIELD_PROGRAM_ID = .*/  QSHIELD_PROGRAM_ID = \"$PROGRAM\"/" "$ROOT/fly.toml"
echo
echo "Done. Recorded in deploy/devnet.json; fly.toml now points at $PROGRAM."
echo "Back up $AUTH_KEY somewhere safe: it controls upgrades."
