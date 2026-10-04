#!/usr/bin/env bash
# Deploys (or upgrades) the QShield vault program on devnet and funds the relayer.
#
#   scripts/devnet-deploy.sh            build, check balances, deploy
#   AIRDROP=1 scripts/devnet-deploy.sh  also try the devnet faucet for the authority
#
# Keys live in deploy-keys/devnet/ (git-ignored; back them up):
#   authority.json  pays for the deploy and is the program's UPGRADE AUTHORITY
#   program.json    the program address (needed only for the first deploy)
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
for k in authority program relayer; do
  if [ ! -f "$KEYS/$k.json" ]; then
    solana-keygen new --no-bip39-passphrase --silent -o "$KEYS/$k.json"
    chmod 600 "$KEYS/$k.json"
    echo "created $KEYS/$k.json"
  fi
done
AUTHORITY="$(solana-keygen pubkey "$KEYS/authority.json")"
PROGRAM="$(solana-keygen pubkey "$KEYS/program.json")"
RELAYER="$(solana-keygen pubkey "$KEYS/relayer.json")"
echo "upgrade authority $AUTHORITY"
echo "program id        $PROGRAM"
echo "relayer payer     $RELAYER"

[ "$(solana genesis-hash -u "$URL")" = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG" ] || { echo "RPC $URL is not devnet"; exit 1; }

echo "== build (cluster-devnet, SBPF v3)"
cargo build-sbf --arch v3 --features cluster-devnet --manifest-path "$ROOT/programs/qshield-vault/Cargo.toml" -- --locked
mkdir -p "$(dirname "$SO")"
cp "$ROOT/target/deploy/qshield_vault.so" "$SO"
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

echo "== deploy"
solana program deploy -u "$URL" \
  --keypair "$KEYS/authority.json" \
  --upgrade-authority "$KEYS/authority.json" \
  --program-id "$KEYS/program.json" \
  --max-sign-attempts 60 \
  "$SO"
solana program show -u "$URL" "$PROGRAM"

if [ "$(sol "$RELAYER")" -lt 500000000 ]; then
  echo "== fund relayer with $RELAYER_FUND_SOL SOL"
  solana transfer -u "$URL" --keypair "$KEYS/authority.json" --allow-unfunded-recipient "$RELAYER" "$RELAYER_FUND_SOL"
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
echo "Back up deploy-keys/devnet/ somewhere safe: authority.json controls upgrades."
