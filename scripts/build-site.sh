#!/usr/bin/env bash
# Builds the public site for Cloudflare Pages into site/:
#   /       landing page (apps/landing)
#   /app/   web wallet, with network settings pinned at build time
#
#   RELAYER_URL=https://qshield-relayer-devnet.fly.dev scripts/build-site.sh
#
# Reads deploy/devnet.json (written by scripts/devnet-deploy.sh).
# Optional: RPC_URL (default: public devnet RPC), REPO_URL (footer source link; omitted when unset).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/site"
DEPLOY="$ROOT/deploy/devnet.json"
: "${RELAYER_URL:?set RELAYER_URL to the public relayer, e.g. https://qshield-relayer-devnet.fly.dev}"
RPC_URL="${RPC_URL:-https://api.devnet.solana.com}"
REPO_URL="${REPO_URL:-}"
[ -f "$DEPLOY" ] || { echo "missing $DEPLOY: run scripts/devnet-deploy.sh first"; exit 1; }
field() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$DEPLOY" "$1"; }
PROGRAM="$(field program_id)"
AUTHORITY="$(field upgrade_authority)"
case "$RELAYER_URL$RPC_URL" in *http://*) echo "RELAYER_URL and RPC_URL must be https"; exit 1 ;; esac
origin() { python3 -c "import sys,urllib.parse as u; p=u.urlsplit(sys.argv[1]); print(f'{p.scheme}://{p.netloc}')" "$1"; }

rm -rf "$OUT"
mkdir -p "$OUT"

echo "== wallet (/app/), pinned to devnet program $PROGRAM"
(
  cd "$ROOT/apps/web"
  [ -d node_modules ] || npm ci --no-audit --no-fund
  VITE_QSHIELD_PROGRAM_ID="$PROGRAM" VITE_QSHIELD_CLUSTER=devnet VITE_QSHIELD_RPC_URL="$RPC_URL" VITE_QSHIELD_RELAYER_URL="$RELAYER_URL" \
    npx vite build --base /app/ --outDir "$OUT/app" --emptyOutDir
)

echo "== landing (/)"
python3 - "$ROOT/apps/landing" "$OUT" "$PROGRAM" "$AUTHORITY" "$REPO_URL" <<'EOF'
import sys, pathlib
src, out, program, authority, repo = sys.argv[1:]
html = pathlib.Path(src, 'index.html').read_text()
if not repo:
    html = '\n'.join(l for l in html.split('\n') if '{{REPO_URL}}' not in l)
for k, v in {'{{PROGRAM_ID}}': program, '{{UPGRADE_AUTHORITY}}': authority, '{{REPO_URL}}': repo, '{{CLUSTER}}': 'devnet'}.items():
    html = html.replace(k, v)
assert '{{' not in html, 'unfilled placeholder'
pathlib.Path(out, 'index.html').write_text(html)
pathlib.Path(out, 'landing.css').write_text(pathlib.Path(src, 'landing.css').read_text())
EOF

# Security headers. The wallet's <meta> CSP cannot set frame-ancestors, so the
# headers carry it, and restrict network access to the pinned RPC and relayer.
# Each CSP is scoped to its own paths: Pages applies every matching rule, and
# two CSP headers on one response are both enforced.
LANDING_CSP="default-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
cat > "$OUT/_headers" <<EOF
/*
  X-Frame-Options: DENY
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Strict-Transport-Security: max-age=31536000; includeSubDomains

/
  Content-Security-Policy: $LANDING_CSP

/index.html
  Content-Security-Policy: $LANDING_CSP

/app/*
  Content-Security-Policy: default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self' $(origin "$RPC_URL") $(origin "$RELAYER_URL"); object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'
EOF

echo
echo "Site ready in $OUT. Deploy with: npx wrangler deploy"
