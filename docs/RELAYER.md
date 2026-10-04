# QShield relayer

`services/relayer` (`qshield-relayer`) is a small, self-hostable HTTP service
that submits **signed** QShield authorizations to Solana and pays the
transaction fees. It exists so a user who holds only a post-quantum key (and
no SOL in a hot wallet) can still get a withdrawal on chain.

**A relayer is untrusted by design** (ADR-0010, ADR-0016):

* it never sees or stores a PQ private key — it receives only the signed
  envelope (authorization bytes, signature, public key, hints), all public;
* it has no custody of user funds and no authority over any vault;
* it cannot alter a signed authorization: every field is covered by the
  ML-DSA signature, and the program checks every account against it
  (invariants I4/I5, `docs/SECURITY_MODEL.md`);
* it **can** refuse, delay or reorder requests. Users can always submit
  themselves (`qshield submit --payer …`) or use another relayer; the
  protocol has no dependency on any relayer.

## API

All bodies are JSON. Every response carries `Access-Control-Allow-Origin: *`
(browser wallets may call it directly) and `Cache-Control: no-store`.

### `POST /v1/submit`

```json
{ "envelope": { …signed authorization file… }, "transport": "inline" }
```

`envelope` is exactly the file produced by `qshield sign` / `signEnvelope`
(`docs/OFFLINE_SIGNING.md`). `transport` is `inline` (default; one v1
transaction, SIMD-0385) or `buffered` (5 legacy transactions; the relayer
temporarily funds a ≈ 0.018 SOL signature buffer, refunded on use).

Checks before accepting (no chain access, nothing spent):

1. body ≤ 32 KiB, per-client rate limit;
2. the envelope is well formed, its displayed fields equal the rendering of
   its bytes, and its signature verifies under the embedded public key whose
   key id is `signer_key_id`;
3. cluster and program match the relayer's;
4. fee policy (below);
5. not a duplicate of a pending/confirmed request, and no other request for
   the same vault is in progress (nonces are sequential).

Responses:

| Code | Body | Meaning |
|-----:|------|---------|
| 202 | `{"request_id", "status": "pending"}` | Queued |
| 200 | status object with `"duplicate": true` | Same authorization already pending/confirmed |
| 400 | `{"error"}` | Malformed, unsigned, inconsistent, wrong cluster/program, bad transport |
| 402 | `{"error"}` | Fee below this relayer's minimum, or payable to someone else |
| 409 | `{"error"}` | Another request for this vault is in progress |
| 413 | `{"error"}` | Body too large |
| 429 | `{"error"}` | Rate limited |
| 503 | `{"error"}` | Queue full |

The submission worker then re-checks against the chain — vault nonce, the
ML-DSA signature against the vault's **current on-chain key**, and for
WithdrawSpl the mint policy, decimals and balances — before sending anything,
and the RPC node simulates each transaction (preflight) before broadcast. An
authorization that would fail costs the relayer nothing.

`request_id` is the hex SHA-256 of the 292 authorization bytes.

### `GET /v1/status/{request_id}`

```json
{"request_id": "…", "status": "pending" | "submitting"}
{"request_id": "…", "status": "confirmed", "signatures": ["…"]}
{"request_id": "…", "status": "failed", "error": "…"}
```

`404` if unknown (records are kept in memory, newest 10,000).

### `GET /v1/info`

Relayer address, program id, cluster, `min_fee_lamports`,
`token_account_rent_lamports` (`spl_token`, `token_2022`),
`max_proposal_lifetime_secs`, accepted transports, rate limit.

### `GET /health`

`{"ok": true, "relayer", "fee_payer_balance_lamports", "pending", "submitted", "failed"}`.

## Fees and gas sponsorship

The relayer always pays Solana fees from its own key. Whether it charges the
user is a policy choice (`--min-fee-lamports`):

* `0` (default): fully sponsored; any signed fee is still honoured.
* `N > 0`: the authorization must carry `fee_lamports ≥ N` payable to the fee
  payer — `fee_recipient` zero ("whoever pays the transaction fee") or this
  relayer's address. Clients read both values from `/v1/info` before signing.

**Rent the relayer would lose.** A token withdrawal (v1/v2 WithdrawSpl, v2
ApproveWithdraw) to a recipient whose associated token account does not
exist makes the fee payer create that account, and the rent goes to the
recipient for good. Such a request must carry `fee_lamports ≥ min_fee +
rent`, payable to the relayer (`token_account_rent_lamports` in `/v1/info`);
otherwise it fails before anything is sent. Create the account first, or
submit yourself, to avoid paying it. A v2 ProposeWithdraw creates a proposal
account whose rent returns to the relayer only when the proposal is
approved, cancelled or closed after expiry, so proposals must expire within
`--max-proposal-hours` (default 168); `expires_at = 0` is refused.

Fees are always part of the signed authorization; a relayer can never take an
unsigned or larger fee (ADR-0010). Token withdrawals pay relayer fees in SOL
from the vault (ADR-0015).

## Abuse protection

| Risk | Mitigation |
|------|------------|
| Request floods | Per-IP rate limit (`--rate-limit`, per minute), bounded queue (`--max-queue`, 503 when full), 32 KiB body cap |
| Making the relayer pay for failing transactions | Full local verification against chain state before sending; RPC preflight simulation |
| Rent farming (token accounts the relayer creates, then the attacker closes) | The signed fee must cover the rent of any account the relayer would create |
| Proposals that lock the relayer's rent forever | Proposals must expire within `--max-proposal-hours` |
| Valid-but-worthless spam (attacker's own vaults) | `--min-fee-lamports`; rate limits. With fee 0 each request still costs the attacker a valid ML-DSA signature over a vault they funded |
| Duplicate submissions | Request id = hash of the authorization; duplicates return the existing status |
| Racing nonces | One in-flight request per vault (409) |
| Draining the fee-payer key | Keep only working capital in it; monitor `/health` |

Behind a reverse proxy, pass `--trust-proxy` so the rate limit uses the
address the proxy appends to `X-Forwarded-For` — only if the relayer is not
reachable except through that proxy.

## Self-hosting

```bash
cargo build --release -p qshield-relayer
solana-keygen new -o relayer.json            # the relayer's fee-payer key
solana transfer $(solana-keygen pubkey relayer.json) 1 …   # fund it

./target/release/qshield-relayer \
  --url https://api.devnet.solana.com \
  --program-id <QSHIELD PROGRAM ID> --cluster devnet \
  --keypair relayer.json \
  --bind 127.0.0.1:8787 \
  --min-fee-lamports 0 --rate-limit 30
```

Every option also reads an environment variable (`QSHIELD_RPC_URL`,
`QSHIELD_PROGRAM_ID`, `QSHIELD_CLUSTER`, `QSHIELD_RELAYER_KEYPAIR`,
`QSHIELD_RELAYER_BIND`, `QSHIELD_RELAYER_MIN_FEE`). The relayer refuses to
start if the RPC endpoint serves a different cluster than `--cluster`.

Example systemd unit:

```ini
[Unit]
Description=QShield relayer
After=network-online.target

[Service]
ExecStart=/usr/local/bin/qshield-relayer --bind 127.0.0.1:8787 --trust-proxy
Environment=QSHIELD_RPC_URL=https://api.devnet.solana.com
Environment=QSHIELD_PROGRAM_ID=<program id>
Environment=QSHIELD_CLUSTER=devnet
Environment=QSHIELD_RELAYER_KEYPAIR=/var/lib/qshield-relayer/relayer.json
DynamicUser=yes
StateDirectory=qshield-relayer
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Terminate TLS in a reverse proxy (nginx, Caddy) in front of it. Logs contain
only public data. State (request records) is in memory; restarting loses
status history but nothing else — vault state lives on chain.

## Using a relayer

* CLI: `qshield submit signed.json --relayer https://relayer.example`
  (or `QSHIELD_RELAYER_URL`).
* Rust: `qshield_client::relayer::RelayerClient`.
* TypeScript: `new RelayerClient(url).submit(signedEnvelope)` then `.wait(id)`.

Before signing for a particular relayer, read its `/v1/info` and include the
fee it requires; set `expires_at` (default one hour) so an authorization a
relayer sits on dies.
