# Offline signing and the authorization envelope

QShield authorizations can be built on an online machine, signed on an
air-gapped machine that holds the PQ key, and submitted by anyone. The file
that moves between them is the **authorization envelope**, implemented by the
Rust SDK/CLI (`crates/qshield-client/src/envelope.rs`) and the TypeScript SDK
(`sdk/typescript/src/envelope.ts`), and checked across both by
`tests/vectors/sdk/interop-v1.json`.

## Workflow with the CLI

```
online machine                     offline machine                    any machine
──────────────                     ───────────────                    ───────────
qshield auth withdraw-sol \        qshield sign auth.json \           qshield submit auth.json \
  --vault V --to D --amount 0.5 \     --key key.json                    --payer relayer.json
  --key key.json --out auth.json    (shows every field, asks y/N)      (verifies first; pays fees)
        (reads nonce from chain)
```

Fully offline construction (no RPC at all) is possible when the nonce and the
expected signer are known:

```bash
qshield --program-id P --cluster devnet auth withdraw-sol --vault V --to D --amount 0.5 \
  --nonce 7 --signer-key-id <hex> --out auth.json
```

`qshield verify auth.json` checks a file anywhere, offline.

## Envelope format (v1)

```json
{
  "qshield_authorization": 1,
  "fields": { "action": "WithdrawSol", "amount": "0.500000000 SOL", "...": "..." },
  "auth_hex": "<292 bytes of QSP-1, hex>",
  "signer_key_id": "<hex>",
  "signature_hex": "<2420 bytes, hex; absent until signed>",
  "public_key_hex": "<1312 bytes, hex; absent until signed>",
  "hints": { "new_key_account": "<base58; RotateKey only>" }
}
```

Rules (all implementations MUST enforce them when loading a file):

1. `auth_hex` is authoritative. It must decode as canonical QSP-1.
2. `fields` must equal the rendering computed from `auth_hex` **exactly** (same
   keys, same strings). A file cannot display one thing and sign another.
   Signers must show the rendering they compute themselves, never the file's.
3. If `signature_hex` is present: `public_key_hex` must be present, its key id
   must equal `signer_key_id`, and the signature must verify (ML-DSA-44, pure,
   context `QSHIELD/QSP-1`) over `auth_hex`.
4. `hints` are not signed. They only help submission; the program re-checks
   everything that matters (e.g. the new key account's key id must equal the
   signed `new_key_id`).

### Rendering

| Field | Rendering |
|-------|-----------|
| cluster | `mainnet-beta`, `devnet`, `testnet`, `localnet`, or `unknown(<hex>)` |
| program_id, vault, destination, mint, fee_recipient | base58 |
| action | `WithdrawSol`, `WithdrawSpl`, `RotateKey`, `Pause`, `Unpause`, `CloseVault` |
| nonce | decimal |
| valid_after | `immediately` or `<n> (unix seconds)` |
| expires_at | `never` or `<n> (unix seconds)` |
| amount (SOL) | `<int>.<9 digits> SOL` |
| amount (CloseVault) | `entire balance above the rent reserve` |
| amount (SPL) | `<int>.<decimals digits> (<n> base units, decimals <d>)` (no `.` when decimals = 0), plus `asset` = `SplToken`/`Token2022`, `mint` |
| new_key_id / new_algorithm | hex / `ML-DSA-44` |
| fee | `<int>.<9 digits> SOL` |
| fee_recipient | only when fee > 0: base58 or `transaction fee payer` |

Fields that do not apply to an action are omitted.

## What the offline machine needs

Only the key file, its password, and the authorization file. It never needs
network access, a Solana wallet, or the program binary. `qshield-client` can
be built with `--no-default-features` to exclude the HTTP client entirely; a
dedicated offline-signer binary built that way is future work (the current
CLI includes the HTTP client but `sign` and `verify` never use it).

## Future transports

QR codes and USB devices can carry the same envelope (≈ 9 KB as JSON once
signed; a binary encoding can be defined later without changing QSP-1).
