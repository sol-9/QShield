# Devnet deployment

Experimental, unaudited, devnet only. Machine-readable record:
[`deploy/devnet.json`](../deploy/devnet.json).

| Field | Value |
|---|---|
| Program | `3X4xqLweQD692RDR2dpHA52bsWici14f8T9qNZYPvhi1` |
| Upgrade authority | `A6JKGNVJ8T8TmLMqkuGeCgVnfGTaori1aoAz8e7KvDug` |
| Program data | `6WUaZuKZ4iWP4hcZLJQ4kusecXKfd7xTYQhuyr2Dib77` |
| Relayer fee payer | `F33apaQghaqrCfbGjgDSwzWjRC9pYN1a2HcnBPGAQb2C` |
| Genesis hash | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |

[View program](https://explorer.solana.com/address/3X4xqLweQD692RDR2dpHA52bsWici14f8T9qNZYPvhi1?cluster=devnet)

The holder of upgrade authority `A6JKGNVJ8T8TmLMqkuGeCgVnfGTaori1aoAz8e7KvDug`
can replace this program and take all funds. The program remains upgradeable.

## History

| Date | Slot | Source | Binary SHA-256 | Notes |
|---|---|---|---|---|
| 2026-10-02 | 506667156 | no git metadata | `3b7deebd…ee3ef4d1` (139,672 bytes) | First deploy. Smoke test: create, inline and buffered withdrawals, replay refused, close. |
| 2026-10-04 | 507386520 | `95416ca` | `da1d8a60…ae26458e` (139,760 bytes) | Upgrade with the review fixes: guardian fees count against the allowance; a frozen vault pays no everyday-key fees. Program data extended by 10,240 bytes (SIMD-0431 minimum). On-chain bytes compared with the build: identical. |

### 2026-10-04 smoke test (live devnet, CLI)

Vault `93iiAXLR36S1WTTP58yspyLP3dnVpDxkb7TcGj6dwUd`: created (7 transactions),
deposited 0.02 SOL, withdrew 0.005 SOL with one inline v1 ML-DSA
authorization (nonce 0 → 1, 0.015 SOL left), then closed (status Closed,
nonce 2; withdrawable SOL and key-account rent returned to the deployer).

The public RPC answered `429 Too Many Requests` during the first attempt.
Both RPC clients (Rust `JsonRpc`, TypeScript `JsonRpc`) now retry 429 and 5xx
responses with exponential backoff (about 30 s); the second attempt passed.
The interrupted attempt left one unfinished key account behind (devnet rent
only).

## Build and verification

```bash
AUTHORITY_KEYPAIR=~/.config/solana/qshield-devnet/deployer.json \
PROGRAM_ID=3X4xqLweQD692RDR2dpHA52bsWici14f8T9qNZYPvhi1 \
scripts/devnet-deploy.sh
```

The script builds with `--features cluster-devnet` into `target/devnet/`,
checks the RPC's genesis hash, extends the program data if needed, upgrades,
dumps the on-chain program and compares it byte for byte with the build, funds
the relayer, and rewrites `deploy/devnet.json`. Toolchain: Rust 1.97.1,
Agave 4.3.0, platform-tools v1.57.

Deployment keys stay outside the repository: the deployer (upgrade authority)
in `~/.config/solana/qshield-devnet/` and the relayer fee payer in
`deploy-keys/devnet/` (git-ignored, mode 0600). Back both up when moving
machines.

## CLI configuration

```bash
export QSHIELD_RPC_URL=https://api.devnet.solana.com
export QSHIELD_CLUSTER=devnet
export QSHIELD_PROGRAM_ID=3X4xqLweQD692RDR2dpHA52bsWici14f8T9qNZYPvhi1
```

The public RPC rate-limits; for heavier use, set `QSHIELD_RPC_URL` to a
dedicated devnet endpoint.
