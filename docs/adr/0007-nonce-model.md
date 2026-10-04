# ADR-0007: Nonce model — sequential u64, tombstoned vaults

Status: Accepted (2026-10-02)

## Context
Every authorization must be single-use; signatures must not become valid again
after a vault is closed and re-created.

## Options considered
1. Sequential u64 nonce per vault.
2. Bitmap / unordered nonces.
3. Hash of executed authorizations stored on-chain.

## Decision
Option 1, consumed on success. Closed vaults are not deleted: they remain as
tombstones (status Closed, nonce preserved), so their address can never be
re-initialized and old authorizations never revive.

## Security implications
Replay is impossible within a vault (nonce), across vaults (vault field), and
across close/re-create (tombstone). Cancellation: execute another authorization
for the same nonce.

## Tradeoffs
No concurrency per vault; ≈ 0.0027 SOL rent locked forever per closed vault.

## Alternatives rejected
Unordered nonces add state and complexity not needed for v1. Storing hashes
grows without bound.
