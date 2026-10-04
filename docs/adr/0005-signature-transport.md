# ADR-0005: Signature transport — v1 inline, buffer fallback

Status: Accepted (2026-10-02)

## Context
Signature 2,420 B; QSP-1 authorization 292 B; legacy/v0 transactions 1,232 B;
v1 transactions (SIMD-0385) 4,096 B. `enable_tx_v1` is in Agave 4.3 and listed as
active on mainnet in LiteSVM 0.17's mainnet snapshot (to be verified per cluster).

## Options considered
1. v1 transactions only.
2. Buffer accounts only.
3. Both: inline for v1, buffer for legacy/v0.

## Decision
Option 3. `Execute` carries `auth ‖ signature` (3,010-byte v1 transaction).
`CreateSigBuffer` / `WriteSigBuffer` / `ExecuteWithBuffer` use a PDA
`["sigbuf", vault, creator, id]` that only its creator can write, that is
immutable after finalize, bound to one vault, and closed on use.

## Security implications
The buffer holds only the signature (public); the authorization bytes are in the
execute instruction and are what the signature is checked against. Tested
attacks: chunk replacement, post-finalize writes, foreign buffers, refund theft.

## Tradeoffs
Two code paths; legacy needs 5 transactions and temporary rent.

## Alternatives rejected
v1-only would exclude clusters/clients without SIMD-0385. Buffer-only would make
every withdrawal 5 transactions even where 1 suffices.
