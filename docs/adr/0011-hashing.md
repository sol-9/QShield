# ADR-0011: Hashing — SHAKE inside ML-DSA, SHA-256 for key ids

Status: Accepted (2026-10-02)

## Context
Hashes are needed inside ML-DSA (mandated by FIPS 204) and for key identifiers.

## Options considered
For key ids: SHAKE256, SHA-256 (Solana syscall), Keccak-256 (Solana syscall), raw public key.

## Decision
ML-DSA uses exactly FIPS 204's SHAKE128/SHAKE256 — never substituted.
Key ids: `SHA-256("QSHIELD_KEY_ID_V1" ‖ alg ‖ pk)` using the `sol_sha256` syscall.
QSP-1 is signed with pure ML-DSA; no pre-hash.

## Security implications
Key ids need second-preimage resistance against keys the attacker does not
control (≥ 2^128 classically, ~2^128 / Grover-limited quantumly) and are domain-separated.

## Tradeoffs
Two hash families in the codebase, but each used where standard or cheapest.

## Alternatives rejected
SHAKE256 key ids: ≈ 130k CU in software vs. a cheap syscall. Raw public key as
id: 1,312 bytes in PDA seeds/state is impractical.
