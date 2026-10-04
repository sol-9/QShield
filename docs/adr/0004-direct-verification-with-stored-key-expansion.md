# ADR-0004: Architecture A with on-chain key expansion

Status: Accepted (2026-10-02)

## Context
Phase 0 measured ML-DSA-44 verification under SBF
(`docs/MLDSA_SOLANA_FEASIBILITY.md`): ≈ 2.30M CU when `A_hat`, `NTT(t1·2^d)` and
`tr` are recomputed (exceeds the 1.4M cap); ≈ 828k CU when they are
precomputed. Each Keccak-f permutation costs ~12–15k CU and `ExpandA` needs ~80.

## Options considered
A. Direct on-chain verification (recompute everything) — does not fit.
A'. Direct on-chain verification against a stored expansion.
B. Split one verification across several transactions with an on-chain state machine.
C. Off-chain verification + succinct proof verified on-chain.

## Decision
A'. The program expands each key once (FinalizeKey + ExpandKey, ≈ 1.56M CU over
3 transactions), stores it in an immutable key account, and verifies each
authorization against it in a single instruction.

## Security implications
The expansion is a deterministic function of the public key; it is produced only
by the program, only from bytes that hash to the key id, and frozen when Ready.
Integrity of the key account is therefore part of the trusted state (invariant
I7). No change to what is verified.

## Tradeoffs
≈ 0.154 SOL rent per key (refundable). One-time setup of 6 transactions per key.
~570k CU headroom left per transaction.

## Alternatives rejected
B: complex multi-transaction state with partial-verification state to protect.
C: trusted setup or large proofs, a prover service, much more code; unnecessary
given A' fits with a 40 % margin.
