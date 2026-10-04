# ADR-0001: Signature scheme — pure ML-DSA-44

Status: Accepted (2026-10-02)

## Context
Vault authorization must rely on a standardized post-quantum signature that can
be verified inside a Solana program (1.4M CU, 4 KiB stack frames, 32 KiB default
heap) and carried in Solana transactions (1,232 bytes legacy, 4,096 bytes v1).

## Options considered
1. ML-DSA-44 (FIPS 204, category 2): pk 1,312 B, sig 2,420 B.
2. ML-DSA-65 (category 3): pk 1,952 B, sig 3,309 B.
3. SLH-DSA (FIPS 205): small keys, signatures 7.8–49 KB, very hash-heavy verification.
4. FN-DSA / Falcon: small signatures, standard not final, floating-point signing.
5. Hybrid Ed25519 + ML-DSA.

## Decision
ML-DSA-44, pure mode (not HashML-DSA), FIPS 204 context string `QSHIELD/QSP-1`.
Algorithm id `1` in QSP-1, leaving room for others.

## Security implications
Security rests on ML-DSA-44 (Module-LWE/SIS) at NIST category 2. No classical
fallback: a break of ML-DSA breaks QShield authorization.

## Tradeoffs
Smallest standardized lattice scheme, fits v1 transactions with margin (3,010 B
withdrawal). Category 2 rather than 3/5.

## Alternatives rejected
ML-DSA-65: withdrawal tx ≈ 3.9 KB, close to the cap, more CU — candidate for a
later algorithm id. SLH-DSA: signatures do not fit any transaction; hash cost
prohibitive without a SHAKE syscall. Falcon: not yet standardized (FIPS 206
pending). Hybrid with Ed25519: adds nothing against the quantum threat model and
re-introduces the Ed25519 key as a required secret.
