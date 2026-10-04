# Cryptography

QShield uses no novel cryptography. This document lists every primitive, where
it is used, and why.

## 1. Primitives

| Primitive | Standard | Used for | Implementation |
|-----------|----------|----------|----------------|
| ML-DSA-44 (pure) | NIST FIPS 204 (Aug 2024) | Authorizing every state change of a vault | Verify: `crates/qshield-mldsa` (on-chain and off-chain). Sign/keygen (tests, vectors): `fips204 0.4.6`. |
| SHAKE128 / SHAKE256 | FIPS 202 | Inside ML-DSA only (ExpandA, H, tr, mu, SampleInBall, c̃) | RustCrypto `sha3 0.10.8` (pinned) |
| SHA-256 | FIPS 180-4 | Key identifiers (`key_id`) | `sol_sha256` syscall on-chain; RustCrypto `sha2` off-chain |
| Ed25519 | RFC 8032 | Solana transaction signatures only — never vault authorization | Solana runtime |

## 2. ML-DSA parameter set

ML-DSA-44 (NIST security category 2): public key 1,312 bytes, signature 2,420
bytes, secret key 2,560 bytes. Chosen because it is the smallest standardized
parameter set and the benchmark shows it fits comfortably
(`docs/MLDSA_SOLANA_FEASIBILITY.md`). ML-DSA-65 (category 3) has 1,952-byte keys
and 3,309-byte signatures: a v1 withdrawal would be ≈ 3.9 KB (close to the
4,096-byte cap) and verification more expensive (k×l = 30 instead of 16
polynomial products). It is a candidate for a future algorithm id, not v0.1.

## 3. Pure ML-DSA vs HashML-DSA

FIPS 204 defines *ML-DSA* (signs the message, prefixed by a domain byte and the
context) and *HashML-DSA* (signs a pre-hash of the message with an algorithm
OID). QSP-1 uses **pure ML-DSA**:

* the message is a short (292-byte) fixed-format authorization, so pre-hashing
  brings no benefit;
* pure ML-DSA's message representative `mu = SHAKE256(tr ‖ 0 ‖ |ctx| ‖ ctx ‖ M)`
  already binds the public key;
* it avoids introducing a second hash function into the signed path.

The verifier does not implement HashML-DSA at all, so a HashML-DSA signature
can never be accepted.

## 4. Context string and domain separation

`ctx = "QSHIELD/QSP-1"` (FIPS 204 context, ≤ 255 bytes) separates QShield
signatures from any other use of the same ML-DSA key, at the signature level.
In addition the authorization starts with the 22-byte tag
`QSHIELD_SOLANA_AUTH_V1` and a version number, and commits to cluster,
program, vault and action (QSP-1 §9).

## 5. The `qshield-mldsa` verifier

Why it exists: existing Rust ML-DSA crates exceed the SBF 4 KiB stack-frame
limit (`fips204 0.4.6`: 10,880-byte frame). Design:

* Implements FIPS 204 Algorithms 3 and 8 and their subroutines (14 CoeffFromThreeBytes, 16 SimpleBitPack (w1), 18/19 bit unpacking, 21 HintBitUnpack, 23/27 pk/sig decoding, 29 SampleInBall, 30 RejNTTPoly, 32 ExpandA, 36 Decompose, 40 UseHint, 41/42 NTT/NTT⁻¹).
* Streams the matrix–vector product row by row and absorbs `w1Encode(w1')` row by row into the final hash; scratch space is a 7 KiB heap workspace.
* Supports an **expanded key** (`A_hat`, `NTT(t1·2^d)`, `tr` precomputed) — the only mode that fits Solana's compute budget. Expansion is a deterministic function of the public key and is produced by the same code.
* Arithmetic keeps coefficients in `[0, q)` and reduces with `%` (one SBF instruction); the zeta table is computed at compile time from ζ = 1753 and checked against FIPS 204 Appendix B values.
* `#![forbid(unsafe_code)]`, `no_std`, one dependency (`sha3`).
* Not constant-time; it never processes secret data.

Validation (details in the feasibility report §3.2): NIST ACVP vectors,
differential testing against `fips204` and RustCrypto `ml-dsa`, property and
exhaustive tests of internal functions.

## 6. Hash usage summary

| Hash | Input | Output | Where |
|------|-------|--------|-------|
| SHAKE256 | pk | `tr` (64 B) | FinalizeKey, stored |
| SHAKE256 | `tr ‖ 0 ‖ 13 ‖ "QSHIELD/QSP-1" ‖ auth` | `mu` (64 B) | every verification |
| SHAKE256 | `c̃` | SampleInBall stream | every verification |
| SHAKE256 | `mu ‖ w1Encode(w1')` | `c̃'` (32 B) | every verification |
| SHAKE128 | `rho ‖ s ‖ r` | `A_hat[r][s]` stream | ExpandKey (once per key) |
| SHA-256 | `"QSHIELD_KEY_ID_V1" ‖ alg ‖ pk` | key id | FinalizeKey, clients |

No hash was substituted for another to save compute units.

## 7. Key generation and storage (clients)

Not implemented in v0.1 beyond tests. Requirements for future signers are in
`docs/SECURITY_MODEL.md` §3: local generation with an OS/browser CSPRNG and
fail-closed behaviour if it is unavailable, never transmitting or logging the
secret key, encrypted-at-rest storage with explicit experimental warnings, and
an architecture that can move signing to hardware.
