# ADR-0003: Dedicated streaming ML-DSA-44 verifier

Status: Accepted (2026-10-02)

## Context
The project prefers adapting audited/reference implementations over writing
cryptography. `fips204 0.4.6` and RustCrypto `ml-dsa 0.1.1` both keep the 16 KiB
matrix and vectors of polynomials on the stack; `cargo build-sbf` rejects
`fips204` with a 10,880-byte frame (limit 4,096).

## Options considered
1. Fork `fips204` and move all temporaries to the heap.
2. Fork RustCrypto `ml-dsa` likewise.
3. Port the C reference implementation.
4. A small verify-only implementation that follows FIPS 204 pseudocode, streaming row by row, tested against (1) and (2) as oracles.

## Decision
Option 4: `crates/qshield-mldsa` (~600 lines, `no_std`, `forbid(unsafe_code)`,
only dependency `sha3`). Differential tests against both `fips204` and
RustCrypto `ml-dsa`, plus NIST ACVP vectors.

## Security implications
New cryptographic code is the largest audit item. Verification handles only
public data (no side-channel requirements), which keeps the code small. Two
independent oracles reduce the chance of a shared misunderstanding of FIPS 204.

## Tradeoffs
Maintenance of our own code vs. tracking upstream fixes. Verify-only means
signing in clients uses a different crate.

## Alternatives rejected
Forking: invasive changes across most of either crate (return values of whole
polynomial vectors, generic array types) would produce a fork that is neither
upstream-reviewed nor small. C port: adds `unsafe`/FFI or a translation with the
same review burden.
