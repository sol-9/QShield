# Dependencies

Cryptographic and on-chain dependencies are security-critical. Every change to
this list needs review; versions of cryptographic crates are pinned exactly in
`Cargo.toml` and all versions are locked in `Cargo.lock`. `cargo deny check`
(policy: `deny.toml`) enforces licenses, sources and advisories in CI.

## Licensing

QShield is dual-licensed **Apache-2.0 OR MIT**. All dependencies use permissive
licenses (Apache-2.0, MIT, BSD-2/3-Clause, Zlib, 0BSD, CC0-1.0, Unicode-3.0,
Unlicense, and CDLA-Permissive-2.0 for the `webpki-roots` CA certificate data used by the RPC client). Note that the Solana crates are **Apache-2.0 only**: anyone
redistributing a QShield program binary under the MIT option must still comply
with Apache-2.0 for those components (notice and license text). NIST ACVP test
vectors are U.S. Government works.

## On-chain (compiled into `qshield_vault.so`)

| Package | Version | Purpose | License | Repository | Audit / history | Why chosen |
|---------|---------|---------|---------|------------|-----------------|------------|
| `qshield-mldsa` | 0.1.0 (this repo) | ML-DSA-44 verification | Apache-2.0 OR MIT | this repo | **unaudited** new code; ACVP + differential tested | SBF stack limits (ADR-0003) |
| `qshield-protocol` | 0.1.0 (this repo) | QSP-1 decoding | Apache-2.0 OR MIT | this repo | unaudited | spec reference implementation |
| `sha3` | =0.10.8 | SHAKE128/256 for ML-DSA | MIT OR Apache-2.0 | github.com/RustCrypto/hashes | widely used; part of RustCrypto (used by many audited projects); no known advisories | standard, `no_std`, pure Rust |
| `keccak` | 0.1.6 (via sha3) | Keccak-f[1600] permutation | Apache-2.0 OR MIT | github.com/RustCrypto/sponges | widely used | transitive |
| `digest`, `block-buffer`, `crypto-common`, `generic-array` | 0.10.x / 0.14.x (via sha3) | hashing traits and buffers | MIT OR Apache-2.0 | RustCrypto | widely used | transitive |
| `bytemuck` | 1.25.x | zero-copy view of the stored expansion (alignment-checked) | Zlib OR Apache-2.0 OR MIT | github.com/Lokathor/bytemuck | widely used, safe API | avoids `unsafe` in our code |
| `solana-program-entrypoint`, `solana-account-info`, `solana-cpi`, `solana-instruction`, `solana-program-error`, `solana-msg`, `solana-pubkey`/`solana-address`, `solana-sysvar`, `solana-clock`, `solana-rent`, `solana-sha256-hasher` | 3.x / 4.x (see `Cargo.lock`) | Solana program interface, syscalls | Apache-2.0 | github.com/anza-xyz/solana-sdk | maintained by Anza; used by all native programs | official split crates (ADR-0013) |

## Off-chain / test only

| Package | Version | Purpose | License | Repository | Why chosen |
|---------|---------|---------|---------|------------|------------|
| `fips204` | =0.4.6 | ML-DSA key generation and signing in tests and vectors; differential oracle | MIT OR Apache-2.0 | github.com/integritychain/fips204 | pure Rust, `no_std`, ACVP-tested |
| `ml-dsa` | =0.1.1 | second independent differential oracle | Apache-2.0 OR MIT | github.com/RustCrypto/signatures | independent codebase from `fips204` |
| `sha2` | 0.10.x | SHA-256 key ids off-chain | MIT OR Apache-2.0 | RustCrypto/hashes | standard |
| `litesvm` | 0.17.x | in-process SVM for program tests and benchmarks | Apache-2.0 | github.com/LiteSVM/litesvm | uses Agave 4.3 SVM crates; mainnet feature snapshot |
| `solana-rpc-client` etc. | 4.3.x | validator benchmark harness (separate workspace) | Apache-2.0 | github.com/anza-xyz/agave | official client |
| `proptest`, `rand`, `rand_chacha`, `hex`, `serde`, `serde_json`, `bincode` | see lockfile | tests, fixtures, reports | MIT/Apache-2.0 | | standard |

## Client software (Rust SDK, CLI)

| Package | Version | Purpose | License | Why chosen |
|---------|---------|---------|---------|------------|
| `fips204` | =0.4.6 | ML-DSA-44 key generation and hedged signing | MIT OR Apache-2.0 | same crate as the differential oracle; `no_std`, ACVP-tested |
| `argon2` | =0.5.3 | Argon2id key derivation for key files | MIT OR Apache-2.0 | RustCrypto |
| `chacha20poly1305` | =0.10.1 | XChaCha20-Poly1305 for key files | Apache-2.0 OR MIT | RustCrypto |
| `zeroize` | 1.8 | wiping secrets from memory | Apache-2.0 OR MIT | RustCrypto |
| `getrandom` | 0.2 | OS CSPRNG (fails closed) | MIT OR Apache-2.0 | standard |
| `ureq` | 3.x | HTTP for JSON-RPC (optional feature `http`) | MIT OR Apache-2.0 | small, blocking, rustls |
| `clap`, `rpassword`, `anyhow`, `thiserror`, `serde_json`, `bs58`, `hex`, `wincode` | see lockfile | CLI parsing, password prompt, errors, encodings | MIT/Apache-2.0 | standard |

Data: the BIP-39 English word list (2,048 words, from bitcoin/bips via
`@scure/bip39`, MIT; SHA-256 checked in tests) for recovery phrases.

## Relayer (`services/relayer`)

| Package | Version | Purpose | License | Why chosen |
|---------|---------|---------|---------|------------|
| `tiny_http` | 0.12 | HTTP server | MIT OR Apache-2.0 | small, blocking, few dependencies (ADR-0016) |
| `qshield-client`, `clap`, `serde_json`, `sha2`, `hex`, `anyhow` | see lockfile | submission logic, CLI, JSON, request ids | MIT/Apache-2.0 | shared with the CLI |

## TypeScript SDK (`sdk/typescript/package.json`, exact pins)

| Package | Version | Purpose | License |
|---------|---------|---------|---------|
| `@noble/post-quantum` | 0.7.1 | ML-DSA-44 keygen/sign/verify | MIT |
| `@noble/hashes` | 2.4.0 | SHA-256, Argon2id | MIT |
| `@noble/ciphers` | 2.4.0 | XChaCha20-Poly1305 | MIT |
| `@noble/curves` | 2.4.0 | ed25519 point decoding for PDA derivation | MIT |
| `@scure/base` | 2.4.0 | hex, base58, base64 | MIT |
| `typescript`, `vitest`, `@types/node` | dev only | build and tests | Apache-2.0 / MIT |

The noble libraries are audited, dependency-light and widely used; the SDK's
ML-DSA results are checked against the QSP-1 vectors (signed by `fips204`) and
cross-verified by the Rust CLI.

## Toolchain

| Tool | Version | Notes |
|------|---------|-------|
| Rust | 1.97.1 | `rust-toolchain.toml`; required by Agave 4.3 crates |
| Agave (`cargo-build-sbf`, `solana-test-validator`) | 4.3.0 | release tarball from github.com/anza-xyz/agave |
| platform-tools | v1.57 | installed by `cargo-build-sbf` |
