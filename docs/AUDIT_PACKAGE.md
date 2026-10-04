# Audit package (v0.1 research preview)

An index for reviewers. Commit hash and program hash must be filled in when an
audit is scheduled.

| Item | Location |
|------|----------|
| Architecture overview | `docs/ARCHITECTURE.md` |
| Feasibility report and architecture decision | `docs/MLDSA_SOLANA_FEASIBILITY.md`, `docs/adr/` |
| Protocol specification | `docs/QSP-1.md` (signed messages), `docs/PROTOCOL.md` (program interface) |
| Threat model | `THREAT_MODEL.md`, `docs/SECURITY_MODEL.md` |
| Program source | `programs/qshield-vault/src/` (`processor.rs` holds all authorization logic; `token.rs` the SPL/Token-2022 parsing and mint policy) |
| Cryptographic implementation | `crates/qshield-mldsa/src/` |
| QSP-1 implementation | `crates/qshield-protocol/src/lib.rs` (Rust), `sdk/typescript/src/qsp1.ts` |
| Client software (key handling) | `crates/qshield-client/src/{key,keystore,envelope}.rs`, `sdk/typescript/src/{keys,keystore,envelope}.ts`, `cli/src/main.rs` |
| Dependency list | `DEPENDENCIES.md`, `Cargo.lock`, `deny.toml` |
| Known limitations | `docs/LIMITATIONS.md` |
| Tests | `crates/*/tests/`, `programs/qshield-vault/tests/` |
| Adversarial test list | `programs/qshield-vault/tests/adversarial.rs` and `spl.rs` (one test per attack class; mapping in `THREAT_MODEL.md` §3) |
| Privileged roles | `docs/SECURITY_MODEL.md` §2 — none in the program; upgrade authority only |
| Upgrade authority | `docs/DEPLOYMENT.md` §3, ADR-0009 |
| Benchmarks | `docs/BENCHMARKS.md`, `benchmarks/ml-dsa-solana/results/` |
| Test coverage report | generate with `cargo llvm-cov --workspace` (host code paths; on-chain paths are covered by LiteSVM integration tests) |

## Suggested review priorities

1. `qshield-mldsa`: equivalence with FIPS 204 Algorithm 8, especially
   `HintBitUnpack`, `UseHint`/`Decompose`, the `z` norm check, `SampleInBall`,
   and the expanded-key path. Oracles: `tests/differential.rs`.
2. `processor.rs::execute`: order and completeness of checks; account aliasing;
   lamport arithmetic; nonce consumption; rotation and close paths.
3. Key-account lifecycle (I7): create/write/finalize/expand/close; no path to
   modify a `Ready` key; key id check.
4. Signature buffers: binding, finalization, consumption.
5. QSP-1 canonicality (`Authorization::validate`).
5a. SPL paths (`deposit_spl`, `execute` WithdrawSpl, `token.rs`): token
   program/asset binding, token-account owner/mint/state checks, PDA signer
   seeds, Token-2022 TLV parsing and the extension allow-list (ADR-0015).
6. Cluster binding build configuration (`lib.rs`).

## Invariants to check

See `docs/SECURITY_MODEL.md` §1 (I1–I9).
