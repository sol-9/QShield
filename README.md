# QShield

QShield is an experimental open-source post-quantum authorization layer for
Solana accounts.

Assets are held by a Solana program-controlled vault. Withdrawals require a
NIST-standardized ML-DSA post-quantum signature rather than relying on a
user's normal Ed25519 Solana wallet key.

**QShield does not make the Solana blockchain itself quantum-resistant.**
It provides an additional authorization model for assets placed inside
QShield-controlled accounts. Solana's transaction signatures, consensus and all
other accounts keep their existing cryptography.

> ⚠️ **Research preview v0.1 — experimental, unaudited.** Do not use with
> meaningful funds. If you lose your post-quantum key, the funds in its vault
> are lost (there is no recovery in v0.1). The program is upgradeable during
> development, so its upgrade authority is a trusted party.

## What works today

* **ML-DSA-44 verification inside a Solana program**, measured at ≈ 828k
  compute units per verification (59 % of the 1.4M per-transaction limit), on
  Agave 4.3 / SBPF v3. See the
  [feasibility report](docs/MLDSA_SOLANA_FEASIBILITY.md).
* **A proof-of-concept vault program** (`programs/qshield-vault`) holding SOL in
  vault PDAs whose withdrawals, key rotation, pause/unpause and close are
  authorized only by ML-DSA-44 signatures over [QSP-1](docs/QSP-1.md)
  authorizations. A relayer can pay the fees without gaining any authority.
* **Single-transaction withdrawals** with v1 transactions (3,010 bytes), and a
  5-transaction signature-buffer path for legacy/v0 transactions.
* **Tests**: NIST ACVP vectors; differential tests against two independent
  ML-DSA implementations; the MVP flow from the project plan; 19 adversarial
  scenarios (replay, substitution, cross-cluster/program/vault replay, buffer
  tampering, account confusion, front-running, …); deterministic QSP-1
  vectors checked by two independent encoders (Rust and Python).

* **Developer tooling** (Phase 2): a Rust SDK (`crates/qshield-client`), the
  `qshield` CLI with first-class offline signing ([CLI](docs/CLI.md),
  [offline signing](docs/OFFLINE_SIGNING.md)), and a TypeScript SDK
  (`sdk/typescript`). All share one encrypted key-file format
  ([keystore](docs/KEYSTORE.md)) and one authorization-file format, and are
  cross-tested against shared vectors; the CLI is tested end to end against a
  real `solana-test-validator`.

* **SPL tokens** (Phase 3): SPL Token and Token-2022 deposits and
  withdrawals under the same PQ authorization. Mint, decimals, token program
  and token accounts are verified on-chain; Token-2022 mints are accepted only
  with allow-listed extensions (transfer hooks, permanent delegates, transfer
  fees and other behaviour-changing extensions fail closed — ADR-0015).

* **Relayer** (Phase 4): `qshield-relayer`, a permissionless, self-hostable
  HTTP service that submits signed authorizations and pays the fees (gas
  sponsorship) with an optional signed minimum fee, rate limiting and full
  local verification before spending ([relayer](docs/RELAYER.md)). It holds
  no PQ key and cannot change what a user signed.

* **Web wallet** (Phase 5, `apps/web`): key generation with a mandatory,
  verified backup; vault creation paid by any Wallet Standard wallet;
  balances; receive; deposits; sends and key rotation signed with the PQ key
  and delivered through a relayer ([wallet](docs/WALLET.md)). Static files, no
  backend, strict CSP; tested in Chromium against a local validator.

* **Malware resistance without delays** (ADR-0018): an optional **guardian**
  key — a second post-quantum key kept on paper (24 words) or another device.
  The everyday key sends instantly within a daily limit or to saved
  addresses; anything else is proposed and approved by the guardian seconds
  later. Malware that steals the everyday key can take at most the limit; it
  cannot unfreeze, save addresses, raise the limit or replace keys. The
  guardian freezes the vault and replaces a stolen key instantly. Plus
  24-word recovery phrases, look-alike-address warnings and a guardian
  approval page for a phone.

Not yet: security hardening phase, devnet deployment.
See [limitations](docs/LIMITATIONS.md).

## How it works

```
 PQ key (user device) ──sign QSP-1 authorization──► signature
                                                        │
                    any relayer (untrusted, pays fees) ◄┘
                                     │
                                     ▼
              QShield program: check cluster, program, vault, nonce, expiry
                               verify ML-DSA-44 (≈ 828k CU)
                                     │
                                     ▼
          vault PDA ──SOL / SPL tokens──► destination
```

The user's ordinary Solana wallet can create a vault and deposit, but holds no
authority over it afterwards: stealing that wallet key does not allow a
withdrawal (`ed25519_wallet_alone_cannot_withdraw`). Details:
[architecture](docs/ARCHITECTURE.md), [threat model](THREAT_MODEL.md).

## Repository

| Path | Contents |
|------|----------|
| `crates/qshield-mldsa` | Verify-only FIPS 204 ML-DSA-44 implementation that fits the SBF runtime |
| `crates/qshield-protocol` | QSP-1 canonical authorization encoding |
| `programs/qshield-vault` | Solana program and its integration/adversarial tests |
| `crates/qshield-client` | Rust SDK: keys, keystore, envelopes, RPC, vault operations |
| `cli/` | `qshield` command-line interface (offline signing) |
| `sdk/typescript` | TypeScript SDK |
| `services/relayer` | `qshield-relayer` HTTP relayer |
| `apps/web` | Web wallet (static, Vite + TypeScript) |
| `benchmarks/ml-dsa-solana` | Feasibility benchmark (program, LiteSVM and validator harnesses, results) |
| `tests/vectors` | NIST ACVP ML-DSA-44 vectors, QSP-1 vectors |
| `docs/` | Specifications, reports, [ADRs](docs/adr/README.md) |

## Build and test

Requires Rust 1.97.1 (pinned) and the Agave 4.3.0 tools (`cargo-build-sbf`).

```bash
cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml
cargo build-sbf --arch v3 --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
cargo test --workspace --release
cargo run --release -p mldsa-bench-harness     # regenerate the benchmark report
(cd sdk/typescript && npm ci && npm test)       # TypeScript SDK
(cd apps/web && npm ci && npm test && npm run build)   # web wallet
scripts/cli-e2e.sh                              # CLI, relayer, TS SDK and web wallet against a local validator
```

## Documentation

* [ML-DSA on Solana feasibility report](docs/MLDSA_SOLANA_FEASIBILITY.md) — Phase 0 result and architecture decision
* [QSP-1 specification](docs/QSP-1.md) and [test vectors](tests/vectors/qsp1/qsp1-vectors.json)
* [On-chain protocol](docs/PROTOCOL.md) · [Architecture](docs/ARCHITECTURE.md) · [Cryptography](docs/CRYPTOGRAPHY.md)
* [Threat model](THREAT_MODEL.md) · [Security model](docs/SECURITY_MODEL.md) · [Recovery model](docs/RECOVERY_MODEL.md)
* [Web wallet](docs/WALLET.md) · [Relayer](docs/RELAYER.md) · [CLI](docs/CLI.md) · [Offline signing](docs/OFFLINE_SIGNING.md) · [Keystore format](docs/KEYSTORE.md) · [TypeScript SDK](sdk/typescript/README.md)
* [Benchmarks](docs/BENCHMARKS.md) · [Deployment](docs/DEPLOYMENT.md) · [Limitations](docs/LIMITATIONS.md)
* [Audit package](docs/AUDIT_PACKAGE.md) · [Dependencies](DEPENDENCIES.md)

## Contributing, security, license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

There is no QShield token, and none is planned.

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
