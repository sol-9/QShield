# Deployment

**No production deployment exists.** QShield v0.1 is a research preview. Do
not deploy vaults holding meaningful funds until every item in §4 is done.

## 1. Supported environments

| Environment | Status |
|-------------|--------|
| LiteSVM (tests) | used by CI |
| Local `solana-test-validator` (Agave 4.3.0) | tested (`scripts/bench-validator.sh`) |
| Devnet | not yet deployed (blocked on verifying devnet feature status; tracked as an issue) |
| Mainnet-beta | **not permitted** (see §4) |

## 2. Building

The cluster is a compile-time choice (QSP-1 §8). Exactly one feature is required:

```bash
cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml
cargo build-sbf --arch v3 --features cluster-devnet   --manifest-path programs/qshield-vault/Cargo.toml
```

A binary built for one cluster rejects authorizations for every other cluster.
Never deploy a `cluster-localnet` build to a public cluster.

`--arch v3` is required: Agave 4.3 contains SIMD-0500, which disables deploying
SBPF v0–v2 programs once activated (it already is on test validators).

Pinned tool versions (see also `.github/workflows/ci.yml`):

| Tool | Version |
|------|---------|
| Rust (host) | 1.97.1 (`rust-toolchain.toml`) |
| Agave / `cargo-build-sbf` | 4.3.0 |
| platform-tools | v1.57 |

## 3. Upgrade authority and governance

A post-quantum vault controlled by an upgradeable program is only as strong as
the **upgrade authority key** — today an Ed25519 key, i.e. not quantum-resistant,
and able to replace the program and drain every vault. This is the single most
important trust assumption of any deployment.

Planned path (each step requires an ADR and public announcement):

1. **Development (now):** upgradeable, local/devnet only, upgrade authority held
   by maintainers, no meaningful funds.
2. **Audited release:** external audit of the program and `qshield-mldsa`;
   reproducible build published (§5).
3. **Timelocked upgrades:** upgrade authority moved to a multisig behind a
   public timelock (e.g. ≥ 14 days), so users can withdraw before any change
   takes effect. Every proposed binary is published with its verified build
   hash during the delay.
4. **Public verification period:** the audited binary runs unchanged for a
   period with a bug bounty.
5. **Immutable core:** the upgrade authority is removed (`solana program
   set-upgrade-authority --final`). New features ship as a *new* program id;
   users migrate by authorizing a withdrawal from the old vault to a new one.

Because QSP-1 binds `program_id`, authorizations never carry over between
program instances, which makes "new program per major version" safe.

Production trust assumptions while upgradeable must be stated wherever a
deployment is announced: *"the holder(s) of upgrade authority X can replace this
program and take all funds."*

## 4. Mainnet prerequisites (spec §57)

- [ ] Architecture reviewed externally
- [ ] Cryptographic implementation (`qshield-mldsa`) reviewed by cryptographers
- [ ] Program audited
- [ ] Threat model reviewed
- [ ] Reproducible build established and documented with hashes
- [ ] Upgrade model decided and implemented (§3)
- [ ] Incident-response procedure written (contacts, pause semantics, communication)
- [ ] `enable_tx_v1` and SBPF v3 status verified on mainnet (otherwise legacy path only)
- [ ] Cluster genesis hashes verified with `solana genesis-hash`

## 5. Reproducible / verified builds

Goal: anyone can rebuild the deployed binary from source and compare hashes.

Record for every deployment:

| Field | Example |
|-------|---------|
| Source commit | `git rev-parse HEAD` |
| Rust toolchain | from `rust-toolchain.toml` |
| Agave / platform-tools | `cargo-build-sbf --version` |
| Build command | as in §2, including `--features cluster-*` |
| Program hash | `sha256sum target/deploy/qshield_vault.so` |
| Deployed address | program id |
| On-chain hash | `solana program dump <ID> dump.so && sha256sum dump.so` (compare after stripping padding) |

Plan: adopt a container-pinned build (e.g. `solana-verify`) so that builds are
bit-for-bit reproducible across machines; until then, hashes are only
reproducible with identical toolchain versions. Tracked as an issue.

## 6. Local end-to-end run

```bash
scripts/bench-validator.sh   # starts a test validator if needed, deploys, runs the RPC harness
```
