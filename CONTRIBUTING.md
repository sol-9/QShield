# Contributing to QShield

QShield prioritizes **correctness, security, simplicity, auditability,
determinism and interoperability** over cleverness, premature optimization,
feature count or UI polish. There is no token and none is planned.

## Development setup

* Rust 1.97.1 (pinned in `rust-toolchain.toml`).
* Agave 4.3.0 CLI tools (`cargo-build-sbf`, `solana-test-validator`) from the
  [Agave releases](https://github.com/anza-xyz/agave/releases), on `PATH`.

```bash
cargo build-sbf --arch v3 --features cluster-localnet --manifest-path programs/qshield-vault/Cargo.toml
cargo build-sbf --arch v3 --manifest-path benchmarks/ml-dsa-solana/program/Cargo.toml
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --release
python3 scripts/qsp1_reference.py
```

## Rules for every contributor (human or agent)

1. Read the existing documentation (`docs/`, ADRs) before changing architecture.
2. Never change protocol formats silently. Changes to the signature scheme,
   serialization, vault ownership, nonce model, recovery model, upgrade
   authority, relayer trust model, hashing, signature transport or program
   architecture require an ADR in `docs/adr/`.
3. Open an issue for major architecture decisions.
4. Use focused branches and small, reviewable pull requests.
5. Include tests with every security-relevant change; every discovered
   vulnerability gets a regression test.
6. Explain security implications in the PR description.
7. Never merge failing CI. Never weaken or delete tests to make CI pass. Never
   disable a security check without documenting why.
8. Do not implement cryptography from scratch when a reviewed implementation can
   be used; when you must (see ADR-0003), test against official vectors and at
   least one independent implementation.
9. Avoid `unsafe`; if unavoidable, isolate and document it.
10. Never log or transmit secret keys, seeds or recovery material.
11. Keep security claims narrow: QShield does not make Solana quantum-safe.
12. Verify assumptions experimentally; record Solana limits with their source.

## Pull request checklist

- [ ] `cargo fmt`, `clippy -D warnings`, `cargo test --workspace` pass
- [ ] Program rebuilt and adversarial suite passes
- [ ] Benchmarks regenerated if the verifier or program changed
- [ ] Docs/ADR updated for any protocol or architecture change
- [ ] Security implications described

By contributing you agree that your contributions are licensed under
Apache-2.0 OR MIT, at the user's option. See `CODE_OF_CONDUCT.md`.
