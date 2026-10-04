# Fuzzing

Coverage-guided fuzz targets (libFuzzer via `cargo-fuzz`, nightly Rust):

| Target | Input |
|--------|-------|
| `qsp1_decode` | QSP-1 authorization parser |
| `instruction_unpack` | program instruction decoder |
| `account_state` | vault / key / signature-buffer account parsers |
| `mldsa_verify` | ML-DSA-44 verification on arbitrary keys, signatures, messages, contexts |

```bash
cargo install cargo-fuzz --locked
cargo +nightly fuzz run qsp1_decode --fuzz-dir tests/fuzz -- -max_total_time=300
```

The same parsers are property-tested on stable in
`crates/qshield-protocol/tests/properties.rs`,
`crates/qshield-mldsa/tests/differential.rs` and
`programs/qshield-vault/tests/parsing.rs`.
