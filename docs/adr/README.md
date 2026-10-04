# Architecture Decision Records

Changes to any of the following require an ADR (project rules §47): signature
scheme, serialization format, vault ownership model, nonce model, recovery
model, upgrade authority, relayer trust model, hashing scheme, signature
transport mechanism, program architecture.

Format: Context · Options considered · Decision · Security implications ·
Tradeoffs · Alternatives rejected. Status is one of Proposed, Accepted,
Superseded (with a link).

| ADR | Title | Status |
|-----|-------|--------|
| [0001](0001-signature-scheme-ml-dsa-44.md) | Signature scheme: pure ML-DSA-44 | Accepted |
| [0002](0002-qsp1-fixed-layout-serialization.md) | QSP-1 serialization: fixed-length canonical layout | Accepted |
| [0003](0003-streaming-verifier-implementation.md) | Verifier: dedicated streaming ML-DSA-44 implementation | Accepted |
| [0004](0004-direct-verification-with-stored-key-expansion.md) | Architecture A with on-chain key expansion | Accepted |
| [0005](0005-signature-transport.md) | Signature transport: v1 inline, buffer fallback | Accepted |
| [0006](0006-vault-ownership-model.md) | Vault ownership: PDA bound to the initial key, no Ed25519 authority | Accepted |
| [0007](0007-nonce-model.md) | Nonce model: sequential u64, tombstoned vaults | Accepted |
| [0008](0008-recovery-none-in-v0-1.md) | Recovery: none in v0.1 | Accepted |
| [0009](0009-upgrade-authority.md) | Upgrade authority path to immutability | Accepted |
| [0010](0010-relayer-trust-and-fees.md) | Relayers are untrusted; fees are signed | Accepted |
| [0011](0011-hashing.md) | Hashing: SHAKE inside ML-DSA, SHA-256 for key ids | Accepted |
| [0012](0012-compile-time-cluster-binding.md) | Cluster id bound at compile time | Accepted |
| [0013](0013-native-program-sbpf-v3.md) | Native program, no framework, SBPF v3 | Accepted |
| [0014](0014-key-storage-and-envelope-formats.md) | Key storage and authorization envelope formats | Accepted |
| [0015](0015-spl-tokens-and-token-2022-policy.md) | SPL Token / Token-2022 support and mint policy | Accepted |
| [0016](0016-relayer-service.md) | Relayer service design | Accepted |
| [0017](0017-web-wallet.md) | Web wallet architecture | Accepted |
| [0018](0018-guardian-policy-qsp1-v2.md) | Guardian policy and QSP-1 v2 (instant, no delays) | Accepted |
