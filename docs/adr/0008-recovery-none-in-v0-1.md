# ADR-0008: Recovery — none in v0.1

Status: Accepted (2026-10-02)

## Context
Any recovery path is an alternative way to control the vault and therefore an
attack surface. Using the Ed25519 wallet for recovery would negate the PQ property.

## Options considered
1. No recovery. 2. Ed25519 wallet recovery. 3. Secondary PQ key. 4. Time-delayed PQ recovery. 5. PQ guardians / multisig.

## Decision
No recovery in v0.1; reserve layout fields (`threshold`, `key_count`,
`recovery_mode`) for future PQ-only policies (`docs/RECOVERY_MODEL.md`).

## Security implications
No backdoor. Key loss = fund loss; this must be stated in every user-facing surface.

## Tradeoffs
Usability. Users must back up keys.

## Alternatives rejected
Ed25519 recovery: defeats the purpose. Others: deferred until the base model is
reviewed; each needs its own ADR and tests.
