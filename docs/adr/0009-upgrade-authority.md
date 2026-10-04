# ADR-0009: Upgrade authority — path to immutability

Status: Accepted (2026-10-02)

## Context
An upgradeable program's authority (an Ed25519 key) can replace the program and
take all vault funds; it is also not quantum-resistant.

## Options considered
1. Keep upgradeable with a single key. 2. Multisig. 3. Multisig + timelock.
4. Immutable from day one. 5. Staged: dev → audited → timelocked → immutable.

## Decision
Option 5 (`docs/DEPLOYMENT.md` §3). New major versions ship as new program ids;
QSP-1's `program_id` binding makes this safe.

## Security implications
Until immutability, every deployment must disclose the upgrade authority as a
full-custody trust assumption.

## Tradeoffs
Immutable programs cannot be patched; migrations require user action.

## Alternatives rejected
Immutable from day one: bugs in unaudited code would be permanent. Single-key
upgradeable in production: unacceptable custody risk.
