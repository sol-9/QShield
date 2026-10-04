# ADR-0010: Relayers are untrusted; fees are signed

Status: Accepted (2026-10-02)

## Context
Users holding only a PQ key need someone to pay Solana fees. That party must
gain no authority.

## Options considered
1. Trusted relayer with discretion. 2. Untrusted relayer; fee implicit/free. 3. Untrusted relayer; fee explicitly signed.

## Decision
Option 3. `fee_lamports` and `fee_recipient` are QSP-1 fields; zero recipient
means "the transaction fee payer". Anyone may submit; the protocol never
depends on a specific relayer.

## Security implications
A relayer cannot change any effect (invariants I4, I5). It can censor or delay;
users can submit themselves or via another relayer.

## Tradeoffs
With a zero recipient a competing submitter can capture the fee (same cost to
the user).

## Alternatives rejected
Implicit fees: unbounded. Trusted relayers: centralization and custody risk.
