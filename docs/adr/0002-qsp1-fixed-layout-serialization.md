# ADR-0002: QSP-1 serialization — fixed-length canonical layout

Status: Accepted (2026-10-02)

## Context
Independent wallets must produce identical bytes; relayers must not find any
malleable or ambiguous field; the on-chain decoder must be cheap and simple.

## Options considered
1. Borsh / bincode of a Rust struct.
2. A TLV or length-prefixed encoding.
3. A single fixed-length layout with every field always present, unused fields required to be zero.
4. EIP-712-style typed hashing.

## Decision
Option 3: 292 bytes, little-endian integers, fixed offsets, domain tag and
version prefix, per-action zero rules enforced by the decoder (QSP-1 §4–§5).

## Security implications
No length confusion, no optional-field ambiguity, no alternative encodings of
the same value (property-tested: `decode(x)` succeeds only if `encode(decode(x)) == x`).

## Tradeoffs
Some bytes are wasted (e.g. `new_key_id` on withdrawals). Adding fields requires
a new version.

## Alternatives rejected
Borsh/bincode: library-defined, enum/option encodings easy to get subtly wrong
across languages. TLV: parsing complexity and canonicality rules. EIP-712:
complex, designed for Ethereum tooling.
