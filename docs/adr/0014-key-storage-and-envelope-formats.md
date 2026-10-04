# ADR-0014: Key storage and authorization envelope formats

Status: Accepted (2026-10-02)

## Context
Phase 2 adds client software (Rust SDK, CLI, TypeScript SDK). Keys must be
generated locally and stored encrypted; offline signing needs a file format
that moves between machines. Both formats must be identical across
implementations so a key or authorization made by one tool works in another.

## Options considered
Key storage: (1) raw seed or secret key files; (2) Ethereum-style "Web3 Secret
Storage" (scrypt/PBKDF2 + AES-CTR + MAC); (3) Argon2id + XChaCha20-Poly1305
over the 32-byte seed with header fields as associated data; (4) OS keychains
only.
Offline files: (a) raw QSP-1 bytes; (b) PSBT-like binary container; (c) JSON
envelope with the QSP-1 bytes, a human-readable rendering that must match them,
and the signature.

## Decision
Key storage (3), specified in `docs/KEYSTORE.md`: store only the seed;
Argon2id (default 64 MiB, t = 3) → XChaCha20-Poly1305; header bound as AAD;
the public key is re-derived and checked after decryption; KDF cost bounded on
load. Offline files (c), specified in `docs/OFFLINE_SIGNING.md`; the rendering
is part of the format and must be byte-identical across implementations.

## Security implications
A stolen key file is only as strong as its password (memory-hard KDF slows
guessing). Header tampering is detected. Envelope rule 2 prevents a file from
displaying different values from those it signs; signers still must display
their *own* rendering. Software storage remains vulnerable to malware on the
signing device — documented in every user-facing surface.

## Tradeoffs
JSON envelopes are large (~9 KB signed) for QR transport; a compact binary
encoding can be added later without changing QSP-1. Argon2id at 64 MiB is slow
in browsers (pure JS) but acceptable for an occasional unlock.

## Alternatives rejected
Raw files: no protection at rest. Web3 Secret Storage: older KDF choices and
unauthenticated header. OS keychains only: not portable, not available for
air-gapped machines (to be offered later behind the `PqSigner` interface).
Raw QSP-1 bytes for offline signing: no way to carry the signature, expected
signer or submission hints.
