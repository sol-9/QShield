# ADR-0017: Web wallet architecture

Status: Accepted (2026-10-02)

## Context
Phase 5 delivers a wallet UI: key generation, vault creation, balances,
send, receive, key rotation and a backup flow. Browsers are a hostile
environment for secrets; the UI must keep the PQ key and the Solana wallet
clearly separate and must not introduce new trust in a backend.

## Options considered
Framework: React/Vue vs plain TypeScript + Vite. Hosting: hosted backend vs
static files. Fee payer: wallet adapters (`@solana/wallet-adapter`), Wallet
Standard directly, or relayer-only. Key storage: plaintext/IndexedDB
non-extractable WebCrypto keys (not available for ML-DSA) vs the existing
password-encrypted key file. Backup: "I have saved it" checkbox vs proof by
re-import.

## Decision
Plain TypeScript + Vite, static files, the SDK consumed from source, no
runtime dependencies beyond the SDK's audited noble libraries. Fee payer via
the Wallet Standard event protocol (implemented in ~40 lines, no adapter
library) with `solana:signTransaction`; a development payer only on test
networks. Withdrawals and rotations go through the relayer. Key storage reuses
the keystore format (ADR-0014) in `localStorage`. Backup is verified by
re-importing the downloaded file and decrypting it, and gates vault creation.
Strict CSP, no `innerHTML`.

## Security implications
No server sees keys or signatures beyond the relayer, which only receives
signed envelopes. The browser remains the weak point (extensions, XSS,
malware): documented prominently; the CLI with an offline signer remains the
recommended path for anything beyond experimentation. A malicious wallet
cannot alter transactions undetected (the SDK compares messages) and holds no
vault authority anyway.

## Tradeoffs
No framework means more manual DOM code, but a much smaller audit surface
(≈ 130 KB of JavaScript including ML-DSA, Argon2id and the SDK). Argon2id at
64 MiB in pure JavaScript takes a few seconds per unlock.

## Alternatives rejected
Wallet-adapter libraries: large dependency trees for one feature. A hosted
backend: unnecessary trust. Checkbox-only backups: users click through them,
and a lost key loses the vault (no recovery in this version).
