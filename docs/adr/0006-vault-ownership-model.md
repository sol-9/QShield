# ADR-0006: Vault ownership — PDA bound to the initial key, no Ed25519 authority

Status: Accepted (2026-10-02)

## Context
Compromise of the user's Ed25519 wallet must not allow withdrawal. Vault
initialization should be permissionless yet impossible to hijack.

## Options considered
1. Vault PDA seeded by the creator's wallet; wallet recorded as owner.
2. Vault PDA seeded by a random seed only.
3. Vault PDA seeded by `initial_key_id ‖ vault_seed`; no wallet recorded.
4. Key accounts as PDAs vs. client-allocated keypair accounts.

## Decision
Option 3 for vaults. Key accounts are client-allocated keypair accounts (the
runtime caps account growth in CPI at 10 KiB; the key account is 21,976 bytes),
initialized only with the key account's own signature.

## Security implications
Whoever initializes a vault address, it is controlled by the key its address
commits to (front-running is harmless). The wallet has no recorded role.

## Tradeoffs
Users must keep `vault_seed` (or the vault address) to find their vault; key
accounts need an extra signer at creation.

## Alternatives rejected
1: records an Ed25519 authority. 2: front-runnable with a different key.
PDA key accounts: impossible to allocate at this size via CPI in one step.
