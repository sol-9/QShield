# Security model

Companion to [`THREAT_MODEL.md`](../THREAT_MODEL.md). This document states the
invariants the code must maintain, the privileged roles (there are none in the
program), and requirements for future client software.

## 1. Program invariants

These are tested continually (`programs/qshield-vault/tests/`). Any change that
weakens one needs an ADR.

| # | Invariant | Tests |
|---|-----------|-------|
| I1 | Possession of the user's Ed25519 key alone never permits withdrawal from, re-keying of, or re-initialization of a vault. | `ed25519_wallet_alone_cannot_withdraw`, `random_ed25519_only_instructions_never_move_funds` |
| I2 | A vault's lamports decrease only in `Execute`/`ExecuteWithBuffer` after a valid ML-DSA-44 signature over a QSP-1 authorization for this cluster, program, vault and current nonce, and only by `amount + fee_lamports` (or, for CloseVault, the balance above the rent reserve). | `mvp_demonstration`, `destination_amount_fee_and_field_substitution`, `duplicate_and_aliased_accounts` |
| I3 | A successful authorization consumes its nonce; a failed one changes nothing. | `mvp_demonstration`, `replay_attack_inline_and_buffered`, every `untouched()` assertion |
| I4 | Changing any byte of a signed authorization invalidates it. | `destination_amount_fee_and_field_substitution` |
| I5 | The identity of the relayer (fee payer) does not affect the outcome. | `relayer_identity_cannot_change_outcome` |
| I6 | After rotation the old key cannot authorize anything. | `key_rotation` |
| I7 | A key account's public key and expansion are written only by the program, only from bytes that hash to its `key_id`, and never change once `Ready`. | `key_account_attacks` |
| I8 | A vault address is initialized at most once and always with the key it commits to. | `front_running_vault_initialization_is_harmless`, `close_vault_is_final` |
| I9 | No instruction lets any party other than the vault's PQ key holder transfer vault funds (no admin). | code review, I1 tests |
| I10 | Tokens leave a vault-owned token account only through `Execute` WithdrawSpl with a valid signature: exactly `amount` base units of the signed mint (signed decimals = mint decimals) to the signed destination token account, via the signed asset type's token program, for mints that pass the policy of ADR-0015. | `spl.rs` (all tests) |
| I11 | On a guarded vault, the everyday key alone moves at most `limit + limit·t/period` lamports (fees included) over any interval `t` to addresses that are not saved, and no tokens to unsaved owners; it cannot unfreeze, change keys, save addresses, raise the limit or use v1 authorizations. | `policy.rs` |
| I12 | The guardian moves funds only by approving a proposal of the current everyday key with identical effect, plus signed fees that count against the allowance; it has its own nonce, unaffected by the everyday key. A frozen vault pays no everyday-key fees. | `policy.rs` |
| I13 | Replacing the everyday key invalidates its proposals and its key account; re-enabling a policy never reuses guardian nonces. | `policy.rs` |

## 2. Privileged roles

| Role | Exists? | Powers |
|------|---------|--------|
| Program admin / owner key | **No** | — |
| Guardian key (opt-in, per vault) | Yes, chosen by the vault owner | Approve proposals, freeze/unfreeze, replace the everyday key, policy changes (ADR-0018). Cannot send funds on its own initiative. |
| Emergency pause authority | **No** | Pause is an action authorized by the vault's own PQ key. |
| Fee payer / relayer | Yes (anyone) | Pays fees; receives only signed fees. |
| Key-account creator | Yes (per key) | Uploads the public key; receives rent refunds. Cannot change a ready key. |
| Signature-buffer creator | Yes (per buffer) | Writes the buffer; receives rent refund. |
| **Program upgrade authority** | Yes, while upgradeable | Can replace the program: full control over all vaults. See `docs/DEPLOYMENT.md`. |

## 3. Requirements for client software (SDKs, CLI, wallets)

Status in v0.3: items 1, 2, 3, 5 (rendering and default 1-hour expiry), 6 and
7 are implemented by the Rust SDK, CLI and TypeScript SDK; item 4 is provided
by `get_vault_checked` / `getVaultChecked` and `deposit-sol --key` /
`deposit-spl --key`; item 8 holds trivially (there is no analytics code);
item 9 by `get_mint` / `getMint`, the WithdrawSpl pre-checks and the CLI close
guard.

1. Generate ML-DSA keys **locally** with a cryptographically secure RNG (OS
   `getrandom`, browser `crypto.getRandomValues`); fail closed if unavailable.
2. Never send the secret key or seed to a relayer, backend, RPC provider,
   analytics or logs; never place it on-chain. Scrub it from error messages.
3. Store it encrypted at rest (password-based KDF + AEAD) with clear
   "experimental, not hardware-grade" warnings; design signing behind an
   interface that hardware wallets, secure enclaves, offline/QR signers can
   implement.
4. Before depositing, check that the vault's on-chain `key_id` equals the
   user's key id, and that the program id and cluster are the intended ones.
5. Display every QSP-1 field in human-readable form before signing, and set
   `expires_at` by default (e.g. 1 hour).
6. Use hedged (randomized) ML-DSA signing.
7. Distinguish clearly, in any UI, between the Solana wallet (pays fees, can
   deposit, cannot withdraw) and the QShield PQ key (authorizes withdrawals).
8. Analytics disabled by default; never collect keys or signed material.
9. For tokens: read the mint from chain and refuse unsupported mints before
   depositing or signing; show token amounts with the mint's decimals; warn
   about freeze authorities; refuse to close a vault that still holds tokens.

## 4. Relayer requirements (`services/relayer`, `docs/RELAYER.md`)

A relayer only ever handles public data. It may validate formatting and
simulate before submitting; it must not be able to — and by I4/I5 cannot —
alter the effect of an authorization. Users must always be able to submit
directly; the protocol has no dependency on any particular relayer.
