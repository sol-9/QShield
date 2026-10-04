# QShield threat model

Scope: research preview — the `qshield-vault` program, the QSP-1 protocol, the
`qshield-mldsa` verifier, the client software and the reference relayer
(`services/relayer`). The web app does not exist yet.

QShield never claims absolute security, and it does **not** make Solana
quantum-resistant. It changes *who can authorize* moving assets that are held
in QShield vaults.

## 1. Assets and actors

| Asset | Description |
|-------|-------------|
| Vault funds | Lamports held by a vault PDA, and SPL Token / Token-2022 balances in token accounts whose owner is the vault PDA |
| Vault control | The right to withdraw, rotate the key, pause, close |
| PQ private key | ML-DSA-44 secret key on the user's device |
| Relayer funds | SOL the relayer spends on fees and buffer rent |

| Actor | Trust |
|-------|-------|
| User device holding the PQ key | Trusted while signing |
| User's Ed25519 wallet | **Untrusted after vault creation** (may be stolen) |
| Relayer / fee payer | **Untrusted** (may modify, delay, drop, or reorder) |
| Any other Solana user | Untrusted (may front-run, spam, craft accounts) |
| RPC providers | Untrusted for integrity; see the private-key boundary below |
| Solana validators / runtime | Trusted to execute programs correctly (§4) |
| Program upgrade authority | Trusted during development; see `docs/DEPLOYMENT.md` |

## 2. Trust boundaries

```
 ┌───────────── user device (trusted while signing) ─────────────┐
 │  ML-DSA-44 secret key ──► sign QSP-1 bytes ──► signature        │
 └─────────────────────────────────────────┬──────────────────────┘
                                           │ authorization + signature (public)
 ┌──────────────────────── untrusted ──────▼──────────────────────┐
 │  relayer / any submitter ── Solana transaction ── RPC / leader  │
 └─────────────────────────────────────────┬──────────────────────┘
                                           │
 ┌──────────── trusted computing base (on-chain) ─────────────────┐
 │  Solana runtime ── qshield-vault program ── qshield-mldsa       │
 │                    vault PDA, key account (expanded key)        │
 └────────────────────────────────────────────────────────────────┘
```

Everything crossing the middle box is public. Integrity comes only from the
ML-DSA signature over the full QSP-1 authorization.

## 3. Protected against (assuming §4 holds)

Each item references the automated test that demonstrates it.

| Threat | Mechanism | Test |
|--------|-----------|------|
| Theft of the user's ordinary Solana Ed25519 key, for assets already in a vault | No instruction lets an Ed25519 signer move vault funds, change the key, or re-initialize the vault | `lifecycle.rs::ed25519_wallet_alone_cannot_withdraw`, `adversarial.rs::random_ed25519_only_instructions_never_move_funds` |
| Malicious relayer modifying destination, amount, fee, vault, nonce, action, cluster, program, expiry, or any other field | Every field is signed; canonical encoding leaves no unsigned bits | `adversarial.rs::destination_amount_fee_and_field_substitution` (flips each of the 292 bytes), `lifecycle.rs::mvp_demonstration`, `explicit_relayer_fee` |
| Relayer substituting accounts (destination, fee recipient, key, vault, buffer creator) | Every touched account is compared with the authorization or vault state | `adversarial.rs::destination_account_substitution`, `wrong_vault_and_pda_substitution`, `buffer_chunk_replacement_and_ownership` |
| Relayer charging an unspecified fee | Fees exist only as signed `fee_lamports` to signed `fee_recipient` | `lifecycle.rs::explicit_relayer_fee` |
| Authorization replay | Per-vault nonce consumed on success; closed vaults are tombstones | `adversarial.rs::replay_attack_inline_and_buffered`, `lifecycle.rs::close_vault_is_final` |
| Cross-vault replay | `vault` field | `lifecycle.rs::mvp_demonstration` (step 15), `adversarial.rs::wrong_vault_and_pda_substitution` |
| Cross-network replay (devnet ↔ mainnet) | `cluster_id` compiled into the binary | `adversarial.rs::cross_cluster_replay` |
| Cross-deployment replay (program A ↔ B) | `program_id` | `adversarial.rs::cross_program_replay` |
| Cross-protocol replay (same ML-DSA key used elsewhere) | ML-DSA context `QSHIELD/QSP-1` + in-message domain | QSP-1 vector `neg_empty_context` |
| Expired / premature authorizations | `valid_after`, `expires_at` vs `Clock` | `lifecycle.rs::expiry_and_valid_after_use_clock_unix_timestamp` |
| Signature truncation / padding / malformed encodings | Exact-length instruction parsing; strict `sigDecode` / `HintBitUnpack` | `adversarial.rs::signature_truncation_and_padding`, `qshield-mldsa` differential tests |
| Signature-buffer tampering (chunk replacement, post-finalize edits, foreign buffers, refund theft) | Creator-only writes, immutable after finalize, bound to vault, consumed on use | `adversarial.rs::buffer_chunk_replacement_and_ownership` |
| Key-account tampering (wrong key uploaded, rewriting a ready key, closing an in-use key, front-running initialization) | Key id check, state machine, `in_use`, key-account signature on init | `adversarial.rs::key_account_attacks`, `lifecycle.rs::ed25519_wallet_alone_cannot_withdraw` |
| Vault front-running at initialization | Vault address commits to its initial key id | `adversarial.rs::front_running_vault_initialization_is_harmless` |
| Account type confusion, fake owners, fake system program | Owner, discriminator, layout-version and size checks | `adversarial.rs::account_type_confusion`, `key_account_attacks` |
| Integer overflow/underflow, draining the rent reserve | Checked arithmetic; rent reserve excluded from withdrawable balance | `adversarial.rs::integer_overflow_and_underflow`, `lifecycle.rs::cannot_withdraw_below_rent_or_more_than_balance` |
| Malicious extra accounts | Ignored | `adversarial.rs::malicious_remaining_accounts_are_ignored` |
| Rotation abuse (redirecting refunds, foreign key accounts) | Old key creator and new key binding checked | `adversarial.rs::rotation_attacks`, `lifecycle.rs::key_rotation` |
| Ed25519 wallet or attacker moving vault tokens directly through the token program | Only the vault PDA is the token-account authority; the program signs as the PDA only inside `Execute` after PQ verification | `spl.rs::withdraw_spl_account_substitution` |
| Relayer substituting the mint, destination token account, token program, or a source not owned by the vault; mismatched decimals; frozen accounts | All read from chain and compared with the signed authorization; `TransferChecked` | `spl.rs::withdraw_spl_account_substitution`, `withdraw_spl_field_checks` |
| Token-2022 extensions that let third parties move tokens, run code during transfers, or change delivered amounts | Mint extension allow-list, unknown extensions rejected (ADR-0015) | `spl.rs::token_2022_unsupported_extensions_fail_closed` |
| Deposits to token accounts the program cannot withdraw from | `DepositSpl` checks the destination is owned by a live vault and the mint is supported | `spl.rs::deposit_spl_checks` |
| Admin theft | There is no admin role, no admin key and no privileged instruction | Code review: `programs/qshield-vault/src/processor.rs`; `random_ed25519_only_instructions_never_move_funds` |

## 4. Not protected against (by design or out of scope)

| Threat | Notes |
|--------|-------|
| Malware stealing the PQ private key | Without a guardian: full compromise of the vault. **With a guardian policy (ADR-0018):** loss bounded by the everyday limit until the guardian freezes and replaces the key (`policy.rs::freeze_and_recovery_after_the_everyday_key_is_stolen`); the guardian must live off the infected device. |
| Malware stealing the guardian key | Equivalent to a stolen single key (it can replace the everyday key). Keep it on paper or a separate device. |
| Malicious browser extensions / compromised device during signing | Can make the user sign a different authorization than displayed. Wallets must show decoded fields. |
| Compromised Solana runtime or validator supermajority | The program trusts the runtime to execute it correctly. |
| Malicious or compromised **program upgrade authority** | Can replace the program and take every vault. The single largest trust assumption while the program is upgradeable. See `docs/DEPLOYMENT.md` §3. |
| Cryptographic failure of ML-DSA-44 or SHAKE | QShield inherits ML-DSA's security; no hybrid fallback in v0.1. |
| Bugs in QShield (program, verifier, encoders) | Unaudited research code. |
| Future implementation attacks | e.g. new side channels in signers. Verification is public-data only. |
| Social engineering | e.g. convincing a user to sign a withdrawal to the attacker. |
| Compromised recovery credentials | v0.1 has no recovery (`docs/RECOVERY_MODEL.md`). |
| Solana consensus failure, chain halts, reorgs beyond finality | Out of scope. |
| Loss of the PQ key | **Permanent loss of vault funds** in v0.1 (no recovery). |
| Relayer censorship / delay | A relayer can refuse to submit. Mitigation: anyone (including the user's own wallet) can submit; no protocol dependency on any relayer. An authorization without `expires_at` stays valid until its nonce is used — users can cancel by executing another authorization for that nonce. |
| Front-running a submitted authorization | Harmless for integrity: whoever submits, the effect is identical (`adversarial.rs::relayer_identity_cannot_change_outcome`). A competing relayer can capture a `fee_recipient = 0` fee; users who care name the recipient. |
| Lamports sent directly to a closed vault | Unrecoverable (no key remains). UIs must warn. |
| Tokens left in vault token accounts at `CloseVault`, or sent to a closed vault | Unrecoverable: `CloseVault` does not sweep tokens. Clients refuse to build a close while tokens remain. |
| Token issuer actions (freeze authority freezing vault accounts, mint authority inflating supply) | Inherent to the token; QShield cannot override the issuer. Clients warn about freeze authorities. |
| Tokens of unsupported mints sent directly to a vault-owned token account | Cannot be withdrawn by this version (fail closed). |
| Quantum attacks on Solana itself (Ed25519 transaction signatures, consensus, other programs, the upgrade authority key) | QShield cannot change these. |
| Denial of service by spamming failing transactions | The spammer pays fees; vault state is unaffected. |
| Spamming a relayer to drain its fee-payer key | Relayer verifies every request against chain state (including the ML-DSA signature against the vault key) before spending, rate-limits, bounds its queue and can require a signed minimum fee (`docs/RELAYER.md`). Valid authorizations for attacker-owned vaults with zero fee still cost the relayer fees unless it sets a minimum. |
| Compromised relayer | Loses its own fee-payer SOL; can censor or delay. Cannot alter or forge authorizations. |

## 5. Assumptions

1. The Solana runtime correctly enforces account ownership, signer flags, writability, rent and transaction atomicity.
2. ML-DSA-44 (FIPS 204) is EUF-CMA secure, including against quantum adversaries at NIST category 2.
3. SHA-256 is collision- and second-preimage-resistant (key ids; ≥ 2^85 quantum collision cost is considered sufficient for identifiers bound to keys the attacker does not control).
4. The `Clock` sysvar's `unix_timestamp` is within minutes of real time.
5. The program binary corresponds to the reviewed source (reproducible builds, `docs/DEPLOYMENT.md`), and its upgrade authority is honest or removed.
6. Users verify, before depositing, that a vault's key id equals their own key id (SDKs must do this).
