# ADR-0015: SPL Token / Token-2022 support and mint policy

Status: Accepted (2026-10-02)

## Context
Phase 3 enables `WithdrawSpl`, which QSP-1 has defined (fields `asset_type`,
`mint`, `destination`, `amount`, `decimals`) since v0.1 but the program
rejected. Tokens add new trust surfaces: which token program is called, which
accounts are debited and credited, what "amount" means, and Token-2022
extensions that change transfer semantics (fees, hooks running third-party
code, permanent delegates, confidential balances, pausing, UI scaling).
The specification requires verifying mint, source, destination, authority,
decimals and token program, never trusting client metadata, and failing
explicitly on unsupported Token-2022 behaviour.

## Options considered
Custody: (1) a program-owned escrow token account per mint, created by the
program; (2) any token account whose *owner* (authority) is the vault PDA,
usually the vault's associated token account.
Token-2022: (a) accept every mint; (b) deny-list dangerous extensions;
(c) allow-list extensions known not to change who can move tokens, how many
base units arrive, or whether a transfer runs third-party code.
Deposits: (i) only through a program instruction; (ii) plain transfers, plus
an optional checked `DepositSpl` instruction.
Fees: (x) token-denominated relayer fees; (y) SOL fees from the vault, as for
other actions.

## Decision
* Custody (2). The vault PDA is the token-account authority and signs
  `TransferChecked` via `invoke_signed`. The debited account is not signed:
  any vault-owned account of the mint may be used.
* Mint policy (c). SPL Token mints are accepted. Token-2022 mints are accepted
  only with MintCloseAuthority, MetadataPointer, TokenMetadata, GroupPointer,
  TokenGroup, GroupMemberPointer or TokenGroupMember. Anything else —
  including extensions this version does not know — fails with
  `UnsupportedTokenExtension`. The same policy code (`qshield_vault::token`)
  is used by the program and the Rust SDK; the TypeScript SDK reimplements it
  and is checked against shared vectors.
* `WithdrawSpl` reads the mint and token accounts from chain and checks:
  token program ↔ `asset_type`; mint key, owner, initialization, decimals;
  destination key, program, mint, not frozen, ≠ source; source program, mint,
  owner = vault, not frozen, balance. `TransferChecked` re-checks decimals.
* Deposits (ii). `DepositSpl` checks the destination belongs to a live vault
  and the mint passes the policy, so the official clients never deposit what
  the program could not withdraw.
* Fees (y). `fee_lamports` stays SOL, signed, paid from the vault's SOL above
  its rent reserve. The token CPI happens before any direct lamport movement.

## Security implications
* The Ed25519 wallet still cannot move vault tokens: only the vault PDA can
  authorize transfers out of its token accounts, and only `Execute` with a
  valid PQ signature makes the program sign as the PDA (I1, I2 extended to
  tokens; tested in `programs/qshield-vault/tests/spl.rs`).
* A relayer cannot change the mint, destination, amount, decimals or token
  program (all signed and checked); swapping the source for another
  vault-owned account of the same mint does not change the signed effect.
* Rejected Token-2022 extensions would otherwise let a third party take vault
  tokens (PermanentDelegate), run arbitrary code during a vault-signed transfer
  (TransferHook), deliver fewer base units than signed (TransferFeeConfig),
  move balances outside the public amount (Confidential*), or make signed
  amounts differ from displayed ones (InterestBearing, ScaledUiAmount).
* Tokens with a freeze authority are accepted; the issuer can freeze vault
  accounts. Clients warn on deposit.
* Tokens of unsupported mints that reach a vault-owned account by a plain
  transfer cannot be withdrawn by this version (fail closed rather than
  attempt an unsafe transfer). `CloseVault` does not sweep tokens; clients
  refuse to build a close while the vault holds tokens.

## Tradeoffs
Popular Token-2022 assets that use transfer hooks or permanent delegates are
not supported. The vault's token-account rent (≈ 0.002 SOL each) is not
recoverable in this version (no signed "close token account" action).
Compute: WithdrawSpl ≈ 833k CU (SPL Token) and ≈ 836k CU (Token-2022), the
ML-DSA verification dominating.

## Alternatives rejected
Program-created escrow accounts: an extra instruction and account type for no
security gain over vault-owned ATAs. Accepting all mints or a deny-list:
unknown future extensions would silently become trusted. Token-denominated
fees: needs a second destination and policy per mint; SOL fees already work
for every action. Program-only deposits: anyone can transfer tokens to any
account, so the program cannot rely on seeing deposits anyway.
