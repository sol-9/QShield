# QShield on-chain protocol (program interface v0.1)

This document specifies the `qshield-vault` program interface: instruction
encodings, account lists, account layouts and error codes. The signed message
format is specified separately in [QSP-1](QSP-1.md).

All integers are little-endian. `s` = signer, `w` = writable.

## 1. Instructions

Instruction data is `tag:u8 ‖ payload`. Payload lengths are exact; any
trailing byte is rejected (`InvalidInstruction`).

| Tag | Name | Payload | Accounts |
|----:|------|---------|----------|
| 0 | CreateKey | `vault:32 ‖ key_id:32 ‖ algorithm:u8` (65) | `creator (s,w)`, `key_account (s,w)` |
| 1 | WriteKey | `offset:u16 ‖ bytes[1..]` | `creator (s)`, `key_account (w)` |
| 2 | FinalizeKey | — | `creator (s)`, `key_account (w)` |
| 3 | ExpandKey | `max_polys:u8` | `key_account (w)` |
| 4 | CloseKey | — | `creator (s,w)`, `key_account (w)` |
| 5 | InitializeVault | `vault_seed:32` | `payer (s,w)`, `vault (w)`, `key_account (w)`, `system_program` |
| 6 | DepositSol | `amount:u64` | `depositor (s,w)`, `vault (w)`, `system_program` |
| 7 | Execute | `auth:292 ‖ signature:2420` | `fee_payer (s,w)`, `vault (w)`, `key_account (w*)`, *action accounts* |
| 8 | CreateSigBuffer | `vault:32 ‖ buffer_id:u64` | `creator (s,w)`, `buffer (w)`, `system_program` |
| 9 | WriteSigBuffer | `offset:u16 ‖ finalize:u8 (0/1) ‖ bytes` | `creator (s)`, `buffer (w)` |
| 10 | CloseSigBuffer | — | `creator (s,w)`, `buffer (w)` |
| 11 | ExecuteWithBuffer | `auth:292` | `fee_payer (s,w)`, `vault (w)`, `key_account (w*)`, `buffer (w)`, `buffer_creator (w)`, *action accounts* |
| 13 | ExecuteV2 | `auth_v2:317 ‖ signature:2420` | `fee_payer (s,w)`, `vault (w)`, `signer_key (w*)`, `policy (w)`, *v2 action accounts* (§5) |
| 14 | ExecuteV2WithBuffer | `auth_v2:317` | `fee_payer (s,w)`, `vault (w)`, `signer_key (w*)`, `policy (w)`, `buffer (w)`, `buffer_creator (w)`, *v2 action accounts* |
| 15 | CloseProposal | — | `vault`, `proposal (w)`, `rent_payer (w)` — permissionless when the proposal is dead |
| 12 | DepositSpl | `amount:u64 ‖ decimals:u8` (9) | `depositor (s)`, `source (w)`, `mint`, `vault_token_account (w)`, `vault`, `token_program` |

`w*`: writable required only for RotateKey and CloseVault.

### 1.1 Action accounts (Execute / ExecuteWithBuffer)

| QSP-1 action | Accounts, in order |
|--------------|--------------------|
| WithdrawSol | `destination (w)` [, `fee_recipient (w)`] |
| RotateKey | `new_key_account (w)`, `old_key_creator (w)` [, `fee_recipient (w)`] |
| Pause, Unpause | [`fee_recipient (w)`] |
| CloseVault | `destination (w)`, `key_creator (w)` [, `fee_recipient (w)`] |
| WithdrawSpl | `vault_token_account (w)`, `mint`, `destination (w)`, `token_program` [, `fee_recipient (w)`] |

`fee_recipient` is passed only if `fee_lamports > 0` and the authorization's
`fee_recipient` is non-zero; with a zero `fee_recipient` the fee is paid to
`fee_payer`. Extra trailing accounts are ignored.

### 1.1.1 SPL tokens (ADR-0015)

**WithdrawSpl** checks, before the transfer:

* `token_program` is SPL Token when `asset_type = 2`, Token-2022 when `asset_type = 3`;
* `mint` is the signed `mint`, owned by `token_program`, initialized, with
  `decimals` equal to the signed `decimals` and only allow-listed Token-2022
  extensions (§1.1.2);
* `destination` is the signed `destination`, a token account of `token_program`
  for that mint, not frozen, and different from the source;
* `vault_token_account` is a token account of `token_program` for that mint
  whose owner is the vault, not frozen, holding at least `amount`.

It then CPIs `TransferChecked(amount, decimals)` signed by the vault PDA, and
pays `fee_lamports` (SOL, from the vault's balance above its rent reserve) to
the fee recipient. The source token account is not part of the signed message:
any vault-owned account of the mint may be debited; the signed effect (mint,
amount, destination) is the same.

**DepositSpl** (anyone may call it) checks that `vault` is a QShield vault that
is not closed, that `vault_token_account` is a token account of `mint` owned by
the vault, and that the mint passes the same policy, then CPIs
`TransferChecked` signed by the depositor. Clients create the vault's
associated token account (Associated Token Account `CreateIdempotent`, owner =
vault PDA) in the same transaction. Tokens can also reach a vault-owned token
account by a plain transfer; the program does not need to see deposits.

### 1.1.2 Mint policy

SPL Token mints are accepted. Token-2022 mints are accepted only if every
extension is one of: MintCloseAuthority (3), MetadataPointer (18),
TokenMetadata (19), GroupPointer (20), TokenGroup (21), GroupMemberPointer
(22), TokenGroupMember (23). Every other extension — including any unknown to
this program version — fails with `UnsupportedTokenExtension`.

### 1.2 Key setup sequence

1. `SystemProgram::CreateAccount { from: creator, to: key_account, space: 21976, owner: program }` and `CreateKey` (may share one transaction; the key account's keypair signs both).
2. `WriteKey` until all 1,312 public-key bytes are written (2 legacy transactions of ≤ 900 bytes, or 1 v1 transaction).
3. `FinalizeKey`: the program checks `SHA-256("QSHIELD_KEY_ID_V1" ‖ alg ‖ pk) == key_id` and stores `tr`.
4. `ExpandKey` until 20 polynomials are done (two transactions with `max_polys = 10`, ≈ 780k + 650k CU).
5. For a new vault: `InitializeVault` with `vault = PDA(["vault", key_id, vault_seed])` and the key's `vault` field equal to that address. For rotation: `Execute` RotateKey.

### 1.3 Buffered execution sequence (legacy transactions)

`CreateSigBuffer(vault, id)` → `WriteSigBuffer` × 3 (900-byte chunks, last with
`finalize = 1`) → `ExecuteWithBuffer`. The buffer is closed by a successful
`ExecuteWithBuffer` (rent to its creator) or explicitly by `CloseSigBuffer`.

## 2. Account layouts

Every program account starts with an 8-byte discriminator and a layout-version
byte (`1`).

### 2.1 Vault — 256 bytes, PDA `["vault", initial_key_id, vault_seed]`

| Off | Len | Field |
|----:|----:|-------|
| 0 | 8 | `QSHVAULT` |
| 8 | 1 | layout version |
| 9 | 1 | status: 1 Active, 2 Paused, 3 Closed |
| 10 | 1 | PDA bump |
| 11 | 1 | pq_algorithm (1 = ML-DSA-44) |
| 12 | 1 | threshold (1) — reserved for m-of-n |
| 13 | 1 | key_count (1) — reserved for m-of-n |
| 14 | 1 | recovery_mode (0 = none) — reserved |
| 15 | 1 | reserved |
| 16 | 8 | nonce (u64) |
| 24 | 32 | key_id |
| 56 | 32 | key_account |
| 88 | 32 | initial_key_id |
| 120 | 32 | vault_seed |
| 152 | 8 | created_slot |
| 160 | 8 | created_at (unix) |
| 168 | 88 | reserved (zero) |

### 2.2 Key account — 21,976 bytes, keypair account

| Off | Len | Field |
|----:|----:|-------|
| 0 | 8 | `QSHKEY01` |
| 8 | 1 | layout version |
| 9 | 1 | algorithm |
| 10 | 1 | state: 1 Writing, 2 Expanding, 3 Ready |
| 11 | 1 | reserved |
| 12 | 1 | in_use |
| 13 | 1 | expanded polynomial count (0–20) |
| 14 | 10 | reserved |
| 24 | 32 | vault |
| 56 | 32 | key_id |
| 88 | 32 | creator |
| 120 | 1312 | public key (FIPS 204 encoding) |
| 1432 | 64 | `tr = SHAKE256(pk, 64)` |
| 1496 | 16384 | `A_hat[r][s]`, row-major (`r*4+s`), 256 × u32 each, coefficients in `[0, q)` |
| 17880 | 4096 | `NTT(t1[r]·2^13)` for r = 0..3, 256 × u32 each |

### 2.3 Signature buffer — 2,508 bytes, PDA `["sigbuf", vault, creator, buffer_id:u64 LE]`

| Off | Len | Field |
|----:|----:|-------|
| 0 | 8 | `QSHSIGB1` |
| 8 | 1 | layout version |
| 9 | 1 | state: 1 Writing, 2 Finalized |
| 10 | 1 | PDA bump |
| 11 | 5 | reserved |
| 16 | 32 | vault |
| 48 | 32 | creator |
| 80 | 8 | buffer_id |
| 88 | 2420 | signature |

## 3. Error codes

| Code | Name | Meaning |
|-----:|------|---------|
| 0x5100 | InvalidInstruction | Instruction data malformed |
| 0x5101 | MissingAccount | Required account missing |
| 0x5102 | InvalidAccount | Wrong owner, type, size or state of an account |
| 0x5103 | MissingSignature | Required signer missing |
| 0x5104 | NotWritable | Required writable account is read-only |
| 0x5110 | MalformedAuthorization | QSP-1 decode failed |
| 0x5111 | WrongCluster | `cluster_id` mismatch |
| 0x5112 | WrongProgram | `program_id` mismatch |
| 0x5113 | WrongVault | `vault` mismatch |
| 0x5114 | WrongNonce | `nonce` ≠ vault nonce |
| 0x5115 | NotYetValid | before `valid_after` |
| 0x5116 | Expired | at/after `expires_at` |
| 0x5117 | InvalidSignature | ML-DSA verification failed |
| 0x5118 | ActionNotPermitted | Not allowed in the vault's status |
| 0x5119 | UnsupportedAction | Action defined by QSP-1 but not implemented (none since v0.3) |
| 0x511a | AccountMismatch | Account differs from authorization / state |
| 0x5120 | InsufficientFunds | amount + fee exceeds balance above rent |
| 0x5121 | Overflow | Arithmetic overflow |
| 0x5130 | WrongKeyState | Key account in the wrong state |
| 0x5131 | KeyIdMismatch | Uploaded key does not hash to key_id |
| 0x5132 | KeyInUse | Key referenced by a vault |
| 0x5133 | OutOfBounds | Write outside buffer |
| 0x5134 | WrongBufferState | Buffer in the wrong state |
| 0x5135 | UnsupportedAlgorithm | Algorithm byte not supported |
| 0x5136 | ZeroAmount | Deposit of zero |
| 0x5140 | InvalidTokenProgram | Not SPL Token / Token-2022, or not the signed asset type's program |
| 0x5141 | InvalidMint | Mint mismatch, wrong owner, uninitialized or malformed |
| 0x5142 | UnsupportedTokenExtension | Token-2022 extension outside the allow-list |
| 0x5143 | InvalidTokenAccount | Token account with wrong program, mint, owner or state |
| 0x5144 | DecimalsMismatch | Signed/passed decimals differ from the mint |
| 0x5150 | PolicyActive | Guarded vault: v1 authorizations refused / policy already enabled |
| 0x5151 | PolicyRequired | Action needs a policy, or the policy account is wrong |
| 0x5152 | LimitExceeded | Beyond the everyday allowance / unsaved token destination: propose instead |
| 0x5153 | ProposalMismatch | Approval differs from the proposal |
| 0x5154 | ProposalStale | Proposal expired or its everyday key was replaced |
| 0x5155 | PolicyFull | 8 saved addresses already |
| 0x5156 | AlreadySaved | Address already saved |
| 0x5157 | NotSaved | Address not saved |
| 0x5158 | KeyConflict | Guardian and everyday key must differ |

## 4. Compute budget

Execute and ExpandKey need an explicit compute-unit limit (≈ 840k and ≈ 800k).
In v1 transactions set it in the transaction config; in legacy transactions
use `ComputeBudgetInstruction::SetComputeUnitLimit`. v1 transactions must also
set a loaded-accounts data size limit large enough for the program and the
21,976-byte key account (observed: the v1 default was too small; 1 MiB works).

## 5. Guardian policy (QSP-1 v2, ADR-0018)

`signer_key` is the vault's key account for `role` 1 and the policy's guardian
key account for `role` 2; it must be writable for RotateGuardian and
DisablePolicy. The optional `fee_recipient (w)` always comes last.

| Action | Action accounts |
|--------|-----------------|
| WithdrawSol | `destination (w)` |
| WithdrawSpl | `vault_token_account (w)`, `mint`, `destination (w)`, `token_program` |
| ProposeWithdraw | `proposal (w)` = PDA `["proposal", vault, nonce_le]`, `system_program` |
| ApproveWithdraw | `proposal (w)`, `rent_payer (w)`, then the WithdrawSol or WithdrawSpl accounts |
| CancelProposal | `proposal (w)`, `rent_payer (w)` |
| RotateKey | `new_key (w)`, `old_key (w)` (the vault's key account), `old_key_creator (w)` |
| RotateGuardian | `new_guardian_key (w)`, `old_guardian_creator (w)` |
| EnablePolicy | `guardian_key (w)`, `system_program` (the policy PDA is created, rent from `fee_payer`) |
| Pause, Unpause, SetLimit, AddAddress, RemoveAddress, DisablePolicy | — |

### 5.1 Policy account — 512 bytes, PDA `["policy", vault]`, never closed

| Off | Len | Field |
|----:|----:|-------|
| 0 | 8 | `QSHPOL01` |
| 8 | 1 | layout version |
| 9 | 1 | bump |
| 10 | 1 | enabled |
| 11 | 1 | saved address count (≤ 8) |
| 16 | 32 | vault |
| 48 | 32 | guardian key id |
| 80 | 32 | guardian key account |
| 112 | 8 | guardian nonce |
| 120 | 8 | limit (lamports) |
| 128 | 8 | period (seconds) |
| 136 | 8 | available (lamports) |
| 144 | 8 | last refill (unix) |
| 160 | 256 | saved addresses (8 × 32) |

### 5.2 Proposal — 208 bytes, PDA `["proposal", vault, id_le]`

`id` is the vault nonce the ProposeWithdraw consumed. Fields: asset type (10),
decimals (11), vault (16), id (48), created at (56), expires at (64), proposing
key id (72), mint (104), destination (136), amount (168), rent payer (176).

### 5.3 Other layout changes

* Vault byte 14 is `policy_mode` (0 none, 1 guardian policy).
* Key account byte 12 is a role: 0 free, 1 the vault's key, 2 guardian.

