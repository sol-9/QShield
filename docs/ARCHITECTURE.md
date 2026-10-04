# Architecture

QShield v0.1 is **Architecture A**: ML-DSA-44 signatures are verified directly
inside the Solana program, against a public key that was expanded once
on-chain. See `docs/MLDSA_SOLANA_FEASIBILITY.md` for why, and the ADRs in
`docs/adr/` for each decision.

## 1. Components

| Component | Path | Runs | Trust |
|-----------|------|------|-------|
| ML-DSA-44 verifier | `crates/qshield-mldsa` | on-chain and off-chain | trusted computing base |
| QSP-1 encoding | `crates/qshield-protocol` | on-chain and off-chain | trusted computing base |
| Vault program | `programs/qshield-vault` | on-chain | trusted computing base |
| Feasibility benchmark | `benchmarks/ml-dsa-solana` | dev only | — |
| Rust SDK | `crates/qshield-client` | user device / servers | holds the PQ key only on the signing device |
| CLI | `cli/` | user device, offline signer | holds the PQ key only on the signing device |
| TypeScript SDK | `sdk/typescript` | browsers, Node | same |
| Web wallet | `apps/web` (`docs/WALLET.md`) | user's browser | holds the PQ key (encrypted at rest) only in the user's browser |
| Relayer | `services/relayer` (`docs/RELAYER.md`) | anywhere | **untrusted**: holds only its fee-payer key |

## 2. Accounts

```
                    ┌────────────────────────────────────────────┐
                    │ Vault  (PDA ["vault", initial_key_id, seed])│
                    │  status · nonce · key_id · key_account      │
                    │  lamports = rent reserve + user SOL         │
                    └──────────────┬─────────────────────────────┘
                                   │ owner (authority) of
                    ┌──────────────▼─────────────────────────────┐
                    │ Token accounts (SPL Token / Token-2022),    │
                    │  usually the vault's associated token       │
                    │  accounts; moved only by Execute WithdrawSpl│
                    └────────────────────────────────────────────┘
                                   │ key_account (address)
                    ┌──────────────▼─────────────────────────────┐
                    │ Key account (keypair account, 21,976 bytes) │
                    │  state · vault · key_id · creator           │
                    │  pk (1,312) · tr · A_hat (16 KiB) · t1_hat  │
                    └────────────────────────────────────────────┘
                    ┌────────────────────────────────────────────┐
                    │ Signature buffer (PDA, optional, 2,508 B)   │
                    │  ["sigbuf", vault, creator, id]             │
                    │  state · vault · creator · signature        │
                    └────────────────────────────────────────────┘
```

* The **vault** holds SOL, and is the owner (authority) of token accounts
  holding its SPL tokens; the program signs token transfers as the vault PDA
  only after verifying a WithdrawSpl authorization (ADR-0015). Its address commits to the key it was created with,
  so nobody can create "the user's vault" with a different key.
* The **key account** holds the public key and its expansion (`A_hat`,
  `NTT(t1·2^d)`, `tr`), computed by the program from the uploaded key after the
  key bytes are checked against `key_id = SHA-256("QSHIELD_KEY_ID_V1" ‖ 0x01 ‖ pk)`.
  Once `Ready` it is immutable. It is not a PDA because the runtime limits
  account growth inside CPI to 10 KiB; the creator allocates it with a system
  `CreateAccount` and the program initializes it (requiring the key account's
  own signature). Its rent (≈ 0.154 SOL) is refunded to the creator when the
  key is rotated away or the vault closed.
* The **signature buffer** is only used when the 2,420-byte signature cannot be
  carried inline (legacy/v0 transactions).

Exact byte layouts: `programs/qshield-vault/src/state.rs` and `docs/PROTOCOL.md`.

## 3. Flows

### 3.1 Setup and deposit

```
User's Solana wallet (Ed25519)                QShield program
        │                                            │
        │ 1. allocate key account + CreateKey ──────►│ key: Writing
        │ 2. WriteKey × 2 (pk bytes)  ──────────────►│
        │ 3. FinalizeKey ───────────────────────────►│ check key_id, compute tr → Expanding
        │ 4. ExpandKey × 2 (anyone may send) ───────►│ A_hat, t1_hat → Ready (immutable)
        │ 5. InitializeVault ───────────────────────►│ vault PDA created, key in_use
        │ 6. DepositSol (or plain SOL transfer) ────►│
        ▼                                            ▼
                         Wallet
                           │  SOL
                           ▼
                     QShield vault PDA
```

The wallet only pays rent and fees. It is never recorded as an authority.

### 3.2 Withdrawal

```
 PQ secret key (user device)
        │  sign QSP-1 authorization (292 bytes) with ML-DSA-44, ctx "QSHIELD/QSP-1"
        ▼
 authorization + signature (2,420 bytes)  ── public, may be shared freely
        │
        ▼
 Relayer (untrusted) — or the user's own wallet
        │  builds a Solana transaction and pays the fee
        │   • v1 transaction: Execute(auth ‖ signature)            — 1 tx, 3,010 bytes
        │   • legacy: CreateSigBuffer, 3 × WriteSigBuffer,
        │             ExecuteWithBuffer(auth)                      — 5 txs
        ▼
 Solana runtime
        ▼
 QShield program
   decode QSP-1 → cluster / program / vault / nonce / status / clock checks
   → ML-DSA-44 verify against the vault's ready key account (≈ 828k CU)
   → nonce += 1
        ▼
 Vault PDA ──lamports──► destination   (+ signed fee ──► fee recipient)
```

### 3.3 Key rotation

The new key goes through steps 1–4 of §3.1 bound to the existing vault, then
the **current** key signs `RotateKey(new_key_id)`. The program checks the new
key account (ready, same vault, same key id and algorithm), switches the vault
to it, closes the old key account (rent to its creator) and advances the nonce.
After rotation the old key is useless (`lifecycle.rs::key_rotation`).

## 4. Trust boundary

```
 ┌──────────────────────────── TRUSTED ───────────────────────────────┐
 │  User device while signing (holds ML-DSA secret key)                │
 │  Solana runtime + QShield program + qshield-mldsa (on-chain TCB)    │
 │  Program upgrade authority (until removed — see DEPLOYMENT.md)      │
 └─────────────────────────────────────────────────────────────────────┘
 ┌─────────────────────────── UNTRUSTED ──────────────────────────────┐
 │  Relayers / fee payers / any transaction submitter                  │
 │  The user's Ed25519 wallet after vault creation                     │
 │  RPC nodes, other users, front-runners                              │
 │  Signature buffers' and key accounts' creators                      │
 └─────────────────────────────────────────────────────────────────────┘
```

## 5. Program instructions and authorization rules

| # | Instruction | Who may call | Authorization |
|---|-------------|--------------|---------------|
| 0 | CreateKey | anyone | creator + key account signatures (key account is fresh) |
| 1 | WriteKey | key creator | creator signature; only while `Writing` |
| 2 | FinalizeKey | key creator | creator signature; pk must hash to `key_id` |
| 3 | ExpandKey | anyone | none needed: deterministic computation |
| 4 | CloseKey | key creator | creator signature; key not in use |
| 5 | InitializeVault | anyone | none needed: vault address commits to the key |
| 6 | DepositSol | anyone | depositor signature; vault not closed |
| 7 | Execute | anyone (pays fee) | **ML-DSA-44 signature over QSP-1** |
| 8 | CreateSigBuffer | anyone | creator signature |
| 9 | WriteSigBuffer | buffer creator | creator signature; only before finalize |
| 10 | CloseSigBuffer | buffer creator | creator signature |
| 11 | ExecuteWithBuffer | anyone (pays fee) | **ML-DSA-44 signature over QSP-1** (from a finalized buffer) |

"Withdraw SOL", "rotate PQ key", "pause", "unpause" and "close vault" are
QSP-1 actions executed through instructions 7 and 11. No instruction moves
vault funds without a valid ML-DSA signature; there is no admin.

## 6. Repository layout and deviations from the initial plan

```
crates/qshield-mldsa       ML-DSA-44 verifier (SBF-compatible)
crates/qshield-protocol    QSP-1 encoding + key ids
programs/qshield-vault     Solana program, tests (LiteSVM)
crates/qshield-client      Rust SDK (keys, keystore, envelopes, RPC, vault ops)
cli/                       qshield CLI
sdk/typescript             TypeScript SDK
benchmarks/ml-dsa-solana   program, LiteSVM harness, validator harness, results
tests/vectors/acvp         NIST ACVP ML-DSA-44 vectors
tests/vectors/qsp1         QSP-1 known-answer vectors
tests/vectors/keystore     keystore known-answer vector
tests/vectors/sdk          Rust/TypeScript interoperability vectors
scripts/                   benchmark, stack-report and reference-encoder scripts
docs/                      specifications, reports, ADRs
```

Deviations from the suggested layout:

* `crates/qshield-crypto` is named `crates/qshield-mldsa` (it contains exactly
  one algorithm); `crates/qshield-core` is not needed yet.
* Integration and adversarial tests live in `programs/qshield-vault/tests/`
  (they need the compiled program and LiteSVM) rather than top-level
  `tests/integration` and `tests/adversarial`; top-level `tests/` holds shared
  vectors.
* The Rust SDK lives in `crates/qshield-client` (not `sdk/rust`) so it shares
  the Cargo workspace; `sdk/typescript` is the TypeScript SDK.
* `apps/web` and `services/relayer` are not built yet (Phases 4–5).
* `benchmarks/ml-dsa-solana/validator` is a separate Cargo workspace because
  the Solana RPC client and LiteSVM pin incompatible versions of shared crates.
