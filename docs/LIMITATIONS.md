# Known limitations (v0.1 research preview)

## Scope

* **Not quantum-proof Solana.** QShield protects authorization of assets held
  in QShield vaults. Solana's transaction signatures, consensus, every other
  program and every other account remain as they are.
* **Experimental and unaudited.** Do not use with meaningful funds.
* **Token support is restricted.** SPL Token mints and Token-2022 mints with
  only metadata, group and mint-close-authority extensions are supported
  (ADR-0015). Mints with transfer hooks, permanent delegates, transfer fees,
  confidential transfers, default-frozen accounts, non-transferability,
  interest/scaled UI amounts, pausing or unknown extensions are rejected;
  tokens of such mints sent to a vault-owned account by a plain transfer
  cannot be withdrawn by this version.
* **CloseVault does not sweep tokens.** Withdraw all tokens first (the CLI
  enforces this). Vault token-account rent (≈ 0.002 SOL each) is not
  recoverable in this version.
* **Relayer rent rule.** A relayer refuses token sends that would make it
  create the recipient's token account unless the signed fee covers that rent,
  and refuses proposals that never expire (`docs/RELAYER.md`). It does not
  close expired proposals itself yet.
* **Relayer fees are SOL.** A token withdrawal's relayer fee is paid in SOL
  from the vault; a vault with no spare SOL can still withdraw tokens with
  `fee_lamports = 0` if someone pays the transaction fee.
* **Recovery needs a backup or a guardian.** The key file (with its password),
  the 24 recovery words, or a guardian that switches the vault to a new key.
  Without any of them, losing the ML-DSA key loses the vault
  (`docs/RECOVERY_MODEL.md`).
* **Guardian policy is opt-in** (ADR-0018). Without it a vault is single-key:
  whoever holds the key (or gets one signature from it) can drain it. With it,
  the everyday key is bounded by its limit and saved addresses; a stolen
  guardian is equivalent to a stolen single key. No general m-of-n yet; no
  per-mint token limits (tokens to unsaved addresses always need approval);
  at most 8 saved addresses.
* **Client software is a research preview.** Rust SDK, CLI, TypeScript SDK,
  a reference relayer and a web wallet exist. The relayer keeps request
  history in memory only and rate-limits per IP (best effort). The web wallet
  stores the encrypted key in browser storage: a compromised browser or
  extension can capture it while it is unlocked; it supports one vault per
  key, SOL/token send and receive, freeze/unfreeze, key replacement, guardian
  flows and recovery, but not CloseVault (use the CLI). Activity shows the
  current session only, and tokens are shown by mint address (no metadata).
  Key storage is
  password-encrypted software storage (`docs/KEYSTORE.md`), not hardware.
* **TypeScript SDK sends through a relayer.** It produces instructions and
  submission plans, and `RelayerClient` submits signed envelopes to a relayer;
  it does not serialize v1 transactions (SIMD-0385) itself.

## Trust

* The program is **upgradeable** during development; its Ed25519 upgrade
  authority can replace it (`docs/DEPLOYMENT.md` §3).
* `qshield-mldsa` is new cryptographic code. It passes NIST ACVP vectors and
  differential tests against two independent implementations, but has not been
  externally reviewed.

## Protocol / program behaviour

* **Sequential nonces.** One authorization at a time per vault (QSP-1 §7.1).
* **Clock precision.** Validity windows use `Clock::unix_timestamp`, which may
  drift by seconds; use windows of minutes.
* **Closed vaults are tombstones.** Lamports sent to a closed vault (by plain
  transfer) are unrecoverable. The vault account's own rent reserve
  (≈ 0.0027 SOL) stays locked forever, so the address can never be reused.
* **Key account rent.** ≈ 0.154 SOL per key, refunded to the key account's
  creator on rotation away from the key or on vault close.
* **Transaction format.** Single-transaction withdrawals need v1 transactions
  (SIMD-0385). Legacy/v0 clients use 5 transactions per withdrawal.
* **Compute.** Each authorization consumes ≈ 830k CU (≈ 59 % of the 1.4M
  per-transaction cap). Priority fees scale with requested CU. An action cannot
  be composed in the same transaction with another CU-heavy instruction.
* **CPI.** Other programs can invoke `Execute` (the PQ signature still governs);
  there is no CPI-friendly "smart account" interface yet.
* **Cluster binding at build time.** Each binary serves exactly one cluster.
* **Genesis hashes** in `crates/qshield-protocol` match `solana genesis-hash`
  for mainnet-beta, devnet and testnet (checked 2026-10-04).

## Token-2022

Implemented as an allow-list (ADR-0015, `docs/PROTOCOL.md` §1.1.2). Candidates
for future support, each needing its own analysis: TransferFeeConfig with the
fee included in the signed authorization; TransferHook with an allow-list of
hook programs; ScaledUiAmount/InterestBearing with UI-amount rendering.

## Not done in this release (tracked as issues)

Devnet deployment;
container-reproducible builds; hardware/enclave signers; recovery and multisig
designs.
