# QSP-1 — QShield Signing Protocol, version 1

| | |
|---|---|
| Status | Draft (research preview v0.1). Breaking changes require a new protocol version and an ADR. |
| Reference implementation | `crates/qshield-protocol` (Rust); independent encoder `scripts/qsp1_reference.py` |
| Test vectors | `tests/vectors/qsp1/qsp1-vectors.json` |

The key words MUST, MUST NOT, SHOULD and MAY are to be interpreted as in RFC 2119.

## 1. Purpose

QSP-1 defines the exact byte string a user signs with a post-quantum key to
authorize one action on one QShield vault, how it is signed, and how a
verifier decides whether it is valid. Any wallet, hardware device, custodian
or CLI that follows this document produces authorizations that every other
QSP-1 implementation (and the QShield program) accepts or rejects identically.

## 2. Overview

```
authorization = Encode(fields)                      # 292 bytes, §4
signature     = ML-DSA-44.Sign(sk, authorization, ctx = "QSHIELD/QSP-1")   # 2,420 bytes, §6
```

A verifier accepts iff **all** of the following hold:

1. `authorization` decodes under §4–§5 (length, domain, version, known enums, canonical per-action fields);
2. `ML-DSA-44.Verify(pk, authorization, signature, ctx = "QSHIELD/QSP-1")` is true for the vault's current key (§6);
3. the policy checks of §7 hold (cluster, program, vault, nonce, validity window, action-specific rules).

## 3. Conventions

* Integers are unsigned little-endian (`u8`, `u16`, `u64`) or two's-complement little-endian (`i64`).
* `bytes32` is a raw 32-byte value: a Solana address, a genesis hash or a SHA-256 digest. Solana addresses are their 32 raw bytes (not base58).
* "Zero" for a `bytes32` means 32 zero bytes.
* Every field has a fixed length. There are no length prefixes, optional fields or padding; the encoding of a given set of field values is unique.

## 4. Layout

| Offset | Size | Field | Type | Description |
|-------:|-----:|-------|------|-------------|
| 0 | 22 | `domain` | bytes | ASCII `QSHIELD_SOLANA_AUTH_V1` (`51 53 48 49 45 4c 44 5f 53 4f 4c 41 4e 41 5f 41 55 54 48 5f 56 31`) |
| 22 | 2 | `version` | u16 | `1` |
| 24 | 32 | `cluster_id` | bytes32 | Genesis hash of the target cluster (§8) |
| 56 | 32 | `program_id` | bytes32 | Address of the QShield program instance |
| 88 | 32 | `vault` | bytes32 | Vault account address |
| 120 | 1 | `action` | u8 | §5 |
| 121 | 1 | `asset_type` | u8 | `0` none, `1` SOL, `2` SPL Token, `3` Token-2022 |
| 122 | 8 | `nonce` | u64 | Must equal the vault's current nonce |
| 130 | 8 | `valid_after` | i64 | Unix seconds; `0` = no lower bound |
| 138 | 8 | `expires_at` | i64 | Unix seconds; `0` = no expiry |
| 146 | 32 | `mint` | bytes32 | Token mint (SPL actions) |
| 178 | 32 | `destination` | bytes32 | Recipient system account (SOL) or token account (SPL) |
| 210 | 8 | `amount` | u64 | Lamports (SOL) or token base units (SPL) |
| 218 | 1 | `decimals` | u8 | Mint decimals (SPL actions) |
| 219 | 32 | `fee_recipient` | bytes32 | Recipient of `fee_lamports`; zero = the transaction fee payer |
| 251 | 8 | `fee_lamports` | u64 | Lamports paid from the vault to `fee_recipient` |
| 259 | 32 | `new_key_id` | bytes32 | Key id of the replacement key (RotateKey) |
| 291 | 1 | `new_algorithm` | u8 | Algorithm of the replacement key (RotateKey) |
| 292 | | | | **End. Total length: 292 bytes.** |

Decoders MUST reject any input that is not exactly 292 bytes, whose `domain`
differs, whose `version` is not `1`, or whose `action` / `asset_type` is not a
value listed in this document.

## 5. Actions and canonical field rules

For each action, fields marked **0** MUST be zero, fields marked **≠0** MUST be
non-zero, and `—` means any value. A decoder MUST reject an authorization that
violates these rules (error `NonCanonical`). This makes every field either
meaningful or fixed, so no bits are "free" for a relayer to tamper with.

| `action` | Name | `asset_type` | `mint` | `destination` | `amount` | `decimals` | `new_key_id` | `new_algorithm` |
|---|---|---|---|---|---|---|---|---|
| 1 | WithdrawSol | 1 | 0 | ≠0 | ≠0 | 0 | 0 | 0 |
| 2 | WithdrawSpl | 2 or 3 | ≠0 | ≠0 | ≠0 | — | 0 | 0 |
| 3 | RotateKey | 0 | 0 | 0 | 0 | 0 | ≠0 | a defined algorithm (§6) |
| 4 | Pause | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 5 | Unpause | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| 6 | CloseVault | 1 | 0 | ≠0 | 0 | 0 | 0 | 0 |

Rules for all actions:

* If `fee_lamports == 0` then `fee_recipient` MUST be zero.
* `valid_after` and `expires_at` MUST be ≥ 0.
* If `expires_at != 0` then `expires_at > valid_after` (error `Window`).

Action semantics (enforced by the program, §7):

* **WithdrawSol** — transfer exactly `amount` lamports from the vault to `destination`, plus exactly `fee_lamports` to the fee recipient. The vault must remain rent-exempt.
* **WithdrawSpl** — transfer exactly `amount` base units of `mint` (whose decimals must equal `decimals`) from a vault-owned token account of the token program named by `asset_type` (`2` SPL Token, `3` Token-2022) to the token account `destination`, plus exactly `fee_lamports` of SOL to the fee recipient. The program applies a mint policy and fails closed on unsupported Token-2022 extensions (`docs/PROTOCOL.md` §1.1.1–1.1.2, ADR-0015). Executed since program v0.3; v0.1 rejected it (`UnsupportedAction`). The message format is unchanged.
* **RotateKey** — replace the vault's key with the ready key account whose key id is `new_key_id` and algorithm `new_algorithm`.
* **Pause / Unpause** — block / re-enable withdrawals.
* **CloseVault** — send every lamport above the vault's rent-exempt reserve (minus `fee_lamports`) to `destination` and mark the vault permanently closed. `amount` is zero because the exact balance is generally unknown at signing time; the authorization commits to "everything".

## 6. Signature

* Algorithm: **ML-DSA-44**, FIPS 204, *pure* mode (`ML-DSA.Sign`, Algorithm 2; `ML-DSA.Verify`, Algorithm 3). **HashML-DSA is not used**; the 292-byte authorization itself is the message `M`.
* Context string `ctx`: the 13 ASCII bytes `QSHIELD/QSP-1` (`51 53 48 49 45 4c 44 2f 51 53 50 2d 31`). Per FIPS 204 the signed message representative is `mu = SHAKE256(tr ‖ 0x00 ‖ 0x0d ‖ "QSHIELD/QSP-1" ‖ authorization, 64)`.
* Public key: 1,312 bytes; signature: 2,420 bytes (FIPS 204 encodings). Any other length is invalid.
* Signers SHOULD use the hedged (randomized) variant of ML-DSA.Sign. Deterministic signing is valid and is used only to make test vectors reproducible.
* Algorithm identifiers: `1` = ML-DSA-44 (as above). No other value is defined in QSP-1.

### 6.1 Key identifier

```
key_id = SHA-256( "QSHIELD_KEY_ID_V1" ‖ algorithm (1 byte) ‖ public_key )
```

`"QSHIELD_KEY_ID_V1"` is 17 ASCII bytes. SHA-256 is used here (not SHAKE)
because it is available as a cheap Solana syscall; key ids are identifiers,
not signatures.

## 7. Verification policy

A QShield program instance MUST, for every authorization, in any order but all
before changing state:

1. Decode the authorization (§4, §5).
2. Require `cluster_id` = the cluster the program binary was built for (§8).
3. Require `program_id` = its own program address.
4. Require `vault` = the vault account being operated on.
5. Require `nonce` = the vault's current nonce.
6. Require the action to be permitted in the vault's status (Active: all except Unpause; Paused: Unpause and RotateKey; Closed: none).
7. Read the clock (`Clock` sysvar, `unix_timestamp`) and require `valid_after == 0 || now >= valid_after` and `expires_at == 0 || now < expires_at`.
8. Verify the ML-DSA-44 signature (§6) under the vault's current key.
9. Require every account the action touches to match the authorization (destination, fee recipient, new key account; for WithdrawSpl also the mint, its decimals and the token program, read from chain — never from client metadata).

On success it MUST increment the nonce by exactly one and perform exactly the
authorized action. On any failure the transaction fails and no state changes
(Solana transactions are atomic).

### 7.1 Replay protection and concurrency

The nonce is a single per-vault counter. An authorization is valid only for
the nonce value it carries, so it can execute at most once. Consequences:

* Authorizations for the same vault are **strictly sequential**. Signing nonce
  *n+1* before *n* has executed is allowed, but *n+1* only becomes executable
  after *n*.
* Two different authorizations signed for the same nonce are mutually
  exclusive: whichever lands first wins, the other fails with `WrongNonce`.
  This is the way to **cancel** a pending authorization: execute any other
  authorization (e.g. Pause) for the same nonce.
* A vault address can never be re-initialised (closed vaults stay as
  tombstones), so the nonce sequence of an address never restarts.

Unordered nonces (for concurrent, independent payments) are deliberately not
part of QSP-1 v1.

### 7.2 Clock

The program uses the `Clock` sysvar's `unix_timestamp`, a stake-weighted
estimate of wall-clock time that can drift from real time by up to several
seconds, and that is bounded but not exact. Implementations SHOULD choose
validity windows of minutes, not seconds. Expiry is a liveness guard (limits
how long a leaked or forgotten authorization stays usable); the nonce, not the
clock, is the replay protection.

## 8. Cluster identifiers

`cluster_id` is the cluster's genesis hash (raw 32 bytes):

| Cluster | Genesis hash (base58) |
|---------|------------------------|
| mainnet-beta | `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` |
| devnet | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |
| testnet | `4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY` |
| local test validators | ASCII `QSHIELD-LOCALNET-NOT-A-REAL-NET!` (sentinel; local genesis hashes are random) |

Implementers MUST confirm these with `solana genesis-hash --url <cluster>`
before relying on them. Solana programs cannot read the genesis hash at run
time, so a QShield binary is compiled for exactly one cluster (feature
`cluster-*`), and its build documentation states which. A signature for
devnet therefore never authorizes anything on mainnet, even for a program
deployed at the same address with the same keys.

## 9. Domain separation summary

| Replay across | Prevented by |
|---------------|--------------|
| clusters | `cluster_id` (§8) |
| QShield deployments / program versions at different addresses | `program_id` |
| vaults | `vault` |
| actions | `action` + canonical field rules |
| protocols (other uses of the same ML-DSA key) | ML-DSA context `QSHIELD/QSP-1` **and** in-message `domain` |
| time | `nonce` (always), `valid_after`/`expires_at` (optional) |
| QSP versions | `version` + `domain` suffix `_V1` |

## 10. Test vectors

`tests/vectors/qsp1/qsp1-vectors.json` contains:

* `keys[]`: `xi_hex` (FIPS 204 key-generation seed), `public_key_hex`, `key_id_hex`;
* `vectors[]`: `name`, `description`, `key` (index into `keys`), `fields` (positive vectors; integers > 2^53 as decimal strings), `auth_hex`, `auth_sha256` (convenience digest; not part of the protocol), `mu_hex` (the FIPS 204 message representative, to debug ML-DSA integrations), `signature_hex`, and `expected` = `{ decode: "ok" | <error>, signature_valid: bool }`.

Negative vectors cover modified amount, destination, nonce and cluster;
wrong key; empty ML-DSA context; flipped, truncated and padded signatures;
wrong domain and version; non-canonical fields; truncated authorization.
Signatures in the file are deterministic (`rnd = 0^32`).

Validate an implementation by (a) encoding each positive vector's `fields`
and comparing with `auth_hex`, (b) decoding every `auth_hex` and comparing with
`expected.decode`, and (c) verifying every signature and comparing with
`expected.signature_valid`.

## 11. Version 2: guardian policy (ADR-0018)

Vaults with a guardian policy accept only version 2 authorizations. Version 1
remains valid, unchanged, for vaults without a policy.

### 11.1 Layout (317 bytes)

Bytes 0–291 are the version 1 layout of §4, except `domain` =
`QSHIELD_SOLANA_AUTH_V2` (22 ASCII bytes) and `version` = `2`. Appended:

| Offset | Size | Field | Type | Description |
|-------:|-----:|-------|------|-------------|
| 292 | 1 | `role` | u8 | `1` everyday key, `2` guardian key |
| 293 | 8 | `ref_id` | u64 | Proposal id (ApproveWithdraw, CancelProposal) |
| 301 | 8 | `limit_lamports` | u64 | Spending limit (EnablePolicy, SetLimit) |
| 309 | 8 | `limit_period` | i64 | Seconds, 3,600 ≤ p ≤ 2,592,000 (EnablePolicy, SetLimit) |

`nonce` is the signing role's nonce: the vault nonce for the everyday key, the
policy's guardian nonce for the guardian. The ML-DSA context is unchanged
(§6); the different domain and version make v1 and v2 messages disjoint.

### 11.2 Actions

`T` = transfer fields as in v1 (`asset_type` 1/2/3, `mint` per asset,
`destination` ≠ 0, `amount` ≠ 0, `decimals` 0 for SOL). `A` = saved-address
fields (`asset_type` 0, `destination` ≠ 0, other asset fields 0). `K` =
`new_key_id` ≠ 0 with a defined `new_algorithm`. `L` = `limit_lamports` any,
`limit_period` in range. Every field not listed MUST be zero.

| `action` | Name | `role` | Fields |
|---|---|---|---|
| 1 | WithdrawSol | 1 | T with `asset_type` 1 |
| 2 | WithdrawSpl | 1 | T with `asset_type` 2/3 |
| 3 | RotateKey (everyday key) | 2 | K |
| 4 | Pause | 1 or 2 | — |
| 5 | Unpause | 2 | — |
| 7 | ProposeWithdraw | 1 | T |
| 8 | ApproveWithdraw | 2 | T, `ref_id` ≠ 0 |
| 9 | CancelProposal | 1 or 2 | `ref_id` ≠ 0 |
| 10 | EnablePolicy | 1 | K (guardian), L |
| 11 | SetLimit | 1 or 2 | L |
| 12 | AddAddress | 2 | A |
| 13 | RemoveAddress | 1 or 2 | A |
| 14 | RotateGuardian | 2 | K |
| 15 | DisablePolicy | 2 | — |

Action 6 (CloseVault) does not exist in v2: disable the policy first. Fee
rules and the validity window are as in §5.

### 11.3 Policy semantics (enforced by the program)

* Everyday WithdrawSol: if `destination` is not saved, `amount` counts against
  the allowance. Fees always count, for both roles (a guardian authorization
  with a fee above the allowance fails). The allowance refills
  continuously (`limit` per `limit_period`, capped at `limit`).
* Everyday WithdrawSpl: only if the destination token account's owner is a
  saved address (fee counts against the allowance).
* ProposeWithdraw creates the proposal `["proposal", vault, nonce]`;
  ApproveWithdraw must restate its asset, mint, destination, amount and
  decimals, and fails if the proposing everyday key has since been replaced or
  the proposal expired (`expires_at` of the proposing authorization).
* SetLimit by the everyday key may only lower `limit` with the same period.
* Frozen (Paused) vaults accept only guardian actions and the everyday
  CancelProposal, SetLimit (lower) and RemoveAddress, all with
  `fee_lamports = 0`.
* Test vectors: `tests/vectors/qsp1/qsp1-v2-vectors.json`.

