# ADR-0018: Guardian policy and QSP-1 v2 (instant, no delays)

Status: Accepted (2026-10-02). Amends ADR-0007 (nonce model: a second nonce
lane) and ADR-0008 (recovery: the guardian replaces a lost or stolen key).

## Context
With one key, malware that steals it — or merely gets one signature — can
drain a vault in one transaction. Client-side storage cannot prevent this on
an infected device (red-team review, `THREAT_MODEL.md`). A requirement: Solana
is used for speed, so **no time delays on transfers**. One ML-DSA-44
verification costs ≈ 830k of 1.4M CU, so a transaction can check only one
signature.

## Options considered
1. Time-delayed withdrawals cancellable by a guardian (rejected: delays).
2. Spending limit only (bounded loss but no way to make large sends).
3. Destination allowlist only.
4. 2-of-2 for everything (two devices for every coffee).
5. Hybrid: limit + allowlist for the everyday key, guardian co-approval for
   the rest, guardian as recovery authority — all instant.
6. Two keys with equal power (any disagreement deadlocks the vault).

## Decision
Option 5, opt-in per vault (`EnablePolicy`, signed by the everyday key with
the guardian's key id and the limit):

| Who | Instantly, alone |
|-----|------------------|
| everyday key | SOL within a refilling allowance (`limit` per `period`, fees included); any amount to saved addresses; tokens to saved addresses (destination token account's owner); freeze; lower the limit; remove addresses; cancel proposals |
| guardian | approve a proposal (restating its exact effect); unfreeze; replace the everyday key; save addresses; any limit; rotate itself; disable the policy |
| both | anything else: the everyday key proposes (a proposal PDA), the guardian approves — two transactions, seconds apart |

The guardian never moves funds by itself except by approving a proposal made
by the current everyday key. Each role has its own nonce, so a thief burning
everyday nonces cannot invalidate a guardian's (possibly pre-signed) freeze.
Guarded vaults accept only QSP-1 v2 (317 bytes, domain
`QSHIELD_SOLANA_AUTH_V2`): v1 messages signed before the policy cannot bypass
it. Replacing the everyday key kills its proposals. The policy account is
never closed, so guardian nonces are never reused across disable/re-enable.

## Security implications
* Stolen everyday key: loss bounded by `limit + limit·t/period` over the time
  `t` until the guardian freezes (one transaction) and replaces the key; sends
  to saved addresses go only to the user's own accounts. It cannot unfreeze,
  raise limits, save addresses, change keys or use v1.
* Stolen guardian: equivalent to a stolen single key (it can replace the
  everyday key). Keep it offline — paper or a separate device.
* Both stolen: loss. Both lost: the everyday key keeps sending within limits
  and to saved addresses; nothing else can change (users should save one of
  their own cold addresses when enabling).
* Invariants I11–I13 in `docs/SECURITY_MODEL.md`.

## Tradeoffs
A second key account (≈ 0.154 SOL rent, refundable) and a policy account
(≈ 0.0045 SOL). Large sends take two signatures on two devices. Tokens to
unsaved addresses always need approval (no per-mint limits yet). Up to 8
saved addresses.

## Alternatives rejected
Delays (product requirement). Equal-power keys (deadlock under the common
case of a stolen hot key). m-of-n for everything (UX). Per-mint token limits
(more state; deferred).
