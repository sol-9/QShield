# Recovery model

## v0.1: no recovery

A QShield v0.1 vault is controlled by exactly one ML-DSA-44 key. **If that key
is lost, the funds in the vault are lost.** If it is stolen, the thief controls
the vault. There is no administrator, no Ed25519 fallback, no time-locked
backdoor.

This is deliberate. The project's rule is: *it is better to have no recovery
than an insecure backdoor disguised as recovery.* In particular, using the
user's ordinary Ed25519 Solana wallet as a recovery authority would make the
vault exactly as quantum-vulnerable as the wallet, defeating the purpose.

What v0.1 does offer:

* **Key rotation**, authorized by the current key, to move to a new key (e.g.
  after migrating devices, or on suspicion of exposure while the key is still
  under the user's control).
* **Pause**, authorized by the key, to block withdrawals until an Unpause. With
  a single key this does not protect against a thief who has the key (they can
  unpause); it is a self-imposed lock.
* **Cancellation** of an outstanding signed authorization by executing any
  other authorization for the same nonce.

Users of v0.1 must back up the ML-DSA key (or its 32-byte seed) offline.

## Future policies (not implemented)

The vault layout reserves `threshold`, `key_count` and `recovery_mode`
fields so these can be added without migrating existing vaults:

| Policy | Idea | Main risk to analyse |
|--------|------|----------------------|
| Secondary PQ recovery key | A second ML-DSA key that can only `RotateKey` | Recovery key compromise = vault compromise |
| Time-delayed recovery | Recovery key starts a rotation that executes only after N days unless the primary key cancels | Liveness of the user during the delay; clock assumptions |
| m-of-n PQ multisig (2-of-3, 3-of-5) | QSP-1 authorization signed by m registered keys | CU budget: each signature ≈ 828k CU, so multi-signature needs multi-transaction verification or a cheaper verifier |
| PQ guardians | Social recovery with guardians' PQ keys | Guardian collusion, coordination |
| Cold-storage recovery key | Offline key, used rarely | Physical security |

Each requires an ADR (recovery model and nonce model changes are listed as
ADR-mandatory in the project rules) and its own adversarial tests.

Note on multisig cost: one ML-DSA-44 verification uses ≈ 59 % of a transaction's
compute budget, so a 2-of-3 policy cannot verify two signatures in one
transaction with the current verifier. Options include per-signature
verification transactions that record approvals in an account (state machine
bound to the authorization hash and nonce) — to be designed.
