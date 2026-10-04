# `qshield` command-line interface

Experimental research preview. Build with `cargo build --release -p qshield-cli`
(binary: `target/release/qshield`).

## Global options

| Option | Env | Default | Meaning |
|--------|-----|---------|---------|
| `--url` | `QSHIELD_RPC_URL` | `http://127.0.0.1:8899` | Solana JSON-RPC endpoint |
| `--program-id` | `QSHIELD_PROGRAM_ID` | — | QShield program |
| `--cluster` | `QSHIELD_CLUSTER` | `localnet` | Cluster the program was built for; the CLI refuses an RPC endpoint whose genesis hash differs (except localnet) |
| `--password-env VAR` | — | prompt | Read key-file passwords from an environment variable (scripts/tests) |

## Commands

| Command | Network | Purpose |
|---------|---------|---------|
| `keygen --out FILE` | no | Generate an ML-DSA-44 key from the OS CSPRNG; write an encrypted key file (`docs/KEYSTORE.md`). Refuses to overwrite; file mode 0600. Prints the key id. |
| `key info FILE [--public-key]` | no | Key id (no password needed). |
| `key export-seed FILE --i-understand-this-reveals-my-secret-key` | no | Print the 32-byte seed for offline backup. |
| `vault address --key FILE [--label L \| --seed HEX]` | no | Vault PDA for a key and seed. |
| `vault create --key FILE --payer KEYPAIR [--label L]` | yes | Key setup (6 txs) + `InitializeVault`. The payer gains no authority. Asks for the key file's password: the public key is taken from the decrypted key, never from the file's plaintext header. |
| `vault info VAULT [--key FILE]` | yes | State, nonce, key id, balance; with `--key`, fails unless the vault is controlled by that key. |
| `deposit-sol --vault V --payer KEYPAIR --amount SOL [--key FILE]` | yes | Deposit (check the key first with `--key`). |
| `deposit-spl --vault V --payer KEYPAIR --mint M --amount TOKENS [--key FILE]` | yes | Deposit tokens from the payer's associated token account through `DepositSpl`; creates the vault's token account if needed. Unsupported mints are refused (ADR-0015); freeze authorities are reported. |
| `auth withdraw-sol \| withdraw-spl \| rotate-key \| pause \| unpause \| close …  --out FILE` | optional | Build an unsigned authorization. Offline with `--nonce` and `--signer-key-id`/`--key`. Options: `--expires-in` (default 3600 s, 0 = never), `--valid-in`, `--fee`, `--fee-recipient`. |
| `sign FILE --key KEYFILE [--yes]` | no | Show every field (computed from the signed bytes), confirm, sign. |
| `verify FILE` | no | Check consistency and signature. |
| `submit FILE --payer KEYPAIR [--transport inline\|buffered]` | yes | Submit a signed file. Checks nonce, key and signature first so invalid submissions cost nothing. `inline` = one v1 transaction; `buffered` = 5 legacy transactions. |
| `submit FILE --relayer URL [--transport …]` | yes | Send the signed file to a relayer (`docs/RELAYER.md`), which pays the fees; waits for confirmation. Also `QSHIELD_RELAYER_URL`. |
| `withdraw …` | yes | `auth withdraw-sol` + `sign` + `submit` in one step. |
| `withdraw-spl --key FILE --vault V --mint M --to WALLET --amount TOKENS --payer KEYPAIR` | yes | `auth withdraw-spl` + `sign` + `submit`. Tokens go to the recipient's associated token account, created by the payer if missing. |
| `rotate-key --key OLD --new-key NEW --vault V --payer KEYPAIR` | yes | Set up the new key account, sign RotateKey with the old key, submit. Both key files are decrypted (two password prompts). |
| `benchmark [--iterations N]` | no | Local keygen/sign/verify timing. |

### Guardian policy (ADR-0018)

| Command | Purpose |
|---------|---------|
| `guardian enable --key EVERYDAY --guardian GUARDIAN --vault V --key-payer KEYPAIR --limit SOL [--period-hours 24]` | Set up the guardian key account and attach the policy (everyday key signs). |
| `guardian show VAULT` | Limit, available allowance, saved addresses, nonces. |
| `send --key EVERYDAY --vault V --to WALLET --amount A [--mint M]` | Instant if within the limit / to a saved address; otherwise creates a proposal and prints its number. |
| `guardian approve --key GUARDIAN --vault V --proposal N [--to-owner WALLET]` | Shows the proposal's exact effect, signs, submits. |
| `guardian freeze` / `unfreeze` / `cancel` / `add-address` / `remove-address` / `set-limit` / `replace-key` / `replace-guardian` / `disable` | Policy management (`--as-guardian` where either key may sign). |

Every guardian command takes `--payer KEYPAIR`, `--relayer URL`, or
`--out FILE` (write the unsigned authorization for offline signing with
`qshield sign`, then `qshield submit`). `key export-phrase` /
`key import-phrase [--expect-key-id]` back up and restore keys as 24 words.

Amounts are SOL with up to 9 decimals, or tokens with up to the mint's
decimals, parsed exactly (no floating point).

`auth withdraw-spl` takes `--mint`, `--amount`, and either `--to WALLET`
(destination = that wallet's associated token account; the file carries a
`destination_owner` hint so the submitter can create it) or
`--to-token-account`. Offline (`--nonce`) it also needs `--decimals` and
`--token-program spl|token2022`, which the program checks against the mint.

`auth close` refuses while the vault holds tokens (they would be lost), and in
offline mode, where balances cannot be checked, unless `--allow-token-loss`.
`vault info` lists the vault's token accounts.

## Example: the MVP flow on a local validator

```bash
export QSHIELD_PROGRAM_ID=<deployed program> QSHIELD_CLUSTER=localnet
qshield keygen --out key.json
VAULT=$(qshield vault create --key key.json --payer wallet.json)
qshield deposit-sol --vault $VAULT --payer wallet.json --amount 0.1 --key key.json
qshield withdraw --key key.json --vault $VAULT --to <DEST> --amount 0.01 --payer relayer.json
```

`scripts/cli-e2e.sh` runs this plus replay, tampering, offline signing,
buffered submission, a theft attempt, rotation and close against a real
`solana-test-validator`.

## Safety notes

* The secret key exists in clear only in memory during `sign`, `withdraw`,
  `rotate-key` and `key export-seed`. It is never logged or transmitted.
* Every command that hands a vault to a key (`vault create`, `rotate-key`,
  `guardian enable`, `guardian replace-key`, `guardian replace-guardian`)
  decrypts that key file first. Its plaintext `public_key`/`key_id` fields are
  not authenticated, so an edited file could otherwise hand the vault to
  someone else's key, or to a key nobody can sign with.
* `sign` always displays the rendering it computes from the authorization
  bytes; a file whose displayed fields disagree with its bytes is rejected.
* Use `--expires-in` (on by default) so forgotten authorizations die.
