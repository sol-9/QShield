# QShield web wallet (`apps/web`)

A static, single-page web wallet for the QShield research preview: no backend,
no analytics, no third-party scripts. It talks only to the Solana RPC endpoint
and the relayer configured in Settings (or pinned at build time, as in the
devnet beta). Phone-sized layout with Home, Activity, Security and Settings
tabs; light and dark themes (Auto follows the device).

> Experimental and unaudited. Do not use with meaningful funds. QShield does
> not make Solana quantum-resistant; it protects assets held in QShield vaults.

## Two keys

| | QShield key (post-quantum) | Solana wallet |
|---|---|---|
| Algorithm | ML-DSA-44 | Ed25519 |
| Where | generated in this browser; stored only encrypted | your wallet extension (Wallet Standard) or a development payer on test networks |
| Can | authorize withdrawals, rotation | pay rent and fees, deposit |
| Cannot | — | withdraw, rotate, or change the vault in any way |

Withdrawals and rotations are sent through a relayer (`docs/RELAYER.md`):
the relayer pays the network fee and cannot change what was signed.

## First run

A guided sequence: **create key → back it up → connect a Solana wallet →
create the vault** ("Step n of 4"). The welcome screen names the three
parties (vault key, Solana wallet, relayer). Steps that need the chain stop at
a "Connect to the QShield network" box until a valid program id is set. On
localnet a one-click test wallet (airdropped) is offered; on devnet the
wallet points to Phantom/Solflare in Devnet mode and faucet.solana.com.

## Flows

* **Key generation** — `crypto.getRandomValues` seed, ML-DSA-44 key, encrypted
  with Argon2id (64 MiB, t = 3) + XChaCha20-Poly1305 (`docs/KEYSTORE.md`).
  Passwords shorter than 12 characters are refused.
* **Recovery words** — Settings → Recovery words (or during backup): after the
  password, the 24 words of the vault key are shown once and four are quizzed;
  then they count as a backup. They are the key itself, without a password,
  and never stored. Same words as `qshield key export-phrase` /
  `import-phrase`.
* **Backup (mandatory)** — download the encrypted key file, then prove the
  backup works by selecting that file and entering its password. The app
  checks the file is byte-identical to the key (key id, salt, nonce,
  ciphertext) and decrypts it. Vault creation stays disabled until then.
  The same file works with the CLI (`qshield sign --key …`).
* **Restore** — from any QShield key file (CLI or web) or from the 24 recovery
  words (with a new password for this browser).
* **Vault creation** — 7 transactions paid by the Solana wallet (≈ 0.157 SOL
  rent): key-account setup (6) and `InitializeVault`. The vault address is
  derived from the **initial** key id and a name; "Open existing vault" finds
  it by name, or by its address once the key has been replaced.
* **Balances / receive** — SOL above the rent reserve and every token account
  owned by the vault. Receiving SOL: send to the vault address. Tokens: use
  Deposit (checks the mint is supported) or send to the vault's associated
  token account.
* **Deposit** — SOL or tokens, from the connected wallet, after checking the
  vault is controlled by your key.
* **Send** — SOL or a supported token to a recipient wallet (tokens go to its
  associated token account, created by the relayer if missing). The review
  screen shows every field computed from the exact bytes to be signed; the
  relayer's fee (from its `/v1/info`) is signed explicitly to the relayer's
  address. Signing decrypts the key in memory only for that signature.
* **Freeze / unfreeze** — Security tab. On a single-key vault the vault key
  can unfreeze; on a guarded vault only the guardian can.
* **Replace the vault key** (single-key vaults, Security tab, "Step n of 3"):
  create the new key, back it up, then switch: the **current** key signs the
  rotation, so the current password is required. A half-made replacement can
  be cancelled. Afterwards the old key cannot authorize anything.
* **Change password** — Settings: re-encrypts the same key under a new
  password; nothing on chain changes. Old key files still open with the old
  password, so the backup is marked out of date (recovery words stay valid).
* **Recover on a new computer** — "Lost your computer? Recover your vault":
  with the key file or the 24 words, restore and open the vault (by address if
  the key was ever replaced); with a guardian, create a new key here, set it
  up on the vault (≈ 0.154 SOL refundable rent), and send the guardian a link
  with four match words; the guardian switches the vault to the new key.

## Guardian protection (ADR-0018)

**Why:** malware on the computer that holds your everyday key can use that key.
A guardian — a second post-quantum key that never touches that computer —
limits what such malware can do, without slowing normal payments.

| Situation | What happens | Speed |
|---|---|---|
| Send to a saved address | everyday key alone | instant |
| Send within the daily limit (e.g. 1 SOL/24 h) | everyday key alone | instant |
| Anything else | proposed in the wallet, approved on the guardian page | seconds (two transactions) |
| "I think I'm hacked" | Freeze (everyday key or guardian) | instant |
| Unfreeze, save an address, raise the limit, replace a key | guardian | instant |

* **Setup** ("Add a guardian"): the wallet shows 24 words to write on paper and
  quizzes four of them; the browser then forgets the guardian secret and keeps
  only its public key. Alternatively, create the guardian on another device
  and import its key file (public part only). Your Solana wallet pays the
  guardian key account's rent (≈ 0.16 SOL, refundable); your everyday key signs.
* **Approving**: a proposal shows a link (open it on the guardian device) and a
  four-word match code. The guardian page reads the proposal **from the
  chain**, shows the amount, the recipient and the same match code, asks for
  the last four characters of a new recipient, and approves through the
  relayer. The guardian device needs no SOL.
* **Freeze**: always available on the wallet ("Think your key is stolen?");
  only the guardian unfreezes.
* **Replace the everyday key** (guardian page): checks the new key account on
  chain (Ready, this vault, not in use, not the guardian), shows its four match
  words, then signs the rotation. Works while frozen.
* **Review screen**: grouped recipient display, "saved / used before / new"
  status, blocking of look-alike addresses (address poisoning), and a sign
  button that repeats the amount and recipient.
* Limits: tokens to unsaved addresses always need the guardian; up to 8 saved
  addresses (saving is guardian-only, in the guardian page or CLI).

## Security notes

* Only encrypted key files and public data are kept in `localStorage`. A
  compromised device, page or extension can capture the password or the
  decrypted key while signing; this is software key storage, not
  hardware-grade. Use a dedicated device and browser profile.
* A strict Content-Security-Policy forbids third-party scripts, inline
  scripts, frames and form submissions. A `<meta>` CSP cannot forbid framing,
  so hosts must also send the headers from `scripts/build-site.sh`
  (`frame-ancestors 'none'`, `connect-src` limited to the RPC and relayer).
* Browser wallets sign whole transactions; the SDK checks the returned
  transaction carries exactly the message it compiled.
* The test wallet (an in-memory key funded by airdrop) exists only on
  localnet.
* Settings may be pre-filled from the URL (`?rpc=…&program=…&cluster=…&relayer=…`);
  keys never are. Check the cluster badge and program id before depositing.

## Development

```bash
cd sdk/typescript && npm ci && cd ../../apps/web && npm ci
npm run dev            # http://localhost:5173
npm test               # unit tests
npm run build          # dist/
```

`scripts/cli-e2e.sh` runs a Playwright test against `solana-test-validator`
and `qshield-relayer`: key generation with real KDF parameters, verified
backup, a Wallet Standard wallet creating the vault and depositing, a relayed
withdrawal (including a wrong-password attempt), freeze and unfreeze,
cancelled and completed rotation, password change, recovery words and a
restore on a fresh browser; and the guardian flow: limit, proposal and
approval on a second device, freeze/unfreeze, and recovery of the vault on a
new computer through the guardian.
