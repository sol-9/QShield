# QShield web wallet (`apps/web`)

A static, single-page web wallet for the QShield research preview: no backend,
no analytics, no third-party scripts. It talks only to the Solana RPC endpoint
and the relayer configured in Settings.

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

## Flows

* **Key generation** — `crypto.getRandomValues` seed, ML-DSA-44 key, encrypted
  with Argon2id (64 MiB, t = 3) + XChaCha20-Poly1305 (`docs/KEYSTORE.md`).
  Passwords shorter than 12 characters are refused.
* **Recovery phrase** — 24 words (`docs/KEYSTORE.md`), also available from
  the CLI (`qshield key export-phrase`).
* **Backup (mandatory)** — download the encrypted key file, then prove the
  backup works by selecting that file and entering its password. The app
  checks the file is byte-identical to the key (key id, salt, nonce,
  ciphertext) and decrypts it. Vault creation stays disabled until then.
  The same file works with the CLI (`qshield sign --key …`).
* **Import** — any QShield key file (CLI or web).
* **Vault creation** — 7 transactions paid by the Solana wallet (≈ 0.157 SOL
  rent): key-account setup (6) and `InitializeVault`. The vault address is
  derived from the key id and a label; "Open existing vault" finds it again.
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
* **Key rotation** — generate a new key, back it up (same mandatory
  verification), then the wallet pays for the new key account and the current
  key signs the rotation. Afterwards the old key cannot authorize anything.

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
* **Freeze**: always available on the wallet ("I think I am hacked"); only the
  guardian unfreezes.
* **Review screen**: grouped recipient display, "saved / used before / new"
  status, blocking of look-alike addresses (address poisoning), and a sign
  button that repeats the amount and recipient.
* Limits: tokens to unsaved addresses always need the guardian; up to 8 saved
  addresses (saving is guardian-only, in the guardian page or CLI); replacing
  the everyday key from a clean device uses the CLI (`qshield guardian
  replace-key`).

## Security notes

* Only encrypted key files and public data are kept in `localStorage`. A
  compromised device, page or extension can capture the password or the
  decrypted key while signing; this is software key storage, not
  hardware-grade. Use a dedicated device and browser profile.
* A strict Content-Security-Policy forbids third-party scripts, inline
  scripts, frames and form submissions. Host the built files yourself
  (`npm run build` → `dist/`) and serve them over HTTPS.
* Browser wallets sign whole transactions; the SDK checks the returned
  transaction carries exactly the message it compiled.
* The development payer (an in-memory key funded by airdrop) is refused on
  mainnet.
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
withdrawal (including a wrong-password attempt), rotation, and a withdrawal
with the new key.
