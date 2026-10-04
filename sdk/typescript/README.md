# @qshield/sdk (TypeScript)

TypeScript SDK for QShield — **experimental research preview, unaudited**.
QShield does not make Solana quantum-resistant; it adds an ML-DSA-44
authorization layer for assets held in QShield vaults.

Provides:

* **QSP-1** encoding/decoding with the canonical field rules (`encode`, `decode`, `keyId`, `CLUSTER`).
* **ML-DSA-44 keys** generated locally with `crypto.getRandomValues` (fails if unavailable); hedged signing; `PqSigner` interface for hardware/offline signers.
* **Encrypted keystore** compatible with the Rust SDK/CLI (`docs/KEYSTORE.md`).
* **Authorization envelopes** for offline signing, compatible with the CLI (`docs/OFFLINE_SIGNING.md`).
* **PDAs, account parsers and instruction builders** (`docs/PROTOCOL.md`), framework-neutral.
* **`QShield` client**: chain reads over JSON-RPC, intent builders, and submission plans (`planSubmission`) for v1-inline or legacy-buffered transports.
* **SPL Token / Token-2022**: `getMint` (applies the program's mint policy), `planDepositSpl`, `createWithdrawSplIntent`, token account parsing, associated token addresses and exact decimal amounts (`parseTokenAmount`, `formatTokenAmount`).

Dependencies: `@noble/post-quantum` (ML-DSA), `@noble/hashes` (SHA-256, Argon2id),
`@noble/ciphers` (XChaCha20-Poly1305), `@noble/curves` (PDA curve check),
`@scure/base`. All MIT, pinned exactly.

```ts
import { QShield, JsonRpc, LocalKey, CLUSTER, signEnvelope, address } from '@qshield/sdk';

const qshield = new QShield({ rpc: new JsonRpc(url), programId: PROGRAM_ID, clusterId: CLUSTER.devnet });
await qshield.checkCluster();

const vault = await qshield.getVaultChecked(vaultAddress, key.keyId);    // before depositing
const unsigned = await qshield.prepare(vaultAddress, (nonce) =>
  qshield.createWithdrawSolIntent({ vault: vaultAddress, nonce, destination: address(dest), lamports: 10_000_000n }));
const signed = await signEnvelope(unsigned, key);                       // show unsigned.fields to the user first
const txs = await qshield.planSubmission(signed, feePayer, 'inline');   // send with your transaction library or a relayer
```

Sending: `RelayerClient` submits a signed envelope to a QShield relayer
(`docs/RELAYER.md`), which pays the fees:

```ts
const relayer = new RelayerClient('https://relayer.example');
const id = await relayer.submit(signed);
const result = await relayer.wait(id);   // { status: 'confirmed', signatures } or { status: 'failed', error }
```

Not included yet: serializing v1 transactions (SIMD-0385) directly, vault
creation helpers.

## Browser key storage

`encryptKey`/`decryptKey` protect a key file at rest. In a browser, a
compromised page or malicious extension can read the password or the
decrypted key. Do not treat browser storage as hardware-wallet-grade.

## Tests

```bash
npm ci
npm run typecheck
npm test     # QSP-1 vectors, keystore and Rust interop vectors; also cross-checks
             # TS-signed envelopes with the Rust CLI if target/release/qshield exists
```
