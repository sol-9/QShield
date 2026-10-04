# QShield keystore format (v1)

An encrypted file holding one ML-DSA-44 key. Implemented identically by the
Rust SDK (`crates/qshield-client/src/keystore.rs`, used by the CLI) and the
TypeScript SDK (`sdk/typescript/src/keystore.ts`); both are tested against
`tests/vectors/keystore/keystore-v1.json`. Decision record: ADR-0014.

> **Experimental software key storage.** It protects a file at rest against
> someone who does not know the password. It does not protect against malware,
> keyloggers or malicious browser extensions on the device where the password
> is typed, and it is not comparable to a hardware wallet.

## What is stored

Only the 32-byte ML-DSA seed `ξ` (FIPS 204 `ML-DSA.KeyGen_internal(ξ)` derives
the key pair). The public key and key id are stored in clear for convenience;
after decryption they are recomputed from the seed and must match.

## Format

```json
{
  "qshield_keystore": 1,
  "algorithm": "ML-DSA-44",
  "public_key": "<hex, 1312 bytes>",
  "key_id": "<hex, 32 bytes>",
  "kdf": {
    "name": "argon2id", "version": 19,
    "m_cost_kib": 65536, "t_cost": 3, "p_cost": 1,
    "salt": "<hex, 16 bytes>"
  },
  "cipher": { "name": "xchacha20-poly1305", "nonce": "<hex, 24 bytes>" },
  "ciphertext": "<hex, 48 bytes: 32-byte seed + 16-byte tag>"
}
```

## Algorithm

```
k   = Argon2id(password = UTF-8 bytes, salt, m = m_cost_kib, t = t_cost, p = p_cost, version 0x13, output 32 bytes)
aad = "QSHIELD_KEYSTORE_V1" ‖ 0x01 ‖ key_id ‖ u32le(m_cost_kib) ‖ u32le(t_cost) ‖ u32le(p_cost) ‖ salt
ciphertext = XChaCha20-Poly1305(k, nonce).Encrypt(seed, aad)
```

Decryption MUST:

1. reject unknown `qshield_keystore`, `algorithm`, `kdf.name`, `kdf.version`, `cipher.name`;
2. reject KDF parameters outside `8·p ≤ m_cost_kib ≤ 2,097,152` (2 GiB),
   `1 ≤ t_cost ≤ 64`, `1 ≤ p_cost ≤ 16` (bounds the work an untrusted file can demand);
3. authenticate-decrypt (any change to the header fields bound in `aad`, the
   nonce or the ciphertext fails);
4. derive the key pair from the seed and require that its key id equals
   `key_id` and its public key equals `public_key`.

Encryption uses fresh random salt and nonce from the platform CSPRNG and
refuses empty passwords. Defaults: 64 MiB, 3 passes, 1 lane.

## Backups

The keystore file **and** its password are both required. Alternatively the
seed can be exported (`qshield key export-seed`, deliberately awkward to call)
and stored offline; anyone with the seed controls every vault of that key.

## Recovery phrase v1

A key can also be backed up as **24 words** (`qshield key export-phrase`,
the web wallet's backup step; restore with `qshield key import-phrase` or
"Import"):

* the 32-byte seed ξ followed by an 8-bit checksum
  `SHA-256("QSHIELD_RECOVERY_PHRASE_V1" ‖ 0x01 ‖ ξ)[0]`, split into 24 × 11
  bits, each an index into the BIP-39 English word list (file SHA-256
  `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`);
* words may be abbreviated to their first four letters;
* the domain-separated checksum rejects ordinary BIP-39 wallet phrases (and
  wallets reject QShield phrases), avoiding mix-ups;
* the phrase **is** the key. It is never derived from a password: a
  human-chosen phrase could be guessed offline against the public key, which
  is on-chain. On restore, compare the key id with the vault's
  (`--expect-key-id`).

Vectors: `tests/vectors/recovery/recovery-v1.json` (Rust and TypeScript).
