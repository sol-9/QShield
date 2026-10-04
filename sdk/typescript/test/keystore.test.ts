import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../src/bytes.js';
import { LocalKey } from '../src/keys.js';
import { INSECURE_TEST_KDF, decryptKey, encryptKey, type KeystoreFile } from '../src/keystore.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/keystore/keystore-v1.json', import.meta.url), 'utf8'));

describe('keystore interoperability with the Rust SDK', () => {
  it('decrypts the Rust-generated vector', async () => {
    const key = await decryptKey(V.keystore, V.password);
    expect(toHex(key.exportSeed())).toBe(V.seed_hex);
    expect(toHex(key.keyId)).toBe(V.key_id_hex);
  });

  it('produces byte-identical files for identical inputs', async () => {
    const key = LocalKey.fromSeed(fromHex(V.seed_hex));
    const f = await encryptKey(key, V.password, INSECURE_TEST_KDF, { salt: fromHex(V.keystore.kdf.salt), nonce: fromHex(V.keystore.cipher.nonce) });
    expect(f.ciphertext).toBe(V.keystore.ciphertext);
    expect(f.public_key).toBe(V.keystore.public_key);
  });

  it('rejects wrong passwords and tampering', async () => {
    await expect(decryptKey(V.keystore, 'wrong')).rejects.toThrow();
    const t1: KeystoreFile = { ...V.keystore, kdf: { ...V.keystore.kdf, t_cost: 2 } };
    await expect(decryptKey(t1, V.password)).rejects.toThrow();
    const t2: KeystoreFile = { ...V.keystore, key_id: '00'.repeat(32) };
    await expect(decryptKey(t2, V.password)).rejects.toThrow();
    const t3: KeystoreFile = { ...V.keystore, kdf: { ...V.keystore.kdf, m_cost_kib: 2 ** 31 } };
    await expect(decryptKey(t3, V.password)).rejects.toThrow(/KDF/);
  });

  it('round-trips a fresh key', async () => {
    const key = LocalKey.generate();
    const f = await encryptKey(key, 'pw', INSECURE_TEST_KDF);
    const back = await decryptKey(JSON.parse(JSON.stringify(f)), 'pw');
    expect(toHex(back.publicKey)).toBe(toHex(key.publicKey));
    await expect(encryptKey(key, '', INSECURE_TEST_KDF)).rejects.toThrow();
  });
});
