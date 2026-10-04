/**
 * Encrypted key files, interoperable with the Rust SDK and CLI
 * (docs/KEYSTORE.md): Argon2id(password) -> XChaCha20-Poly1305 over the
 * 32-byte seed, with all header fields bound as associated data.
 *
 * EXPERIMENTAL software key storage: protects a file at rest against someone
 * who does not know the password. In a browser it does not protect against
 * malicious extensions or a compromised page; it is not a hardware wallet.
 */
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2idAsync } from '@noble/hashes/argon2.js';
import { concat, equal, fromHex, toHex, utf8 } from './bytes.js';
import { LocalKey, secureRandom } from './keys.js';

export interface KdfParams {
  mCostKib: number;
  tCost: number;
  pCost: number;
}

/** 64 MiB, 3 passes, 1 lane (same as the Rust SDK). */
export const DEFAULT_KDF: KdfParams = { mCostKib: 64 * 1024, tCost: 3, pCost: 1 };
/** For tests only. */
export const INSECURE_TEST_KDF: KdfParams = { mCostKib: 64, tCost: 1, pCost: 1 };

export interface KeystoreFile {
  qshield_keystore: 1;
  algorithm: 'ML-DSA-44';
  public_key: string;
  key_id: string;
  kdf: { name: 'argon2id'; version: 19; m_cost_kib: number; t_cost: number; p_cost: number; salt: string };
  cipher: { name: 'xchacha20-poly1305'; nonce: string };
  ciphertext: string;
}

const AAD_DOMAIN = utf8('QSHIELD_KEYSTORE_V1');

function u32le(v: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, v, true);
  return b;
}

function aad(keyId: Uint8Array, p: KdfParams, salt: Uint8Array): Uint8Array {
  return concat(AAD_DOMAIN, Uint8Array.of(1), keyId, u32le(p.mCostKib), u32le(p.tCost), u32le(p.pCost), salt);
}

function checkParams(p: KdfParams): void {
  const ok =
    Number.isInteger(p.mCostKib) &&
    Number.isInteger(p.tCost) &&
    Number.isInteger(p.pCost) &&
    p.mCostKib >= 8 * Math.max(1, p.pCost) &&
    p.mCostKib <= 2 * 1024 * 1024 &&
    p.tCost >= 1 &&
    p.tCost <= 64 &&
    p.pCost >= 1 &&
    p.pCost <= 16;
  if (!ok) throw new Error('keystore: unsupported KDF parameters');
}

async function derive(password: string, salt: Uint8Array, p: KdfParams): Promise<Uint8Array> {
  checkParams(p);
  return argon2idAsync(utf8(password), salt, { m: p.mCostKib, t: p.tCost, p: p.pCost, dkLen: 32, maxmem: 2 ** 32 - 1 });
}

/** Encrypts a key. Use `DEFAULT_KDF` outside tests. */
export async function encryptKey(
  key: LocalKey,
  password: string,
  params: KdfParams = DEFAULT_KDF,
  saltAndNonce?: { salt: Uint8Array; nonce: Uint8Array },
): Promise<KeystoreFile> {
  if (password.length === 0) throw new Error('keystore: empty password');
  const salt = saltAndNonce?.salt ?? secureRandom(16);
  const nonce = saltAndNonce?.nonce ?? secureRandom(24);
  const k = await derive(password, salt, params);
  const seed = key.exportSeed();
  try {
    const ct = xchacha20poly1305(k, nonce, aad(key.keyId, params, salt)).encrypt(seed);
    return {
      qshield_keystore: 1,
      algorithm: 'ML-DSA-44',
      public_key: toHex(key.publicKey),
      key_id: toHex(key.keyId),
      kdf: { name: 'argon2id', version: 19, m_cost_kib: params.mCostKib, t_cost: params.tCost, p_cost: params.pCost, salt: toHex(salt) },
      cipher: { name: 'xchacha20-poly1305', nonce: toHex(nonce) },
      ciphertext: toHex(ct),
    };
  } finally {
    seed.fill(0);
    k.fill(0);
  }
}

/** Decrypts a key file. Throws on a wrong password or any tampering. */
export async function decryptKey(file: KeystoreFile, password: string): Promise<LocalKey> {
  if (
    file.qshield_keystore !== 1 ||
    file.algorithm !== 'ML-DSA-44' ||
    file.kdf?.name !== 'argon2id' ||
    file.kdf.version !== 19 ||
    file.cipher?.name !== 'xchacha20-poly1305'
  ) {
    throw new Error('keystore: unsupported format');
  }
  const params = { mCostKib: file.kdf.m_cost_kib, tCost: file.kdf.t_cost, pCost: file.kdf.p_cost };
  const salt = fromHex(file.kdf.salt);
  const nonce = fromHex(file.cipher.nonce);
  const keyId = fromHex(file.key_id);
  if (salt.length !== 16 || nonce.length !== 24 || keyId.length !== 32) throw new Error('keystore: bad field length');
  const k = await derive(password, salt, params);
  let seed: Uint8Array;
  try {
    seed = xchacha20poly1305(k, nonce, aad(keyId, params, salt)).decrypt(fromHex(file.ciphertext));
  } catch {
    throw new Error('keystore: wrong password or corrupted file');
  } finally {
    k.fill(0);
  }
  try {
    const key = LocalKey.fromSeed(seed);
    if (!equal(key.keyId, keyId) || toHex(key.publicKey) !== file.public_key.toLowerCase()) {
      key.destroy();
      throw new Error('keystore: public key does not match the encrypted seed');
    }
    return key;
  } finally {
    seed.fill(0);
  }
}
