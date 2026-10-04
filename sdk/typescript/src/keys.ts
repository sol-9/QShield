/**
 * ML-DSA-44 keys. Keys are derived from a 32-byte seed (FIPS 204
 * `KeyGen_internal`); only the seed needs to be stored (encrypted, see
 * keystore.ts). Secret material is never logged or sent anywhere by this SDK.
 */
import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js';
import { ML_DSA_CONTEXT, decode, keyId } from './qsp1.js';
import { isQspAuthorization } from './qsp1v2.js';

/** Signs QSP-1 authorizations. Implement this for hardware / offline signers. */
export interface PqSigner {
  readonly publicKey: Uint8Array;
  readonly keyId: Uint8Array;
  signAuthorization(auth: Uint8Array): Promise<Uint8Array>;
}

/** Cryptographically secure random bytes; throws if no CSPRNG is available (never falls back). */
export function secureRandom(n: number): Uint8Array {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (!c || typeof c.getRandomValues !== 'function') {
    throw new Error('secure randomness unavailable: refusing to generate keys or signatures');
  }
  return c.getRandomValues(new Uint8Array(n));
}

/** An ML-DSA-44 key held in memory. */
export class LocalKey implements PqSigner {
  readonly publicKey: Uint8Array;
  readonly keyId: Uint8Array;
  #seed: Uint8Array;
  #secretKey: Uint8Array;

  private constructor(seed: Uint8Array) {
    if (seed.length !== 32) throw new Error('seed must be 32 bytes');
    const { publicKey, secretKey } = ml_dsa44.keygen(seed);
    this.#seed = Uint8Array.from(seed);
    this.#secretKey = secretKey;
    this.publicKey = publicKey;
    this.keyId = keyId(publicKey);
  }

  /** New key from the platform CSPRNG. */
  static generate(): LocalKey {
    const seed = secureRandom(32);
    try {
      return new LocalKey(seed);
    } finally {
      seed.fill(0);
    }
  }

  /** Key from a 32-byte seed. */
  static fromSeed(seed: Uint8Array): LocalKey {
    return new LocalKey(seed);
  }

  /** The secret seed. Handle with care. */
  exportSeed(): Uint8Array {
    return Uint8Array.from(this.#seed);
  }

  /** Hedged ML-DSA-44 signature with the QSP-1 context. */
  async signAuthorization(auth: Uint8Array): Promise<Uint8Array> {
    // Only canonical QSP-1 v1/v2 authorizations are ever signed.
    if (!isQspAuthorization(auth, decode)) throw new Error('refusing to sign: not a canonical QSP-1 authorization');
    return ml_dsa44.sign(auth, this.#secretKey, { context: ML_DSA_CONTEXT, extraEntropy: secureRandom(32) });
  }

  /** Best-effort wipe of secret material held by this object. */
  destroy(): void {
    this.#seed.fill(0);
    this.#secretKey.fill(0);
  }

  toJSON(): unknown {
    return { keyId: Array.from(this.keyId, (x) => x.toString(16).padStart(2, '0')).join('') };
  }
}

/** Verifies a QSP-1 signature (pure ML-DSA-44, context "QSHIELD/QSP-1"). */
export function verifyAuthorization(publicKey: Uint8Array, auth: Uint8Array, signature: Uint8Array): boolean {
  try {
    return ml_dsa44.verify(signature, auth, publicKey, { context: ML_DSA_CONTEXT });
  } catch {
    return false;
  }
}
