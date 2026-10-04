import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../src/bytes.js';
import { verifyAuthorization } from '../src/keys.js';
import { Action, AssetType, CLUSTER, OFFSETS, Qsp1Error, ZERO32, decode, encode, keyId, type Authorization } from '../src/qsp1.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/qsp1/qsp1-vectors.json', import.meta.url), 'utf8'));

function fromFields(f: any): Authorization {
  return {
    clusterId: fromHex(f.cluster_id),
    programId: fromHex(f.program_id),
    vault: fromHex(f.vault),
    action: f.action,
    assetType: f.asset_type,
    nonce: BigInt(f.nonce),
    validAfter: BigInt(f.valid_after),
    expiresAt: BigInt(f.expires_at),
    mint: fromHex(f.mint),
    destination: fromHex(f.destination),
    amount: BigInt(f.amount),
    decimals: f.decimals,
    feeRecipient: fromHex(f.fee_recipient),
    feeLamports: BigInt(f.fee_lamports),
    newKeyId: fromHex(f.new_key_id),
    newAlgorithm: f.new_algorithm,
  };
}

describe('QSP-1 known-answer vectors', () => {
  const keys: Uint8Array[] = V.keys.map((k: any) => fromHex(k.public_key_hex));

  it('key ids', () => {
    V.keys.forEach((k: any, i: number) => expect(toHex(keyId(keys[i]!))).toBe(k.key_id_hex));
  });

  for (const v of V.vectors) {
    it(v.name, () => {
      const auth = fromHex(v.auth_hex);
      if (v.fields) expect(toHex(encode(fromFields(v.fields)))).toBe(v.auth_hex);
      let got = 'ok';
      try {
        const d = decode(auth);
        expect(toHex(encode(d))).toBe(v.auth_hex);
      } catch (e) {
        expect(e).toBeInstanceOf(Qsp1Error);
        got = (e as Qsp1Error).code;
      }
      expect(got).toBe(v.expected.decode);
      expect(verifyAuthorization(keys[v.key]!, auth, fromHex(v.signature_hex))).toBe(v.expected.signature_valid);
    });
  }
});

describe('QSP-1 canonical rules', () => {
  const base: Authorization = {
    clusterId: CLUSTER.devnet,
    programId: new Uint8Array(32).fill(1),
    vault: new Uint8Array(32).fill(2),
    action: Action.WithdrawSol,
    assetType: AssetType.Sol,
    nonce: 1n,
    validAfter: 0n,
    expiresAt: 0n,
    mint: ZERO32,
    destination: new Uint8Array(32).fill(3),
    amount: 5n,
    decimals: 0,
    feeRecipient: ZERO32,
    feeLamports: 0n,
    newKeyId: ZERO32,
    newAlgorithm: 0,
  };
  it('rejects non-canonical and out-of-range values', () => {
    expect(() => encode({ ...base, amount: 0n })).toThrow(Qsp1Error);
    expect(() => encode({ ...base, mint: new Uint8Array(32).fill(1) })).toThrow(Qsp1Error);
    expect(() => encode({ ...base, feeRecipient: new Uint8Array(32).fill(1) })).toThrow(Qsp1Error);
    expect(() => encode({ ...base, validAfter: 10n, expiresAt: 10n })).toThrow(Qsp1Error);
    expect(() => encode({ ...base, amount: 1n << 64n })).toThrow(RangeError);
    expect(() => encode({ ...base, vault: new Uint8Array(31) })).toThrow(TypeError);
  });
  it('every single-byte change of a valid encoding is rejected or changes meaning', () => {
    const b = encode(base);
    for (let i = 0; i < OFFSETS.end; i++) {
      const m = Uint8Array.from(b);
      m[i] = (m[i]! + 1) & 0xff;
      try {
        expect(toHex(encode(decode(m)))).not.toBe(toHex(b));
      } catch (e) {
        expect(e).toBeInstanceOf(Qsp1Error);
      }
    }
  });
});
