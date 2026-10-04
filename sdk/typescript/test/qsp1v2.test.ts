import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../src/bytes.js';
import { createEnvelopeV2, describeV2, parseEnvelope, signEnvelope } from '../src/envelope.js';
import { LocalKey, verifyAuthorization } from '../src/keys.js';
import { Qsp1Error, keyId } from '../src/qsp1.js';
import { ActionV2, Role, decodeV2, encodeV2, type AuthorizationV2 } from '../src/qsp1v2.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/qsp1/qsp1-v2-vectors.json', import.meta.url), 'utf8'));

function fromFields(f: any): AuthorizationV2 {
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
    role: f.role,
    refId: BigInt(f.ref_id),
    limitLamports: BigInt(f.limit_lamports),
    limitPeriod: BigInt(f.limit_period),
  };
}

describe('QSP-1 v2 (shared vectors with Rust and Python)', () => {
  const pk = fromHex(V.key.public_key_hex);
  it('key id', () => expect(toHex(keyId(pk))).toBe(V.key.key_id_hex));

  it('valid vectors: encode, decode, verify', () => {
    let n = 0;
    for (const v of V.vectors.filter((x: any) => x.expected === 'ok')) {
      const a = fromFields(v.fields);
      expect(toHex(encodeV2(a)), v.name).toBe(v.auth_hex);
      expect(toHex(encodeV2(decodeV2(fromHex(v.auth_hex))))).toBe(v.auth_hex);
      expect(verifyAuthorization(pk, fromHex(v.auth_hex), fromHex(v.signature_hex)), v.name).toBe(true);
      n++;
    }
    expect(n).toBe(14);
  });

  it('rejected vectors fail with the same error class', () => {
    for (const v of V.vectors.filter((x: any) => x.expected !== 'ok')) {
      let err: unknown;
      try {
        decodeV2(fromHex(v.auth_hex));
      } catch (e) {
        err = e;
      }
      expect(err, v.name).toBeInstanceOf(Qsp1Error);
      expect((err as Qsp1Error).code, v.name).toBe(v.expected);
    }
  });

  it('v2 envelopes render, sign and verify; keys refuse non-QSP bytes', async () => {
    const k = LocalKey.generate();
    const a = fromFields(V.vectors.find((x: any) => x.name === 'enable_policy').fields);
    const e = createEnvelopeV2(a, k.keyId);
    expect(e.fields.role).toBe('everyday key');
    expect(e.fields.limit).toBe('1.000000000 SOL per 86400 seconds');
    expect(e.fields).toEqual(describeV2(a));
    const signed = await signEnvelope(e, k);
    parseEnvelope(JSON.stringify(signed));
    const tampered = structuredClone(signed);
    tampered.fields.limit = '100.000000000 SOL per 86400 seconds';
    expect(() => parseEnvelope(JSON.stringify(tampered))).toThrow(/fields/);
    await expect(k.signAuthorization(new Uint8Array(317))).rejects.toThrow(/refusing/);
    // A guardian-only action cannot be built with the everyday role.
    expect(() => encodeV2({ ...a, action: ActionV2.Unpause, role: Role.Everyday, newKeyId: new Uint8Array(32), newAlgorithm: 0, limitLamports: 0n, limitPeriod: 0n })).toThrow(Qsp1Error);
  });
});

describe('v2 renderings match the Rust SDK', () => {
  it('describeV2', () => {
    const I = JSON.parse(readFileSync(new URL('../../../tests/vectors/sdk/interop-v1.json', import.meta.url), 'utf8'));
    expect(I.renderings_v2.length).toBe(6);
    for (const r of I.renderings_v2) expect(describeV2(decodeV2(fromHex(r.auth_hex)))).toEqual(r.fields);
  });
});
