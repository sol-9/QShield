import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { address, fromHex, toHex } from '../src/bytes.js';
import type { Instruction } from '../src/instructions.js';
import * as ix from '../src/instructions.js';
import { LocalKeypair, buildLegacyTransaction, compileLegacyMessage, localSigner, setComputeUnitLimit, setComputeUnitPrice, withComputeBudget } from '../src/transaction.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/sdk/interop-v1.json', import.meta.url), 'utf8'));
const T = V.legacy_transaction;

const fromJson = (i: any): Instruction => ({
  programId: address(i.program_id),
  keys: i.accounts.map((a: any) => ({ pubkey: address(a.pubkey), isSigner: a.signer, isWritable: a.writable })),
  data: fromHex(i.data_hex),
});

describe('legacy transactions (byte-identical to solana-message)', () => {
  const payer = LocalKeypair.fromSeed(fromHex(T.payer_seed_hex));
  const keyKp = LocalKeypair.fromSeed(fromHex(T.key_account_seed_hex));
  const blockhash = address(T.blockhash);

  it('instruction builders match Rust', () => {
    const programId = address(V.program_id);
    const vault = address(V.vault_address);
    const built = [
      setComputeUnitLimit(300_000),
      ix.depositSol(programId, payer.publicKey, vault, 123_456_789n),
      ix.createKey(programId, payer.publicKey, keyKp.publicKey, vault, fromHex(V.key_id_hex), 1),
    ];
    expect(built.map((b) => toHex(b.data))).toEqual(T.instructions.map((i: any) => i.data_hex));
    const want = T.instructions.map(fromJson) as Instruction[];
    built.forEach((b, n) => {
      expect(toHex(b.programId)).toBe(toHex(want[n]!.programId));
      expect(b.keys.map((k) => [toHex(k.pubkey), k.isSigner, k.isWritable])).toEqual(want[n]!.keys.map((k) => [toHex(k.pubkey), k.isSigner, k.isWritable]));
    });
  });

  it('message compilation and signed wire format', async () => {
    const ixs = T.instructions.map(fromJson);
    const msg = compileLegacyMessage(payer.publicKey, ixs, blockhash);
    expect(toHex(msg.bytes)).toBe(T.message_hex);
    const tx = await buildLegacyTransaction(localSigner(payer), ixs, blockhash, [localSigner(keyKp)]);
    expect(toHex(tx)).toBe(T.transaction_hex);
    await expect(buildLegacyTransaction(localSigner(payer), ixs, blockhash)).rejects.toThrow(/missing signer/);
  });
});

describe('wallet signers', () => {
  const payer = LocalKeypair.generate();
  const other = LocalKeypair.generate();
  const bh = LocalKeypair.generate().publicKey;
  const dst = LocalKeypair.generate().publicKey;
  const memo = (signer: Uint8Array): Instruction => ({ programId: dst, keys: [{ pubkey: signer, isSigner: true, isWritable: true }], data: Uint8Array.of(1) });
  /** A wallet that signs whatever message it returns, optionally rewriting it first. */
  const wallet = (rewrite?: (ixs: Instruction[]) => Instruction[]) => ({
    publicKey: payer.publicKey,
    async signTransaction(tx: Uint8Array) {
      const n = tx[0]!;
      const sigs = [...Array(n)].map((_, i) => tx.slice(1 + 64 * i, 65 + 64 * i));
      if (!rewrite) {
        const m = tx.subarray(1 + 64 * n);
        sigs[0] = payer.sign(m);
        return Uint8Array.from([n, ...sigs.flatMap((s) => [...s]), ...m]);
      }
      const msg = compileLegacyMessage(payer.publicKey, rewrite([memo(payer.publicKey)]), bh);
      return Uint8Array.from([1, ...payer.sign(msg.bytes), ...msg.bytes]);
    },
  });

  it('withComputeBudget adds price and limit once', () => {
    const out = withComputeBudget([memo(payer.publicKey)], 1000n);
    expect(out.map((i) => i.data[0])).toEqual([3, 2, 1]);
    expect(withComputeBudget(out, 5n)).toHaveLength(3);
    expect(withComputeBudget([setComputeUnitLimit(9), memo(payer.publicKey)], 1n).map((i) => i.data[0])).toEqual([3, 2, 1]);
  });

  it('accepts an unchanged wallet signature', async () => {
    const tx = await buildLegacyTransaction(wallet(), [memo(payer.publicKey)], bh);
    expect(tx[0]).toBe(1);
  });

  it('accepts a sole-signer wallet that adds instructions', async () => {
    const tx = await buildLegacyTransaction(wallet((ixs) => [setComputeUnitPrice(7n), ...ixs]), [memo(payer.publicKey)], bh);
    expect(tx[0]).toBe(1);
  });

  it('rejects a rewrite when another key co-signed', async () => {
    const ixs = [memo(payer.publicKey), memo(other.publicKey)];
    await expect(buildLegacyTransaction(wallet((x) => [setComputeUnitPrice(7n), ...x]), ixs, bh, [localSigner(other)])).rejects.toThrow(/changed the transaction/);
  });

  it('rejects a rewrite that switches the fee payer', async () => {
    const thief = LocalKeypair.generate();
    const w = {
      publicKey: payer.publicKey,
      async signTransaction() {
        const msg = compileLegacyMessage(thief.publicKey, [memo(thief.publicKey)], bh);
        return Uint8Array.from([1, ...thief.sign(msg.bytes), ...msg.bytes]);
      },
    };
    await expect(buildLegacyTransaction(w, [memo(payer.publicKey)], bh)).rejects.toThrow(/changed the transaction/);
  });
});
