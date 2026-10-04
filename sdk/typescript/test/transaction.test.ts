import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { address, fromHex, toHex } from '../src/bytes.js';
import type { Instruction } from '../src/instructions.js';
import * as ix from '../src/instructions.js';
import { LocalKeypair, buildLegacyTransaction, compileLegacyMessage, localSigner, setComputeUnitLimit } from '../src/transaction.js';

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
