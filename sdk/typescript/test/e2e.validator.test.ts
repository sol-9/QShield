/**
 * TypeScript SDK end to end against solana-test-validator and a running
 * qshield-relayer. Skipped unless QSHIELD_E2E_RPC, QSHIELD_E2E_PROGRAM and
 * QSHIELD_E2E_RELAYER are set (scripts/cli-e2e.sh sets them).
 */
import { describe, expect, it } from 'vitest';
import { address, toBase58 } from '../src/bytes.js';
import { JsonRpc, QShield } from '../src/client.js';
import { createEnvelope, signEnvelope } from '../src/envelope.js';
import { LocalKey } from '../src/keys.js';
import { VaultOperations } from '../src/ops.js';
import { vaultSeedFromLabel } from '../src/pda.js';
import { CLUSTER } from '../src/qsp1.js';
import { RelayerClient } from '../src/relayer.js';
import { LocalKeypair, localSigner } from '../src/transaction.js';

const RPC = process.env.QSHIELD_E2E_RPC;
const PROGRAM = process.env.QSHIELD_E2E_PROGRAM;
const RELAYER = process.env.QSHIELD_E2E_RELAYER;

describe.skipIf(!RPC || !PROGRAM || !RELAYER)('TypeScript SDK against a validator and relayer', () => {
  it('creates a vault from a browser-style payer, deposits, withdraws via the relayer, rotates', async () => {
    const rpc = new JsonRpc(RPC!);
    const q = new QShield({ rpc, programId: address(PROGRAM!), clusterId: CLUSTER.localnet });
    const ops = new VaultOperations(q, rpc);
    const payerKp = LocalKeypair.generate();
    const payer = localSigner(payerKp);
    await rpc.requestAirdrop(payer.publicKey, 2_000_000_000n);
    for (let i = 0; i < 60 && (await rpc.getAccount(payer.publicKey)) === null; i++) await new Promise((r) => setTimeout(r, 500));

    const key = LocalKey.generate();
    const steps: string[] = [];
    const [vault] = await ops.createVault(payer, key.publicKey, vaultSeedFromLabel('ts-e2e'), (p) => steps.push(`${p.step}/${p.total} ${p.label}`));
    expect(steps).toEqual([
      '1/7 create key account',
      '2/7 upload public key',
      '3/7 upload public key',
      '4/7 verify key id',
      '5/7 expand key',
      '6/7 expand key',
      '7/7 initialize vault',
    ]);
    await ops.depositSol(payer, vault, 100_000_000n, key.keyId);
    let b = await ops.balances(vault);
    expect(b.vault.available).toBe(100_000_000n);
    expect(b.tokens).toEqual([]);

    // Withdraw through the relayer: the payer wallet is not involved.
    const dest = LocalKeypair.generate().publicKey;
    const relayer = new RelayerClient(RELAYER!);
    const unsigned = await q.prepare(vault, (nonce) => q.createWithdrawSolIntent({ vault, nonce, destination: dest, lamports: 7_000_000n }));
    const id = await relayer.submit(await signEnvelope(unsigned, key));
    const done = await relayer.wait(id, 60_000, 300);
    expect(done.status, JSON.stringify(done)).toBe('confirmed');
    expect((await rpc.getAccount(dest))!.lamports).toBe(7_000_000n);

    // Rotation: the wallet pays for the new key account; the old PQ key signs.
    const newKey = LocalKey.generate();
    const newAcct = await ops.setupKey(payer, vault, newKey.publicKey);
    const rot = await q.prepare(vault, (nonce) => q.createRotateKeyIntent({ vault, nonce, newKeyId: newKey.keyId }));
    rot.hints = { new_key_account: toBase58(newAcct) };
    const rid = await relayer.submit(await signEnvelope(rot, key));
    expect((await relayer.wait(rid, 60_000, 300)).status).toBe('confirmed');
    b = await ops.balances(vault);
    expect(toBase58(b.vault.state.keyId)).toBe(toBase58(newKey.keyId));
    // The old key is no longer accepted (refused before any fee is spent).
    const stale = createEnvelope(q.createWithdrawSolIntent({ vault, nonce: b.vault.state.nonce, destination: dest, lamports: 1_000_000n }), key.keyId);
    const sid = await relayer.submit(await signEnvelope(stale, key));
    expect((await relayer.wait(sid, 60_000, 300)).status).toBe('failed');
  }, 300_000);
});
