import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { BufferState, KeyState, VaultStatus, parseKeyHeader, parseSigBufferHeader, parseVault } from '../src/accounts.js';
import { address, fromHex, toBase58, toHex } from '../src/bytes.js';
import { QShield, type RpcLike } from '../src/client.js';
import { createEnvelope, describe as render, envelopeToJson, parseEnvelope, signEnvelope } from '../src/envelope.js';
import { LocalKey } from '../src/keys.js';
import { sigBufferAddress, vaultAddress, vaultSeedFromLabel } from '../src/pda.js';
import { CLUSTER, decode } from '../src/qsp1.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/sdk/interop-v1.json', import.meta.url), 'utf8'));

const programId = address(V.program_id);
const key = LocalKey.fromSeed(fromHex(V.key_seed_hex));

describe('Rust <-> TypeScript interoperability', () => {
  it('key id', () => expect(toHex(key.keyId)).toBe(V.key_id_hex));

  it('PDA derivations', () => {
    const [vault, bump] = vaultAddress(programId, key.keyId, fromHex(V.vault_seed_hex));
    expect(toBase58(vault)).toBe(V.vault_address);
    expect(bump).toBe(V.vault_bump);
    const [buf, bbump] = sigBufferAddress(programId, vault, address(V.sig_buffer.creator), BigInt(V.sig_buffer.buffer_id));
    expect(toBase58(buf)).toBe(V.sig_buffer.address);
    expect(bbump).toBe(V.sig_buffer.bump);
    expect(vaultSeedFromLabel('default')).toHaveLength(32);
  });

  it('account layouts', () => {
    const v = parseVault(fromHex(V.accounts.vault_hex));
    expect(v.status).toBe(VaultStatus.Paused);
    expect(v.nonce).toBe(42n);
    expect(toHex(v.keyId)).toBe(V.key_id_hex);
    expect(v.createdSlot).toBe(123_456_789n);
    expect(v.createdAt).toBe(1_790_000_000n);
    expect([v.threshold, v.keyCount, v.recoveryMode]).toEqual([1, 1, 0]);
    const k = parseKeyHeader(fromHex(V.accounts.key_account_header_hex));
    expect(k.state).toBe(KeyState.Ready);
    expect(k.inUse).toBe(true);
    expect(k.expanded).toBe(20);
    expect(toHex(k.publicKey!)).toBe(toHex(key.publicKey));
    const b = parseSigBufferHeader(fromHex(V.accounts.sig_buffer_header_hex));
    expect(b.state).toBe(BufferState.Finalized);
    expect(b.bufferId).toBe(BigInt(V.sig_buffer.buffer_id));
    expect(() => parseVault(fromHex(V.accounts.sig_buffer_header_hex))).toThrow();
  });

  it('envelope signed by Rust parses, renders identically and verifies', () => {
    const e = parseEnvelope(JSON.stringify(V.envelope));
    expect(e.signature_hex).toBeDefined();
    for (const r of V.renderings) expect(render(decode(fromHex(r.auth_hex)))).toEqual(r.fields);
    const tampered = structuredClone(V.envelope);
    tampered.fields.amount = '0.000000001 SOL';
    expect(() => parseEnvelope(JSON.stringify(tampered))).toThrow(/fields/);
    const badSig = structuredClone(V.envelope);
    badSig.signature_hex = badSig.signature_hex.replace(/^../, 'ff');
    expect(() => parseEnvelope(JSON.stringify(badSig))).toThrow(/signature/);
  });

  it('TypeScript-signed envelope verifies in TypeScript and with the Rust CLI', async () => {
    const unsigned = structuredClone(V.envelope);
    delete unsigned.signature_hex;
    delete unsigned.public_key_hex;
    const signed = await signEnvelope(parseEnvelope(JSON.stringify(unsigned)), key);
    expect(signed.signature_hex).not.toBe(V.envelope.signature_hex); // hedged signing
    parseEnvelope(envelopeToJson(signed));
    const other = LocalKey.generate();
    await expect(signEnvelope(parseEnvelope(JSON.stringify(unsigned)), other)).rejects.toThrow(/expected signer/);

    const cli = new URL('../../../target/release/qshield', import.meta.url).pathname;
    if (!existsSync(cli)) {
      console.warn('skipping Rust CLI cross-check: build with `cargo build --release -p qshield-cli`');
      return;
    }
    const dir = mkdtempSync(join(tmpdir(), 'qshield-'));
    writeFileSync(join(dir, 'ts-signed.json'), envelopeToJson(signed));
    const out = execFileSync(cli, ['verify', join(dir, 'ts-signed.json')], { encoding: 'utf8' });
    expect(out).toMatch(/OK: signature valid/);
  });

  it('plans inline and buffered submissions from chain state', async () => {
    const [vault] = vaultAddress(programId, key.keyId, fromHex(V.vault_seed_hex));
    const vaultData = fromHex(V.accounts.vault_hex);
    vaultData[9] = VaultStatus.Active;
    const keyAccountAddr = parseVault(vaultData).keyAccount;
    const keyData = new Uint8Array(21_976);
    keyData.set(fromHex(V.accounts.key_account_header_hex));
    const rpc: RpcLike = {
      async getAccount(a) {
        if (toHex(a) === toHex(vault)) return { lamports: 10_000_000_000n, owner: programId, data: vaultData };
        if (toHex(a) === toHex(keyAccountAddr)) return { lamports: 1n, owner: programId, data: keyData };
        return null;
      },
      async getMinimumBalanceForRentExemption() {
        return 2_672_640n;
      },
      async getGenesisHash() {
        return CLUSTER.devnet;
      },
    };
    const q = new QShield({ rpc, programId, clusterId: CLUSTER.devnet });
    await q.checkCluster();
    const feePayer = new Uint8Array(32).fill(9);
    const inline = await q.planSubmission(V.envelope, feePayer, 'inline');
    expect(inline).toHaveLength(1);
    expect(inline[0]!.format).toBe('v1');
    expect(inline[0]!.instructions[0]!.data).toHaveLength(1 + 292 + 2420);
    const buffered = await q.planSubmission(V.envelope, feePayer, 'buffered', 7n);
    expect(buffered.map((p) => p.format)).toEqual(['legacy', 'legacy', 'legacy', 'legacy', 'legacy']);
    // Wrong nonce is refused before anything is sent.
    const stale = createEnvelope({ ...decode(fromHex(V.envelope.auth_hex)), nonce: 41n }, key.keyId);
    await expect(q.planSubmission(await signEnvelope(stale, key), feePayer)).rejects.toThrow(/nonce/);
    // Wrong cluster.
    const mainnet = new QShield({ rpc, programId, clusterId: CLUSTER.mainnetBeta });
    await expect(mainnet.checkCluster()).rejects.toThrow(/cluster/);
  });
});
