import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { address, fromHex, toBase58 } from '../src/bytes.js';
import { QShield, type AccountInfo, type RpcLike } from '../src/client.js';
import { createEnvelope, signEnvelope } from '../src/envelope.js';
import { LocalKey } from '../src/keys.js';
import { CLUSTER } from '../src/qsp1.js';
import {
  TOKEN_2022_PROGRAM_ID,
  TOKEN_PROGRAM_ID,
  TokenPolicyError,
  associatedTokenAddress,
  formatTokenAmount,
  parseMint,
  parseTokenAmount,
} from '../src/token.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/sdk/interop-v1.json', import.meta.url), 'utf8'));

describe('SPL token helpers (shared vectors with the Rust program)', () => {
  it('mint policy matches the program for every sample', () => {
    expect(V.mint_policy.length).toBeGreaterThan(5);
    for (const c of V.mint_policy) {
      const program = address(c.token_program);
      const data = fromHex(c.data_hex);
      if (c.result.ok) {
        expect(parseMint(program, data).decimals).toBe(c.result.decimals);
      } else {
        let err: unknown;
        try {
          parseMint(program, data);
        } catch (e) {
          err = e;
        }
        expect(err).toBeInstanceOf(TokenPolicyError);
        expect((err as TokenPolicyError).code).toBe(c.result.error);
      }
    }
  });

  it('vault associated token accounts', () => {
    const vault = address(V.vault_address);
    const mint = address(V.vault_token_accounts.mint);
    expect(toBase58(associatedTokenAddress(vault, mint, TOKEN_PROGRAM_ID))).toBe(V.vault_token_accounts.spl_token);
    expect(toBase58(associatedTokenAddress(vault, mint, TOKEN_2022_PROGRAM_ID))).toBe(V.vault_token_accounts.token_2022);
  });

  it('amount formatting and parsing (same rules as the Rust SDK)', () => {
    expect(parseTokenAmount('1', 6)).toBe(1_000_000n);
    expect(parseTokenAmount('0.000001', 6)).toBe(1n);
    expect(parseTokenAmount('.5', 1)).toBe(5n);
    expect(parseTokenAmount('7', 0)).toBe(7n);
    expect(parseTokenAmount('18446744073709551615', 0)).toBe((1n << 64n) - 1n);
    for (const bad of ['', '.', '1.2.3', '-1', '1e6', '0.0000001', '18446744073709551616', ' 1']) {
      expect(() => parseTokenAmount(bad, 6), bad).toThrow();
    }
    expect(formatTokenAmount(1n, 6)).toBe('0.000001');
    expect(formatTokenAmount((1n << 64n) - 1n, 0)).toBe('18446744073709551615');
    expect(formatTokenAmount((1n << 64n) - 1n, 255)).toBe('18446744073709551615e-255');
  });
});

/** In-memory chain with one vault, its key, a mint and the vault's token account. */
function fakeChain(programId: Uint8Array, key: LocalKey) {
  const accounts = new Map<string, AccountInfo>();
  const put = (a: Uint8Array, owner: Uint8Array, data: Uint8Array, lamports = 10_000_000n) => accounts.set(toBase58(a), { owner, data, lamports });
  const rpc: RpcLike = {
    getAccount: async (a) => accounts.get(toBase58(a)) ?? null,
    getMinimumBalanceForRentExemption: async () => 2_000_000n,
    getGenesisHash: async () => CLUSTER.localnet,
  };
  return { rpc, put, accounts };
}

describe('WithdrawSpl submission plan', () => {
  it('derives accounts, creates the destination ATA and enforces local checks', async () => {
    const programId = address(V.program_id);
    const key = LocalKey.fromSeed(fromHex(V.key_seed_hex));
    const vault = address(V.vault_address);
    const keyAccount = fromHex(V.accounts.vault_hex.slice(112, 176));
    const chain = fakeChain(programId, key);
    // Vault (status Active) and its key account (header + public key).
    const vd = fromHex(V.accounts.vault_hex);
    vd[9] = 1;
    chain.put(vault, programId, vd);
    const kd = new Uint8Array(21_976);
    kd.set(fromHex(V.accounts.key_account_header_hex));
    chain.put(keyAccount, programId, kd);
    // A 6-decimal SPL mint and the vault's token account holding 2.0 tokens.
    const mint = address(V.vault_token_accounts.mint);
    const mintData = fromHex(V.mint_policy[0].data_hex);
    chain.put(mint, TOKEN_PROGRAM_ID, mintData);
    const vaultTa = associatedTokenAddress(vault, mint, TOKEN_PROGRAM_ID);
    const ta = new Uint8Array(165);
    ta.set(mint, 0);
    ta.set(vault, 32);
    new DataView(ta.buffer).setBigUint64(64, 2_000_000n, true);
    ta[108] = 1;
    chain.put(vaultTa, TOKEN_PROGRAM_ID, ta);

    const q = new QShield({ rpc: chain.rpc, programId, clusterId: CLUSTER.localnet });
    const m = await q.getMint(mint);
    const recipient = address(V.sig_buffer.creator);
    const feePayer = address(V.sig_buffer.creator);
    const auth = q.createWithdrawSplIntent({ vault, nonce: 42n, mint: m, toOwner: recipient, amount: 1_500_000n });
    const env = await signEnvelope(createEnvelope(auth, key.keyId), key);
    expect(env.fields.amount).toBe('1.500000 (1500000 base units, decimals 6)');

    await expect(q.planSubmission(env, feePayer)).rejects.toThrow(/destination_owner/);
    env.hints = { destination_owner: toBase58(recipient) };
    const [plan] = await q.planSubmission(env, feePayer);
    expect(plan!.instructions).toHaveLength(2);
    const exec = plan!.instructions[1]!;
    expect(exec.keys.slice(3).map((k) => toBase58(k.pubkey))).toEqual([
      toBase58(vaultTa),
      toBase58(mint),
      toBase58(associatedTokenAddress(recipient, mint, TOKEN_PROGRAM_ID)),
      toBase58(TOKEN_PROGRAM_ID),
    ]);

    const tooMuch = q.createWithdrawSplIntent({ vault, nonce: 42n, mint: m, toOwner: recipient, amount: 2_000_001n });
    const e2 = await signEnvelope(createEnvelope(tooMuch, key.keyId), key);
    e2.hints = { destination_owner: toBase58(recipient) };
    await expect(q.planSubmission(e2, feePayer)).rejects.toThrow(/balance/);
  });
});
