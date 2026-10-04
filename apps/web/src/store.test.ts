import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, load, passwordProblem, proposedSettings, save, verifyBackupFile, type Storage } from './store.js';

function mem(): Storage & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v), removeItem: (k) => void data.delete(k) };
}

const ks: any = {
  qshield_keystore: 1,
  algorithm: 'ML-DSA-44',
  public_key: 'aa',
  key_id: 'bb',
  kdf: { name: 'argon2id', version: 19, m_cost_kib: 65536, t_cost: 3, p_cost: 1, salt: 'cc' },
  cipher: { name: 'xchacha20-poly1305', nonce: 'dd' },
  ciphertext: 'ee',
};

describe('wallet store', () => {
  it('defaults, pinning and garbage recovery', () => {
    const s = mem();
    expect(load(s).settings).toEqual(DEFAULT_SETTINGS);
    const pinned = load(s, { programId: 'Pinned', cluster: 'mainnet' }).settings;
    expect(pinned.programId).toBe('Pinned');
    expect(pinned.cluster).toBe('mainnet');
    s.setItem('qshield.wallet.v1', '{not json');
    expect(load(s).keys).toEqual([]);
    const st = load(s);
    st.keys.push({ keystore: ks, status: 'active', backupVerified: true, createdAt: 1 });
    save(s, st);
    expect(load(s).keys[0]!.keystore.key_id).toBe('bb');
  });

  it('link settings are only proposed, never applied, and cannot override pins', () => {
    const q = new URLSearchParams('rpc=https://rpc.example&program=Prog&cluster=devnet&relayer=https://r.example&secret=x');
    expect(proposedSettings(DEFAULT_SETTINGS, q)).toEqual({ rpcUrl: 'https://rpc.example', programId: 'Prog', cluster: 'devnet', relayerUrl: 'https://r.example' });
    expect(proposedSettings(DEFAULT_SETTINGS, new URLSearchParams('cluster=evilnet'))).toBeNull();
    expect(proposedSettings(DEFAULT_SETTINGS, new URLSearchParams(''))).toBeNull();
    const p = proposedSettings(DEFAULT_SETTINGS, q, { programId: 'Pinned', cluster: 'mainnet' })!;
    expect(p.programId).toBe(DEFAULT_SETTINGS.programId);
    expect(p.cluster).toBe(DEFAULT_SETTINGS.cluster);
    expect(p.relayerUrl).toBe('https://r.example');
  });

  it('backup verification accepts only the identical key file', () => {
    expect(verifyBackupFile(ks, JSON.stringify(ks, null, 2))).toBe(true);
    for (const f of ['ciphertext', 'key_id', 'public_key'] as const) expect(verifyBackupFile(ks, JSON.stringify({ ...ks, [f]: 'ff' }))).toBe(false);
    expect(verifyBackupFile(ks, JSON.stringify({ ...ks, kdf: { ...ks.kdf, salt: '00' } }))).toBe(false);
    expect(verifyBackupFile(ks, 'not json')).toBe(false);
    expect(verifyBackupFile(ks, JSON.stringify(ks).slice(0, 50))).toBe(false);
  });

  it('password policy', () => {
    expect(passwordProblem('short', 'short')).toMatch(/12/);
    expect(passwordProblem('correct horse battery', 'correct horse batterY')).toMatch(/match/);
    expect(passwordProblem('correct horse battery', 'correct horse battery')).toBeNull();
  });
});
