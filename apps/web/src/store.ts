/**
 * Browser persistence. Only public data and *encrypted* key files are stored
 * (localStorage); the PQ secret exists in clear only in memory while signing.
 * A compromised page, extension or device can still capture the password —
 * this is experimental software storage, not hardware-grade (docs/KEYSTORE.md).
 */
import type { KeystoreFile } from '@qshield/sdk';

export type ClusterName = 'mainnet' | 'devnet' | 'testnet' | 'localnet';

export interface Settings {
  rpcUrl: string;
  programId: string;
  cluster: ClusterName;
  relayerUrl: string;
}

export interface StoredKey {
  keystore: KeystoreFile;
  /** 'pending' until the backup has been downloaded and verified. */
  status: 'pending' | 'active' | 'retired';
  backupVerified: boolean;
  /** The 24 recovery words were shown and confirmed (a backup on paper). */
  wordsBackedUp?: boolean;
  createdAt: number;
}

export interface StoredVault {
  address: string;
  label: string;
  /** Key id that created it (the vault's current key may differ after rotation). */
  initialKeyId: string;
}

export interface AppState {
  version: 1;
  settings: Settings;
  keys: StoredKey[];
  vault: StoredVault | null;
  /** Addresses this wallet has sent to (look-alike detection). */
  history?: string[];
  /** Guardian public key chosen for the vault, before the policy is enabled (public data only). */
  guardianPublic?: { keyId: string; publicKey: string } | null;
  /**
   * Recovery of a guarded vault on a new device: the vault, and the key
   * account set up for this browser's new key, waiting for the guardian.
   */
  recovery?: { vault?: string; keyAccount?: string } | null;
}

const KEY = 'qshield.wallet.v1';

export const DEFAULT_SETTINGS: Settings = {
  rpcUrl: 'http://127.0.0.1:8899',
  programId: '',
  cluster: 'localnet',
  relayerUrl: 'http://127.0.0.1:8787',
};

export interface Storage {
  getItem(k: string): string | null;
  setItem(k: string, v: string): void;
  removeItem(k: string): void;
}

/**
 * Settings fixed at build time (`VITE_QSHIELD_*`). A production build pins at
 * least the program id and cluster, so neither a link nor the settings form
 * can point the wallet at another program (phishing defence).
 */
export interface Pinned {
  programId?: string;
  cluster?: ClusterName;
  rpcUrl?: string;
  relayerUrl?: string;
}

const CLUSTERS: ClusterName[] = ['mainnet', 'devnet', 'testnet', 'localnet'];

export function load(storage: Storage, pinned: Pinned = {}): AppState {
  let s: AppState;
  try {
    const raw = storage.getItem(KEY);
    s = raw ? (JSON.parse(raw) as AppState) : { version: 1, settings: { ...DEFAULT_SETTINGS }, keys: [], vault: null };
    if (s.version !== 1) throw new Error('unknown version');
  } catch {
    s = { version: 1, settings: { ...DEFAULT_SETTINGS }, keys: [], vault: null };
  }
  s.settings = applyPinned(s.settings, pinned);
  if (!CLUSTERS.includes(s.settings.cluster)) s.settings.cluster = 'localnet';
  return s;
}

export function applyPinned(s: Settings, pinned: Pinned): Settings {
  const out = { ...s };
  for (const k of ['programId', 'cluster', 'rpcUrl', 'relayerUrl'] as const) {
    const v = pinned[k];
    if (v) (out as Record<string, string>)[k] = v;
  }
  return out;
}

/**
 * Settings proposed by a link (`?rpc=…&program=…&cluster=…&relayer=…`).
 * They are never applied silently: the app shows them and the user must
 * click "Apply". Pinned settings cannot be changed at all. Returns null if
 * the link proposes nothing new.
 */
export function proposedSettings(current: Settings, query: URLSearchParams, pinned: Pinned = {}): Settings | null {
  const map: [string, keyof Settings][] = [
    ['rpc', 'rpcUrl'],
    ['program', 'programId'],
    ['cluster', 'cluster'],
    ['relayer', 'relayerUrl'],
  ];
  const next = { ...current };
  let changed = false;
  for (const [q, k] of map) {
    const v = query.get(q);
    if (!v || pinned[k] || v === current[k]) continue;
    if (k === 'cluster' && !CLUSTERS.includes(v as ClusterName)) continue;
    (next as Record<string, string>)[k] = v;
    changed = true;
  }
  return changed ? next : null;
}

export function save(storage: Storage, s: AppState): void {
  storage.setItem(KEY, JSON.stringify(s));
}

export function activeKey(s: AppState): StoredKey | undefined {
  return s.keys.find((k) => k.status === 'active');
}

export function pendingKey(s: AppState): StoredKey | undefined {
  return s.keys.find((k) => k.status === 'pending');
}

/**
 * Backup verification: the user re-imports the file they downloaded. It must
 * be byte-for-byte the same key file (same key id, salt and ciphertext), so a
 * truncated, edited or different file is rejected. Decryption with the
 * password is checked separately by the caller.
 */
export function verifyBackupFile(expected: KeystoreFile, uploaded: string): boolean {
  let f: KeystoreFile;
  try {
    f = JSON.parse(uploaded) as KeystoreFile;
  } catch {
    return false;
  }
  return (
    f.key_id === expected.key_id &&
    f.public_key === expected.public_key &&
    f.ciphertext === expected.ciphertext &&
    f.kdf?.salt === expected.kdf.salt &&
    f.cipher?.nonce === expected.cipher.nonce
  );
}

/** Password policy for new key files (the KDF slows guessing; length matters most). */
export function passwordProblem(pw: string, repeat: string): string | null {
  if (pw.length < 12) return 'Use at least 12 characters (a passphrase of several words is best).';
  if (pw !== repeat) return 'The passwords do not match.';
  return null;
}
