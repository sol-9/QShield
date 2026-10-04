/** Account layouts (docs/PROTOCOL.md §2). */
import { equal, readI64, readU64, utf8 } from './bytes.js';

export enum VaultStatus {
  Active = 1,
  Paused = 2,
  Closed = 3,
}
export enum KeyState {
  Writing = 1,
  Expanding = 2,
  Ready = 3,
}
export enum BufferState {
  Writing = 1,
  Finalized = 2,
}

export interface VaultState {
  status: VaultStatus;
  bump: number;
  pqAlgorithm: number;
  threshold: number;
  keyCount: number;
  /** @deprecated byte 14 is now `policyMode`. */
  recoveryMode: number;
  /** 0 = single key (QSP-1 v1), 1 = guardian policy (QSP-1 v2 only). */
  policyMode: number;
  nonce: bigint;
  keyId: Uint8Array;
  keyAccount: Uint8Array;
  initialKeyId: Uint8Array;
  vaultSeed: Uint8Array;
  createdSlot: bigint;
  createdAt: bigint;
}

export interface KeyHeader {
  algorithm: number;
  state: KeyState;
  inUse: boolean;
  expanded: number;
  vault: Uint8Array;
  keyId: Uint8Array;
  creator: Uint8Array;
  /** In use as the vault's guardian key (role byte 2). */
  guardian: boolean;
  /** Present when the account data includes the public key. */
  publicKey?: Uint8Array;
}

export interface SigBufferHeader {
  state: BufferState;
  bump: number;
  vault: Uint8Array;
  creator: Uint8Array;
  bufferId: bigint;
}

export const VAULT_LEN = 256;
export const KEY_ACCOUNT_LEN = 21_976;
export const KEY_PK_OFFSET = 120;
export const PUBLIC_KEY_LEN = 1312;
export const SIG_BUFFER_LEN = 2_508;
export const SIG_BUFFER_DATA_OFFSET = 88;

const s32 = (d: Uint8Array, o: number) => d.slice(o, o + 32);

export function parseVault(d: Uint8Array): VaultState {
  if (d.length !== VAULT_LEN || !equal(d.subarray(0, 8), utf8('QSHVAULT')) || d[8] !== 1) throw new Error('not a QShield vault account');
  const status = d[9]!;
  if (!(status in VaultStatus)) throw new Error('invalid vault status');
  return {
    status,
    bump: d[10]!,
    pqAlgorithm: d[11]!,
    threshold: d[12]!,
    keyCount: d[13]!,
    recoveryMode: d[14]!,
    policyMode: d[14]!,
    nonce: readU64(d, 16),
    keyId: s32(d, 24),
    keyAccount: s32(d, 56),
    initialKeyId: s32(d, 88),
    vaultSeed: s32(d, 120),
    createdSlot: readU64(d, 152),
    createdAt: readI64(d, 160),
  };
}

/** Parses a key-account header; accepts full account data or just the header (+ public key). */
export function parseKeyHeader(d: Uint8Array): KeyHeader {
  if (d.length < KEY_PK_OFFSET || !equal(d.subarray(0, 8), utf8('QSHKEY01')) || d[8] !== 1) throw new Error('not a QShield key account');
  const state = d[10]!;
  if (!(state in KeyState)) throw new Error('invalid key state');
  const h: KeyHeader = { algorithm: d[9]!, state, inUse: d[12] !== 0, guardian: d[12] === 2, expanded: d[13]!, vault: s32(d, 24), keyId: s32(d, 56), creator: s32(d, 88) };
  if (d.length >= KEY_PK_OFFSET + PUBLIC_KEY_LEN) h.publicKey = d.slice(KEY_PK_OFFSET, KEY_PK_OFFSET + PUBLIC_KEY_LEN);
  return h;
}

export function parseSigBufferHeader(d: Uint8Array): SigBufferHeader {
  if (d.length < SIG_BUFFER_DATA_OFFSET || !equal(d.subarray(0, 8), utf8('QSHSIGB1')) || d[8] !== 1) throw new Error('not a QShield signature buffer');
  const state = d[9]!;
  if (!(state in BufferState)) throw new Error('invalid buffer state');
  return { state, bump: d[10]!, vault: s32(d, 16), creator: s32(d, 48), bufferId: readU64(d, 80) };
}

export const POLICY_LEN = 512;
export const PROPOSAL_LEN = 208;
export const MAX_SAVED = 8;

/** Guardian policy (PDA ["policy", vault]; docs/PROTOCOL.md §5.1). */
export interface PolicyState {
  bump: number;
  enabled: boolean;
  vault: Uint8Array;
  guardianKeyId: Uint8Array;
  guardianKeyAccount: Uint8Array;
  guardianNonce: bigint;
  limit: bigint;
  period: bigint;
  available: bigint;
  lastRefill: bigint;
  saved: Uint8Array[];
}

export function parsePolicy(d: Uint8Array): PolicyState {
  if (d.length !== POLICY_LEN || !equal(d.subarray(0, 8), utf8('QSHPOL01')) || d[8] !== 1) throw new Error('not a QShield policy account');
  const n = d[11]!;
  if (n > MAX_SAVED || d[10]! > 1) throw new Error('invalid policy account');
  return {
    bump: d[9]!,
    enabled: d[10] === 1,
    vault: s32(d, 16),
    guardianKeyId: s32(d, 48),
    guardianKeyAccount: s32(d, 80),
    guardianNonce: readU64(d, 112),
    limit: readU64(d, 120),
    period: readI64(d, 128),
    available: readU64(d, 136),
    lastRefill: readI64(d, 144),
    saved: Array.from({ length: n }, (_, i) => s32(d, 160 + 32 * i)),
  };
}

/** Allowance after refilling up to `now` (same arithmetic as the program). */
export function availableAt(p: PolicyState, now: bigint): bigint {
  if (p.period <= 0n || now <= p.lastRefill) return p.available;
  const add = ((now - p.lastRefill) * p.limit) / p.period;
  const a = p.available + add;
  return a > p.limit ? p.limit : a;
}

/** Proposal (PDA ["proposal", vault, id]; docs/PROTOCOL.md §5.2). */
export interface ProposalState {
  bump: number;
  assetType: number;
  decimals: number;
  vault: Uint8Array;
  id: bigint;
  createdAt: bigint;
  expiresAt: bigint;
  proposerKeyId: Uint8Array;
  mint: Uint8Array;
  destination: Uint8Array;
  amount: bigint;
  rentPayer: Uint8Array;
}

export function parseProposal(d: Uint8Array): ProposalState {
  if (d.length !== PROPOSAL_LEN || !equal(d.subarray(0, 8), utf8('QSHPROP1')) || d[8] !== 1) throw new Error('not a QShield proposal');
  return {
    bump: d[9]!,
    assetType: d[10]!,
    decimals: d[11]!,
    vault: s32(d, 16),
    id: readU64(d, 48),
    createdAt: readI64(d, 56),
    expiresAt: readI64(d, 64),
    proposerKeyId: s32(d, 72),
    mint: s32(d, 104),
    destination: s32(d, 136),
    amount: readU64(d, 168),
    rentPayer: s32(d, 176),
  };
}
