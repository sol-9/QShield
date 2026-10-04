/**
 * QSP-1 (QShield Signing Protocol v1): canonical 292-byte authorization
 * encoding. Normative spec: docs/QSP-1.md. Mirrors `crates/qshield-protocol`;
 * both are checked against tests/vectors/qsp1/qsp1-vectors.json.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { base58 } from '@scure/base';
import { concat, equal, isZero, readI64, readU16, readU64, utf8, writeI64, writeU64 } from './bytes.js';

export const DOMAIN = utf8('QSHIELD_SOLANA_AUTH_V1');
export const PROTOCOL_VERSION = 1;
export const ML_DSA_CONTEXT = utf8('QSHIELD/QSP-1');
export const AUTH_LEN = 292;
export const KEY_ID_DOMAIN = utf8('QSHIELD_KEY_ID_V1');
export const ZERO32 = new Uint8Array(32);

export const OFFSETS = {
  domain: 0,
  version: 22,
  clusterId: 24,
  programId: 56,
  vault: 88,
  action: 120,
  assetType: 121,
  nonce: 122,
  validAfter: 130,
  expiresAt: 138,
  mint: 146,
  destination: 178,
  amount: 210,
  decimals: 218,
  feeRecipient: 219,
  feeLamports: 251,
  newKeyId: 259,
  newAlgorithm: 291,
  end: 292,
} as const;

/** Cluster ids: genesis hashes (raw bytes). Verify with `solana genesis-hash`. */
export const CLUSTER = {
  mainnetBeta: base58.decode('5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'),
  devnet: base58.decode('EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'),
  testnet: base58.decode('4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY'),
  /** Sentinel for local test validators. */
  localnet: utf8('QSHIELD-LOCALNET-NOT-A-REAL-NET!'),
} as const;

export enum Action {
  WithdrawSol = 1,
  /** Reserved: rejected by program v0.1. */
  WithdrawSpl = 2,
  RotateKey = 3,
  Pause = 4,
  Unpause = 5,
  CloseVault = 6,
}

export enum AssetType {
  None = 0,
  Sol = 1,
  SplToken = 2,
  Token2022 = 3,
}

export enum Algorithm {
  MlDsa44 = 1,
}

export interface Authorization {
  clusterId: Uint8Array;
  programId: Uint8Array;
  vault: Uint8Array;
  action: Action;
  assetType: AssetType;
  nonce: bigint;
  validAfter: bigint;
  expiresAt: bigint;
  mint: Uint8Array;
  destination: Uint8Array;
  amount: bigint;
  decimals: number;
  feeRecipient: Uint8Array;
  feeLamports: bigint;
  newKeyId: Uint8Array;
  newAlgorithm: number;
}

export type Qsp1ErrorCode = 'Length' | 'Domain' | 'Version' | 'Action' | 'AssetType' | 'Algorithm' | 'NonCanonical' | 'Window';

export class Qsp1Error extends Error {
  constructor(readonly code: Qsp1ErrorCode) {
    super(`QSP-1: ${code}`);
  }
}

function check32(name: string, b: Uint8Array): void {
  if (b.length !== 32) throw new TypeError(`${name} must be 32 bytes`);
}

/** Per-action canonical field rules (QSP-1 §5). Throws `Qsp1Error`. */
export function validate(a: Authorization): void {
  for (const k of ['clusterId', 'programId', 'vault', 'mint', 'destination', 'feeRecipient', 'newKeyId'] as const) check32(k, a[k]);
  if (!(a.action in Action) || typeof a.action !== 'number') throw new Qsp1Error('Action');
  if (!(a.assetType in AssetType) || typeof a.assetType !== 'number') throw new Qsp1Error('AssetType');
  if (!Number.isInteger(a.decimals) || a.decimals < 0 || a.decimals > 255) throw new TypeError('decimals must be a u8');
  if (!Number.isInteger(a.newAlgorithm) || a.newAlgorithm < 0 || a.newAlgorithm > 255) throw new TypeError('newAlgorithm must be a u8');
  if (a.feeLamports === 0n && !isZero(a.feeRecipient)) throw new Qsp1Error('NonCanonical');
  if (a.expiresAt !== 0n && a.expiresAt <= a.validAfter) throw new Qsp1Error('Window');
  if (a.validAfter < 0n || a.expiresAt < 0n) throw new Qsp1Error('Window');
  const rotationZero = isZero(a.newKeyId) && a.newAlgorithm === 0;
  let ok: boolean;
  switch (a.action) {
    case Action.WithdrawSol:
      ok = a.assetType === AssetType.Sol && isZero(a.mint) && !isZero(a.destination) && a.amount > 0n && a.decimals === 0 && rotationZero;
      break;
    case Action.WithdrawSpl:
      ok =
        (a.assetType === AssetType.SplToken || a.assetType === AssetType.Token2022) &&
        !isZero(a.mint) &&
        !isZero(a.destination) &&
        a.amount > 0n &&
        rotationZero;
      break;
    case Action.RotateKey:
      ok =
        a.assetType === AssetType.None &&
        isZero(a.mint) &&
        isZero(a.destination) &&
        a.amount === 0n &&
        a.decimals === 0 &&
        !isZero(a.newKeyId) &&
        a.newAlgorithm === Algorithm.MlDsa44;
      break;
    case Action.Pause:
    case Action.Unpause:
      ok = a.assetType === AssetType.None && isZero(a.mint) && isZero(a.destination) && a.amount === 0n && a.decimals === 0 && rotationZero;
      break;
    case Action.CloseVault:
      ok = a.assetType === AssetType.Sol && isZero(a.mint) && !isZero(a.destination) && a.amount === 0n && a.decimals === 0 && rotationZero;
      break;
    default:
      throw new Qsp1Error('Action');
  }
  if (!ok) throw new Qsp1Error('NonCanonical');
}

/** Encodes to the canonical 292 bytes (validates first). */
export function encode(a: Authorization): Uint8Array {
  validate(a);
  const b = new Uint8Array(AUTH_LEN);
  b.set(DOMAIN, OFFSETS.domain);
  b[OFFSETS.version] = PROTOCOL_VERSION & 0xff;
  b[OFFSETS.version + 1] = PROTOCOL_VERSION >> 8;
  b.set(a.clusterId, OFFSETS.clusterId);
  b.set(a.programId, OFFSETS.programId);
  b.set(a.vault, OFFSETS.vault);
  b[OFFSETS.action] = a.action;
  b[OFFSETS.assetType] = a.assetType;
  writeU64(b, OFFSETS.nonce, a.nonce);
  writeI64(b, OFFSETS.validAfter, a.validAfter);
  writeI64(b, OFFSETS.expiresAt, a.expiresAt);
  b.set(a.mint, OFFSETS.mint);
  b.set(a.destination, OFFSETS.destination);
  writeU64(b, OFFSETS.amount, a.amount);
  b[OFFSETS.decimals] = a.decimals;
  b.set(a.feeRecipient, OFFSETS.feeRecipient);
  writeU64(b, OFFSETS.feeLamports, a.feeLamports);
  b.set(a.newKeyId, OFFSETS.newKeyId);
  b[OFFSETS.newAlgorithm] = a.newAlgorithm;
  return b;
}

/** Strict decoding: succeeds only for canonical encodings. Throws `Qsp1Error`. */
export function decode(b: Uint8Array): Authorization {
  if (b.length !== AUTH_LEN) throw new Qsp1Error('Length');
  if (!equal(b.subarray(0, 22), DOMAIN)) throw new Qsp1Error('Domain');
  if (readU16(b, OFFSETS.version) !== PROTOCOL_VERSION) throw new Qsp1Error('Version');
  const action = b[OFFSETS.action]!;
  if (action < 1 || action > 6) throw new Qsp1Error('Action');
  const assetType = b[OFFSETS.assetType]!;
  if (assetType > 3) throw new Qsp1Error('AssetType');
  const s = (o: number) => b.slice(o, o + 32);
  const a: Authorization = {
    clusterId: s(OFFSETS.clusterId),
    programId: s(OFFSETS.programId),
    vault: s(OFFSETS.vault),
    action,
    assetType,
    nonce: readU64(b, OFFSETS.nonce),
    validAfter: readI64(b, OFFSETS.validAfter),
    expiresAt: readI64(b, OFFSETS.expiresAt),
    mint: s(OFFSETS.mint),
    destination: s(OFFSETS.destination),
    amount: readU64(b, OFFSETS.amount),
    decimals: b[OFFSETS.decimals]!,
    feeRecipient: s(OFFSETS.feeRecipient),
    feeLamports: readU64(b, OFFSETS.feeLamports),
    newKeyId: s(OFFSETS.newKeyId),
    newAlgorithm: b[OFFSETS.newAlgorithm]!,
  };
  validate(a);
  return a;
}

/** `key_id = SHA-256("QSHIELD_KEY_ID_V1" ‖ algorithm ‖ public_key)`. */
export function keyId(publicKey: Uint8Array, algorithm: Algorithm = Algorithm.MlDsa44): Uint8Array {
  return sha256(concat(KEY_ID_DOMAIN, Uint8Array.of(algorithm), publicKey));
}

/** Human-readable cluster name (same strings as the Rust SDK). */
export function clusterName(id: Uint8Array): string {
  if (equal(id, CLUSTER.mainnetBeta)) return 'mainnet-beta';
  if (equal(id, CLUSTER.devnet)) return 'devnet';
  if (equal(id, CLUSTER.testnet)) return 'testnet';
  if (equal(id, CLUSTER.localnet)) return 'localnet';
  return `unknown(${Array.from(id, (x) => x.toString(16).padStart(2, '0')).join('')})`;
}
