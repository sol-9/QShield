/**
 * QSP-1 version 2 — authorizations for vaults with a guardian policy
 * (docs/QSP-1.md §11, ADR-0018). Same rules as the Rust crate; checked
 * against tests/vectors/qsp1/qsp1-v2-vectors.json.
 */
import { equal, isZero, readI64, readU16, readU64, utf8, writeI64, writeU64 } from './bytes.js';
import { AssetType, AUTH_LEN, Algorithm, OFFSETS, Qsp1Error } from './qsp1.js';

export const DOMAIN_V2 = utf8('QSHIELD_SOLANA_AUTH_V2');
export const AUTH_V2_LEN = 317;
export const MIN_LIMIT_PERIOD = 3_600n;
export const MAX_LIMIT_PERIOD = 30n * 86_400n;
export const OFFSETS_V2 = { role: 292, refId: 293, limitLamports: 301, limitPeriod: 309, end: 317 } as const;

export enum Role {
  Everyday = 1,
  Guardian = 2,
}

export enum ActionV2 {
  WithdrawSol = 1,
  WithdrawSpl = 2,
  RotateKey = 3,
  Pause = 4,
  Unpause = 5,
  ProposeWithdraw = 7,
  ApproveWithdraw = 8,
  CancelProposal = 9,
  EnablePolicy = 10,
  SetLimit = 11,
  AddAddress = 12,
  RemoveAddress = 13,
  RotateGuardian = 14,
  DisablePolicy = 15,
}

export interface AuthorizationV2 {
  clusterId: Uint8Array;
  programId: Uint8Array;
  vault: Uint8Array;
  action: ActionV2;
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
  role: Role;
  refId: bigint;
  limitLamports: bigint;
  limitPeriod: bigint;
}

/** Roles allowed to sign each action. */
export function allowedV2(action: ActionV2, role: Role): boolean {
  switch (action) {
    case ActionV2.WithdrawSol:
    case ActionV2.WithdrawSpl:
    case ActionV2.ProposeWithdraw:
    case ActionV2.EnablePolicy:
      return role === Role.Everyday;
    case ActionV2.RotateKey:
    case ActionV2.Unpause:
    case ActionV2.ApproveWithdraw:
    case ActionV2.AddAddress:
    case ActionV2.RotateGuardian:
    case ActionV2.DisablePolicy:
      return role === Role.Guardian;
    default:
      return true;
  }
}

export function validateV2(a: AuthorizationV2): void {
  if (!(a.action in ActionV2) || typeof a.action !== 'number') throw new Qsp1Error('Action');
  if (!(a.role in Role) || typeof a.role !== 'number') throw new Qsp1Error('NonCanonical');
  if (a.feeLamports === 0n && !isZero(a.feeRecipient)) throw new Qsp1Error('NonCanonical');
  if (a.validAfter < 0n || a.expiresAt < 0n) throw new Qsp1Error('Window');
  if (a.expiresAt !== 0n && a.expiresAt <= a.validAfter) throw new Qsp1Error('Window');
  if (!allowedV2(a.action, a.role)) throw new Qsp1Error('NonCanonical');
  const noAsset = a.assetType === AssetType.None && isZero(a.mint) && isZero(a.destination) && a.amount === 0n && a.decimals === 0;
  const noKey = isZero(a.newKeyId) && a.newAlgorithm === 0;
  const noRef = a.refId === 0n;
  const noLimit = a.limitLamports === 0n && a.limitPeriod === 0n;
  const limitOk = a.limitPeriod >= MIN_LIMIT_PERIOD && a.limitPeriod <= MAX_LIMIT_PERIOD;
  const newKey = !isZero(a.newKeyId) && a.newAlgorithm === Algorithm.MlDsa44;
  const assetOk =
    a.assetType === AssetType.Sol
      ? isZero(a.mint) && a.decimals === 0
      : a.assetType === AssetType.SplToken || a.assetType === AssetType.Token2022
        ? !isZero(a.mint)
        : false;
  const transfer = assetOk && !isZero(a.destination) && a.amount > 0n;
  const saved = a.assetType === AssetType.None && isZero(a.mint) && !isZero(a.destination) && a.amount === 0n && a.decimals === 0;
  let ok: boolean;
  switch (a.action) {
    case ActionV2.WithdrawSol:
      ok = a.assetType === AssetType.Sol && transfer && noKey && noRef && noLimit;
      break;
    case ActionV2.WithdrawSpl:
      ok = (a.assetType === AssetType.SplToken || a.assetType === AssetType.Token2022) && transfer && noKey && noRef && noLimit;
      break;
    case ActionV2.ProposeWithdraw:
      ok = transfer && noKey && noRef && noLimit;
      break;
    case ActionV2.ApproveWithdraw:
      ok = transfer && noKey && a.refId !== 0n && noLimit;
      break;
    case ActionV2.CancelProposal:
      ok = noAsset && noKey && a.refId !== 0n && noLimit;
      break;
    case ActionV2.RotateKey:
    case ActionV2.RotateGuardian:
      ok = noAsset && newKey && noRef && noLimit;
      break;
    case ActionV2.Pause:
    case ActionV2.Unpause:
    case ActionV2.DisablePolicy:
      ok = noAsset && noKey && noRef && noLimit;
      break;
    case ActionV2.EnablePolicy:
      ok = noAsset && newKey && noRef && limitOk;
      break;
    case ActionV2.SetLimit:
      ok = noAsset && noKey && noRef && limitOk;
      break;
    case ActionV2.AddAddress:
    case ActionV2.RemoveAddress:
      ok = saved && noKey && noRef && noLimit;
      break;
    default:
      throw new Qsp1Error('Action');
  }
  if (!ok) throw new Qsp1Error('NonCanonical');
}

export function encodeV2(a: AuthorizationV2): Uint8Array {
  validateV2(a);
  const b = new Uint8Array(AUTH_V2_LEN);
  b.set(DOMAIN_V2, OFFSETS.domain);
  b[OFFSETS.version] = 2;
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
  b[OFFSETS_V2.role] = a.role;
  writeU64(b, OFFSETS_V2.refId, a.refId);
  writeU64(b, OFFSETS_V2.limitLamports, a.limitLamports);
  writeI64(b, OFFSETS_V2.limitPeriod, a.limitPeriod);
  return b;
}

export function decodeV2(b: Uint8Array): AuthorizationV2 {
  if (b.length !== AUTH_V2_LEN) throw new Qsp1Error('Length');
  if (!equal(b.subarray(0, 22), DOMAIN_V2)) throw new Qsp1Error('Domain');
  if (readU16(b, OFFSETS.version) !== 2) throw new Qsp1Error('Version');
  const action = b[OFFSETS.action]!;
  if (!(action in ActionV2)) throw new Qsp1Error('Action');
  const assetType = b[OFFSETS.assetType]!;
  if (assetType > 3) throw new Qsp1Error('AssetType');
  const s = (o: number) => b.slice(o, o + 32);
  const a: AuthorizationV2 = {
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
    role: b[OFFSETS_V2.role]!,
    refId: readU64(b, OFFSETS_V2.refId),
    limitLamports: readU64(b, OFFSETS_V2.limitLamports),
    limitPeriod: readI64(b, OFFSETS_V2.limitPeriod),
  };
  if (!(a.role in Role)) throw new Qsp1Error('NonCanonical');
  validateV2(a);
  return a;
}

/** True for a canonical v1 or v2 authorization (what keys may sign). */
export function isQspAuthorization(b: Uint8Array, decodeV1: (b: Uint8Array) => unknown): boolean {
  try {
    if (b.length === AUTH_LEN) decodeV1(b);
    else decodeV2(b);
    return true;
  } catch {
    return false;
  }
}

