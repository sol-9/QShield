/**
 * Instruction builders (docs/PROTOCOL.md §1). Framework-neutral: they return
 * `{ programId, keys, data }`, which maps directly onto @solana/kit,
 * @solana/web3.js or any other transaction library.
 */
import { concat, writeU64 } from './bytes.js';
import { AUTH_LEN } from './qsp1.js';
import { ASSOCIATED_TOKEN_PROGRAM_ID, associatedTokenAddress } from './token.js';

export interface AccountMeta {
  pubkey: Uint8Array;
  isSigner: boolean;
  isWritable: boolean;
}
export interface Instruction {
  programId: Uint8Array;
  keys: AccountMeta[];
  data: Uint8Array;
}

export const SYSTEM_PROGRAM_ID = new Uint8Array(32);
export const SIGNATURE_LEN = 2420;

export const TAG = {
  createKey: 0,
  writeKey: 1,
  finalizeKey: 2,
  expandKey: 3,
  closeKey: 4,
  initializeVault: 5,
  depositSol: 6,
  execute: 7,
  createSigBuffer: 8,
  writeSigBuffer: 9,
  closeSigBuffer: 10,
  executeWithBuffer: 11,
  depositSpl: 12,
  executeV2: 13,
  executeV2WithBuffer: 14,
  closeProposal: 15,
} as const;

const w = (pubkey: Uint8Array, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: true });
const r = (pubkey: Uint8Array, isSigner = false): AccountMeta => ({ pubkey, isSigner, isWritable: false });
const u16 = (v: number) => Uint8Array.of(v & 0xff, v >> 8);
const u64 = (v: bigint) => {
  const b = new Uint8Array(8);
  writeU64(b, 0, v);
  return b;
};

export function createKey(programId: Uint8Array, creator: Uint8Array, keyAccount: Uint8Array, vault: Uint8Array, keyId: Uint8Array, algorithm = 1): Instruction {
  return { programId, keys: [w(creator, true), w(keyAccount, true)], data: concat(Uint8Array.of(TAG.createKey), vault, keyId, Uint8Array.of(algorithm)) };
}
export function writeKey(programId: Uint8Array, creator: Uint8Array, keyAccount: Uint8Array, offset: number, bytes: Uint8Array): Instruction {
  return { programId, keys: [r(creator, true), w(keyAccount)], data: concat(Uint8Array.of(TAG.writeKey), u16(offset), bytes) };
}
export function finalizeKey(programId: Uint8Array, creator: Uint8Array, keyAccount: Uint8Array): Instruction {
  return { programId, keys: [r(creator, true), w(keyAccount)], data: Uint8Array.of(TAG.finalizeKey) };
}
export function expandKey(programId: Uint8Array, keyAccount: Uint8Array, maxPolys: number): Instruction {
  return { programId, keys: [w(keyAccount)], data: Uint8Array.of(TAG.expandKey, maxPolys) };
}
export function closeKey(programId: Uint8Array, creator: Uint8Array, keyAccount: Uint8Array): Instruction {
  return { programId, keys: [w(creator, true), w(keyAccount)], data: Uint8Array.of(TAG.closeKey) };
}
export function initializeVault(programId: Uint8Array, payer: Uint8Array, vault: Uint8Array, keyAccount: Uint8Array, vaultSeed: Uint8Array): Instruction {
  return { programId, keys: [w(payer, true), w(vault), w(keyAccount), r(SYSTEM_PROGRAM_ID)], data: concat(Uint8Array.of(TAG.initializeVault), vaultSeed) };
}
export function depositSol(programId: Uint8Array, depositor: Uint8Array, vault: Uint8Array, lamports: bigint): Instruction {
  return { programId, keys: [w(depositor, true), w(vault), r(SYSTEM_PROGRAM_ID)], data: concat(Uint8Array.of(TAG.depositSol), u64(lamports)) };
}
/** `Execute` with the signature inline: needs a v1 transaction (≈ 3 KB). */
export function execute(programId: Uint8Array, feePayer: Uint8Array, vault: Uint8Array, keyAccount: Uint8Array, actionAccounts: AccountMeta[], auth: Uint8Array, signature: Uint8Array): Instruction {
  if (auth.length !== AUTH_LEN || signature.length !== SIGNATURE_LEN) throw new Error('bad authorization or signature length');
  return { programId, keys: [w(feePayer, true), w(vault), w(keyAccount), ...actionAccounts], data: concat(Uint8Array.of(TAG.execute), auth, signature) };
}
export function createSigBuffer(programId: Uint8Array, creator: Uint8Array, buffer: Uint8Array, vault: Uint8Array, bufferId: bigint): Instruction {
  return { programId, keys: [w(creator, true), w(buffer), r(SYSTEM_PROGRAM_ID)], data: concat(Uint8Array.of(TAG.createSigBuffer), vault, u64(bufferId)) };
}
export function writeSigBuffer(programId: Uint8Array, creator: Uint8Array, buffer: Uint8Array, offset: number, finalize: boolean, bytes: Uint8Array): Instruction {
  return { programId, keys: [r(creator, true), w(buffer)], data: concat(Uint8Array.of(TAG.writeSigBuffer), u16(offset), Uint8Array.of(finalize ? 1 : 0), bytes) };
}
export function closeSigBuffer(programId: Uint8Array, creator: Uint8Array, buffer: Uint8Array): Instruction {
  return { programId, keys: [w(creator, true), w(buffer)], data: Uint8Array.of(TAG.closeSigBuffer) };
}
export function executeWithBuffer(programId: Uint8Array, feePayer: Uint8Array, vault: Uint8Array, keyAccount: Uint8Array, buffer: Uint8Array, bufferCreator: Uint8Array, actionAccounts: AccountMeta[], auth: Uint8Array): Instruction {
  if (auth.length !== AUTH_LEN) throw new Error('bad authorization length');
  return { programId, keys: [w(feePayer, true), w(vault), w(keyAccount), w(buffer), w(bufferCreator), ...actionAccounts], data: concat(Uint8Array.of(TAG.executeWithBuffer), auth) };
}
/** `DepositSpl`: `source` (depositor's token account) → `vaultTokenAccount` (owned by `vault`). */
export function depositSpl(programId: Uint8Array, depositor: Uint8Array, source: Uint8Array, mint: Uint8Array, vaultTokenAccount: Uint8Array, vault: Uint8Array, tokenProgram: Uint8Array, amount: bigint, decimals: number): Instruction {
  return {
    programId,
    keys: [r(depositor, true), w(source), r(mint), w(vaultTokenAccount), r(vault), r(tokenProgram)],
    data: concat(Uint8Array.of(TAG.depositSpl), u64(amount), Uint8Array.of(decimals)),
  };
}
/** Associated Token Account `CreateIdempotent` (owner may be a vault PDA). */
export function createAtaIdempotent(payer: Uint8Array, owner: Uint8Array, mint: Uint8Array, tokenProgram: Uint8Array): Instruction {
  const ata = associatedTokenAddress(owner, mint, tokenProgram);
  return { programId: ASSOCIATED_TOKEN_PROGRAM_ID, keys: [w(payer, true), w(ata), r(owner), r(mint), r(SYSTEM_PROGRAM_ID), r(tokenProgram)], data: Uint8Array.of(1) };
}
/** WithdrawSpl action accounts: vault token account, mint, destination, token program [, fee recipient]. */
export function withdrawSplAccounts(vaultTokenAccount: Uint8Array, mint: Uint8Array, destination: Uint8Array, tokenProgram: Uint8Array, feeRecipient?: Uint8Array): AccountMeta[] {
  const v = [w(vaultTokenAccount), r(mint), w(destination), r(tokenProgram)];
  if (feeRecipient) v.push(w(feeRecipient));
  return v;
}
/** `ExecuteV2` (QSP-1 v2, signature inline; needs a v1 transaction). `policy` = PDA ["policy", vault]. */
export function executeV2(programId: Uint8Array, feePayer: Uint8Array, vault: Uint8Array, signerKey: Uint8Array, policy: Uint8Array, actionAccounts: AccountMeta[], auth: Uint8Array, signature: Uint8Array): Instruction {
  if (auth.length !== 317 || signature.length !== SIGNATURE_LEN) throw new Error('bad v2 authorization or signature length');
  return { programId, keys: [w(feePayer, true), w(vault), w(signerKey), w(policy), ...actionAccounts], data: concat(Uint8Array.of(TAG.executeV2), auth, signature) };
}
/** `ExecuteV2WithBuffer`. */
export function executeV2WithBuffer(programId: Uint8Array, feePayer: Uint8Array, vault: Uint8Array, signerKey: Uint8Array, policy: Uint8Array, buffer: Uint8Array, bufferCreator: Uint8Array, actionAccounts: AccountMeta[], auth: Uint8Array): Instruction {
  if (auth.length !== 317) throw new Error('bad v2 authorization length');
  return {
    programId,
    keys: [w(feePayer, true), w(vault), w(signerKey), w(policy), w(buffer), w(bufferCreator), ...actionAccounts],
    data: concat(Uint8Array.of(TAG.executeV2WithBuffer), auth),
  };
}
/** `CloseProposal` (permissionless for dead proposals). */
export function closeProposal(programId: Uint8Array, vault: Uint8Array, proposal: Uint8Array, rentPayer: Uint8Array): Instruction {
  return { programId, keys: [r(vault), w(proposal), w(rentPayer)], data: Uint8Array.of(TAG.closeProposal) };
}
