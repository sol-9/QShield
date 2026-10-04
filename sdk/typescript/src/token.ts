/**
 * SPL Token / Token-2022 helpers (ADR-0015): program ids, account parsing,
 * the mint extension policy (identical to the on-chain program's, checked
 * against tests/vectors/sdk/interop-v1.json), associated token addresses and
 * decimal amounts.
 */
import { address, equal, readU16, readU32, readU64 } from './bytes.js';
import { findProgramAddress } from './pda.js';
import { AssetType } from './qsp1.js';

export const TOKEN_PROGRAM_ID = address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const TOKEN_2022_PROGRAM_ID = address('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
export const ASSOCIATED_TOKEN_PROGRAM_ID = address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');

export const MINT_LEN = 82;
export const TOKEN_ACCOUNT_LEN = 165;
const MULTISIG_LEN = 355;
const ACCOUNT_TYPE_MINT = 1;
const ACCOUNT_TYPE_ACCOUNT = 2;

/** Token-2022 extension type names, by number. */
export const EXTENSION_NAMES: Record<number, string> = {
  1: 'TransferFeeConfig', 2: 'TransferFeeAmount', 3: 'MintCloseAuthority', 4: 'ConfidentialTransferMint',
  5: 'ConfidentialTransferAccount', 6: 'DefaultAccountState', 7: 'ImmutableOwner', 8: 'MemoTransfer',
  9: 'NonTransferable', 10: 'InterestBearingConfig', 11: 'CpiGuard', 12: 'PermanentDelegate',
  13: 'NonTransferableAccount', 14: 'TransferHook', 15: 'TransferHookAccount', 16: 'ConfidentialTransferFeeConfig',
  17: 'ConfidentialTransferFeeAmount', 18: 'MetadataPointer', 19: 'TokenMetadata', 20: 'GroupPointer',
  21: 'TokenGroup', 22: 'GroupMemberPointer', 23: 'TokenGroupMember', 24: 'ConfidentialMintBurn',
  25: 'ScaledUiAmount', 26: 'Pausable', 27: 'PausableAccount', 28: 'PermissionedBurn',
};

/** Mint extensions the program accepts; everything else fails closed. */
export const MINT_EXTENSIONS_ALLOWED: readonly number[] = [3, 18, 19, 20, 21, 22, 23];

/** Program error codes for mint/token-account problems (docs/PROTOCOL.md). */
export class TokenPolicyError extends Error {
  constructor(readonly code: 'InvalidMint' | 'UnsupportedTokenExtension' | 'InvalidTokenAccount', message: string) {
    super(message);
  }
}

export interface MintInfo {
  decimals: number;
  supply: bigint;
  hasFreezeAuthority: boolean;
  /** Token-2022 extension types (empty for a base mint). */
  extensions: number[];
}

export interface TokenAccountInfo {
  mint: Uint8Array;
  owner: Uint8Array;
  amount: bigint;
  frozen: boolean;
}

export function assetTypeFor(program: Uint8Array): AssetType | null {
  if (equal(program, TOKEN_PROGRAM_ID)) return AssetType.SplToken;
  if (equal(program, TOKEN_2022_PROGRAM_ID)) return AssetType.Token2022;
  return null;
}

export function tokenProgramFor(asset: AssetType): Uint8Array | null {
  if (asset === AssetType.SplToken) return TOKEN_PROGRAM_ID;
  if (asset === AssetType.Token2022) return TOKEN_2022_PROGRAM_ID;
  return null;
}

function coption(d: Uint8Array, off: number): boolean {
  const t = readU32(d, off);
  if (t > 1) throw new TokenPolicyError('InvalidMint', 'malformed COption');
  return t === 1;
}

function extensions(tlv: Uint8Array): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < tlv.length) {
    if (tlv.length - i < 2) break;
    const t = readU16(tlv, i);
    if (t === 0) break;
    if (tlv.length - i < 4) throw new TokenPolicyError('InvalidMint', 'truncated extension header');
    const end = i + 4 + readU16(tlv, i + 2);
    if (end > tlv.length) throw new TokenPolicyError('InvalidMint', 'truncated extension value');
    out.push(t);
    i = end;
  }
  return out;
}

/** Parses a mint owned by `program` and applies the extension policy (throws if unsupported). */
export function parseMint(program: Uint8Array, d: Uint8Array): MintInfo {
  const is2022 = equal(program, TOKEN_2022_PROGRAM_ID);
  const baseOk =
    d.length === MINT_LEN ||
    (is2022 && d.length > TOKEN_ACCOUNT_LEN && d.length !== MULTISIG_LEN && d[TOKEN_ACCOUNT_LEN] === ACCOUNT_TYPE_MINT && d.subarray(MINT_LEN, TOKEN_ACCOUNT_LEN).every((b) => b === 0));
  if (!baseOk) throw new TokenPolicyError('InvalidMint', 'not a mint of this token program');
  coption(d, 0);
  const supply = readU64(d, 36);
  const decimals = d[44]!;
  if (d[45] !== 1) throw new TokenPolicyError('InvalidMint', 'mint not initialized');
  const hasFreezeAuthority = coption(d, 46);
  const exts = d.length > MINT_LEN ? extensions(d.subarray(TOKEN_ACCOUNT_LEN + 1)) : [];
  const bad = exts.filter((t) => !MINT_EXTENSIONS_ALLOWED.includes(t));
  if (bad.length) {
    throw new TokenPolicyError('UnsupportedTokenExtension', `unsupported Token-2022 extensions: ${bad.map((t) => EXTENSION_NAMES[t] ?? `Unknown(${t})`).join(', ')}`);
  }
  return { decimals, supply, hasFreezeAuthority, extensions: exts };
}

/** Parses the base fields of a token account owned by `program`. */
export function parseTokenAccount(program: Uint8Array, d: Uint8Array): TokenAccountInfo {
  const is2022 = equal(program, TOKEN_2022_PROGRAM_ID);
  const baseOk = d.length === TOKEN_ACCOUNT_LEN || (is2022 && d.length > TOKEN_ACCOUNT_LEN && d.length !== MULTISIG_LEN && d[TOKEN_ACCOUNT_LEN] === ACCOUNT_TYPE_ACCOUNT);
  if (!baseOk || (d[108] !== 1 && d[108] !== 2)) throw new TokenPolicyError('InvalidTokenAccount', 'not a token account of this program');
  return { mint: d.slice(0, 32), owner: d.slice(32, 64), amount: readU64(d, 64), frozen: d[108] === 2 };
}

/** Associated token account of `owner` (may be a vault PDA) for `mint`. */
export function associatedTokenAddress(owner: Uint8Array, mint: Uint8Array, tokenProgram: Uint8Array): Uint8Array {
  return findProgramAddress([owner, tokenProgram, mint], ASSOCIATED_TOKEN_PROGRAM_ID)[0];
}

/** Base units → decimal string (`1500000`, 6 → `1.500000`); same output as the Rust SDK. */
export function formatTokenAmount(amount: bigint, decimals: number): string {
  if (decimals === 0) return amount.toString();
  const scale = 10n ** BigInt(decimals);
  // u128 overflow in Rust above 38 decimals.
  if (decimals > 38) return `${amount}e-${decimals}`;
  return `${amount / scale}.${(amount % scale).toString().padStart(decimals, '0')}`;
}

/** Decimal string → base units; rejects excess precision and u64 overflow. */
export function parseTokenAmount(s: string, decimals: number): bigint {
  if (!/^\d*(\.\d*)?$/.test(s) || s === '' || s === '.') throw new Error(`invalid token amount ${JSON.stringify(s)}`);
  const [whole = '', frac = ''] = s.split('.');
  if (decimals > 38) throw new Error(`invalid token amount ${JSON.stringify(s)}`);
  if (frac.length > decimals) throw new Error(`${s} has more than ${decimals} decimal places`);
  const v = BigInt(whole || '0') * 10n ** BigInt(decimals) + BigInt((frac || '0').padEnd(decimals, '0') || '0');
  if (v >= 1n << 64n) throw new Error(`invalid token amount ${JSON.stringify(s)}`);
  return v;
}
