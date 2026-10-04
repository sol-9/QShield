/** Byte helpers (little-endian, hex, base58). */
import { base58, hex } from '@scure/base';

export const toHex = (b: Uint8Array): string => hex.encode(b);
export const fromHex = (s: string): Uint8Array => hex.decode(s.toLowerCase());
export const toBase58 = (b: Uint8Array): string => base58.encode(b);
export const fromBase58 = (s: string): Uint8Array => base58.decode(s);

/** Parses a 32-byte Solana address (base58) or throws. */
export function address(s: string): Uint8Array {
  const b = fromBase58(s);
  if (b.length !== 32) throw new Error(`not a 32-byte address: ${s}`);
  return b;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

export const U64_MAX = (1n << 64n) - 1n;
export const I64_MAX = (1n << 63n) - 1n;
export const I64_MIN = -(1n << 63n);

export function writeU64(out: Uint8Array, off: number, v: bigint): void {
  if (v < 0n || v > U64_MAX) throw new RangeError('u64 out of range');
  new DataView(out.buffer, out.byteOffset).setBigUint64(off, v, true);
}
export function writeI64(out: Uint8Array, off: number, v: bigint): void {
  if (v < I64_MIN || v > I64_MAX) throw new RangeError('i64 out of range');
  new DataView(out.buffer, out.byteOffset).setBigInt64(off, v, true);
}
export const readU64 = (b: Uint8Array, off: number): bigint => new DataView(b.buffer, b.byteOffset).getBigUint64(off, true);
export const readI64 = (b: Uint8Array, off: number): bigint => new DataView(b.buffer, b.byteOffset).getBigInt64(off, true);
export const readU16 = (b: Uint8Array, off: number): number => new DataView(b.buffer, b.byteOffset).getUint16(off, true);
export const readU32 = (b: Uint8Array, off: number): number => new DataView(b.buffer, b.byteOffset).getUint32(off, true);

export const isZero = (b: Uint8Array): boolean => b.every((x) => x === 0);
export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
