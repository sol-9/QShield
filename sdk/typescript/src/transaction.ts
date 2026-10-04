/**
 * Legacy Solana transactions: message compilation (same account ordering as
 * `solana-message`, checked byte-for-byte against Rust in the interop
 * vectors), wire serialization, and local Ed25519 signing. Used by the web
 * wallet to create vaults and deposit; withdrawals go through a relayer.
 */
import { ed25519 } from '@noble/curves/ed25519.js';
import { address, concat, equal, toBase58 } from './bytes.js';
import type { Instruction } from './instructions.js';

/** Solana's legacy transaction size limit. */
export const PACKET_DATA_SIZE = 1232;
export const COMPUTE_BUDGET_PROGRAM_ID = address('ComputeBudget111111111111111111111111111111');

/** `ComputeBudgetInstruction::SetComputeUnitLimit`. */
export function setComputeUnitLimit(units: number): Instruction {
  const d = new Uint8Array(5);
  d[0] = 2;
  new DataView(d.buffer).setUint32(1, units, true);
  return { programId: COMPUTE_BUDGET_PROGRAM_ID, keys: [], data: d };
}

function shortvec(n: number): Uint8Array {
  const out: number[] = [];
  let v = n;
  for (;;) {
    let b = v & 0x7f;
    v >>= 7;
    if (v === 0) {
      out.push(b);
      return Uint8Array.from(out);
    }
    b |= 0x80;
    out.push(b);
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return 0;
}

export interface CompiledMessage {
  /** Serialized legacy message (what signers sign). */
  bytes: Uint8Array;
  /** Accounts whose signatures are required, in signature order. */
  signers: Uint8Array[];
}

/** Compiles a legacy message (`Message::new_with_blockhash` equivalent). */
export function compileLegacyMessage(payer: Uint8Array, instructions: Instruction[], recentBlockhash: Uint8Array): CompiledMessage {
  const meta = new Map<string, { key: Uint8Array; signer: boolean; writable: boolean }>();
  const touch = (key: Uint8Array) => {
    const k = toBase58(key);
    let m = meta.get(k);
    if (!m) meta.set(k, (m = { key, signer: false, writable: false }));
    return m;
  };
  for (const ix of instructions) {
    touch(ix.programId);
    for (const a of ix.keys) {
      const m = touch(a.pubkey);
      m.signer ||= a.isSigner;
      m.writable ||= a.isWritable;
    }
  }
  const payerKey = toBase58(payer);
  meta.delete(payerKey);
  const rest = [...meta.values()].sort((a, b) => compareBytes(a.key, b.key));
  const ws = [payer, ...rest.filter((m) => m.signer && m.writable).map((m) => m.key)];
  const rs = rest.filter((m) => m.signer && !m.writable).map((m) => m.key);
  const wn = rest.filter((m) => !m.signer && m.writable).map((m) => m.key);
  const rn = rest.filter((m) => !m.signer && !m.writable).map((m) => m.key);
  const keys = [...ws, ...rs, ...wn, ...rn];
  if (keys.length > 256) throw new Error('too many accounts');
  const index = (k: Uint8Array) => keys.findIndex((x) => equal(x, k));
  const ixBytes = instructions.map((ix) =>
    concat(Uint8Array.of(index(ix.programId)), shortvec(ix.keys.length), Uint8Array.from(ix.keys.map((a) => index(a.pubkey))), shortvec(ix.data.length), ix.data),
  );
  const bytes = concat(Uint8Array.of(ws.length + rs.length, rs.length, rn.length), shortvec(keys.length), ...keys, recentBlockhash, shortvec(instructions.length), ...ixBytes);
  return { bytes, signers: [...ws, ...rs] };
}

/** Wire format: `shortvec(n) ‖ signatures ‖ message`. */
export function serializeTransaction(message: CompiledMessage, signatures: Uint8Array[]): Uint8Array {
  if (signatures.length !== message.signers.length || signatures.some((s) => s.length !== 64)) throw new Error('signature count/length mismatch');
  const tx = concat(shortvec(signatures.length), ...signatures, message.bytes);
  if (tx.length > PACKET_DATA_SIZE) throw new Error(`transaction of ${tx.length} bytes exceeds ${PACKET_DATA_SIZE}`);
  return tx;
}

/** An Ed25519 keypair held in memory (ephemeral key accounts, dev payers). */
export class LocalKeypair {
  private constructor(private readonly secret: Uint8Array, readonly publicKey: Uint8Array) {}
  static generate(): LocalKeypair {
    const s = crypto.getRandomValues(new Uint8Array(32));
    return new LocalKeypair(s, ed25519.getPublicKey(s));
  }
  static fromSeed(seed: Uint8Array): LocalKeypair {
    if (seed.length !== 32) throw new Error('seed must be 32 bytes');
    return new LocalKeypair(seed.slice(), ed25519.getPublicKey(seed));
  }
  /** 64-byte Solana keypair file format (seed ‖ public key). */
  toSolanaKeypairBytes(): Uint8Array {
    return concat(this.secret, this.publicKey);
  }
  sign(message: Uint8Array): Uint8Array {
    return ed25519.sign(message, this.secret);
  }
}

/**
 * Something that can sign for one account: a local keypair (`signMessage`) or
 * a browser wallet that signs whole serialized transactions
 * (`signTransaction`, e.g. Wallet Standard `solana:signTransaction`).
 */
export interface TxSigner {
  publicKey: Uint8Array;
  signMessage?(message: Uint8Array): Promise<Uint8Array>;
  signTransaction?(transaction: Uint8Array): Promise<Uint8Array>;
}

export function localSigner(k: LocalKeypair): TxSigner {
  return { publicKey: k.publicKey, signMessage: async (m) => k.sign(m) };
}

/**
 * Compiles, signs with every required signer and serializes. Local signers
 * sign first; a wallet signer (`signTransaction`) then receives the
 * partially signed transaction and returns it fully signed.
 */
export async function buildLegacyTransaction(payer: TxSigner, instructions: Instruction[], recentBlockhash: Uint8Array, extra: TxSigner[] = []): Promise<Uint8Array> {
  const msg = compileLegacyMessage(payer.publicKey, instructions, recentBlockhash);
  const all = [payer, ...extra];
  const sigs: Uint8Array[] = [];
  const wallets: TxSigner[] = [];
  for (const s of msg.signers) {
    const signer = all.find((x) => equal(x.publicKey, s));
    if (!signer) throw new Error(`missing signer ${toBase58(s)}`);
    if (signer.signMessage) {
      const sig = await signer.signMessage(msg.bytes);
      if (!ed25519.verify(sig, msg.bytes, s)) throw new Error(`invalid signature from ${toBase58(s)}`);
      sigs.push(sig);
    } else if (signer.signTransaction) {
      sigs.push(new Uint8Array(64));
      wallets.push(signer);
    } else {
      throw new Error(`signer ${toBase58(s)} cannot sign`);
    }
  }
  let tx = serializeTransaction(msg, sigs);
  for (const w of wallets) {
    const signed = await w.signTransaction!(tx);
    // The wallet must not change the message: compare everything after the signatures.
    if (!equal(signed.subarray(signed.length - msg.bytes.length), msg.bytes) || signed.length !== tx.length) {
      throw new Error('wallet modified the transaction');
    }
    tx = signed;
  }
  return tx;
}

/** First signature of a serialized transaction (its id), base58. */
export function transactionId(tx: Uint8Array): string {
  return toBase58(tx.subarray(1, 65));
}
