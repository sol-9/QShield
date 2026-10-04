/** Program-derived addresses (same algorithm as Solana's `find_program_address`). */
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, utf8, writeU64 } from './bytes.js';

const PDA_MARKER = utf8('ProgramDerivedAddress');

function onCurve(b: Uint8Array): boolean {
  try {
    // curve25519-dalek's decompression accepts non-canonical y (ZIP-215 rules).
    ed25519.Point.fromBytes(b, true);
    return true;
  } catch {
    return false;
  }
}

export function createProgramAddress(seeds: Uint8Array[], programId: Uint8Array): Uint8Array | null {
  if (seeds.length > 16 || seeds.some((s) => s.length > 32)) throw new Error('invalid seeds');
  const h = sha256(concat(...seeds, programId, PDA_MARKER));
  return onCurve(h) ? null : h;
}

export function findProgramAddress(seeds: Uint8Array[], programId: Uint8Array): [Uint8Array, number] {
  for (let bump = 255; bump >= 0; bump--) {
    const a = createProgramAddress([...seeds, Uint8Array.of(bump)], programId);
    if (a) return [a, bump];
  }
  throw new Error('no viable bump');
}

/** Vault PDA `["vault", initial_key_id, vault_seed]`. */
export function vaultAddress(programId: Uint8Array, initialKeyId: Uint8Array, vaultSeed: Uint8Array): [Uint8Array, number] {
  return findProgramAddress([utf8('vault'), initialKeyId, vaultSeed], programId);
}

/** Signature buffer PDA `["sigbuf", vault, creator, buffer_id_le]`. */
export function sigBufferAddress(programId: Uint8Array, vault: Uint8Array, creator: Uint8Array, bufferId: bigint): [Uint8Array, number] {
  const id = new Uint8Array(8);
  writeU64(id, 0, bufferId);
  return findProgramAddress([utf8('sigbuf'), vault, creator, id], programId);
}

/** Vault seed from a human label, as the CLI does: SHA-256("qshield-vault-label:" ‖ label). */
export function vaultSeedFromLabel(label: string): Uint8Array {
  return sha256(concat(utf8('qshield-vault-label:'), utf8(label)));
}

/** Guardian policy PDA `["policy", vault]`. */
export function policyAddress(programId: Uint8Array, vault: Uint8Array): [Uint8Array, number] {
  return findProgramAddress([utf8('policy'), vault], programId);
}

/** Proposal PDA `["proposal", vault, id_le]` (id = the vault nonce the proposal consumed). */
export function proposalAddress(programId: Uint8Array, vault: Uint8Array, id: bigint): [Uint8Array, number] {
  const b = new Uint8Array(8);
  writeU64(b, 0, id);
  return findProgramAddress([utf8('proposal'), vault, b], programId);
}
