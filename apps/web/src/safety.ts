/**
 * Review-screen defences that work without trusting the network: address
 * chunking, look-alike detection (address poisoning) and short word
 * fingerprints to compare two screens (wallet and guardian device).
 */
import {
  AssetType,
  WORDLIST,
  address,
  associatedTokenAddress,
  sha256,
  toBase58,
  tokenProgramFor,
  type ProposalState,
} from '@qshield/sdk';

/** `4Hd7 kP2x … x9Q2 Lm3a`: first and last 8 characters in groups of 4. */
export function chunkAddress(a: string): string {
  if (a.length <= 16) return a;
  const g = (s: string) => s.match(/.{1,4}/g)!.join(' ');
  return `${g(a.slice(0, 8))} … ${g(a.slice(-8))}`;
}

/**
 * Returns a known address that looks like `dest` (same first 4 and last 4
 * characters) but is different — the pattern of address-poisoning scams.
 */
export function lookalike(dest: string, known: readonly string[]): string | null {
  for (const k of known) {
    if (k !== dest && k.slice(0, 4) === dest.slice(0, 4) && k.slice(-4) === dest.slice(-4)) return k;
  }
  return null;
}

/** Four words derived from bytes (SHA-256, 11 bits per word) to compare across devices. */
export function fingerprint(bytes: Uint8Array): string {
  const h = sha256(bytes);
  const out: string[] = [];
  for (let i = 0; i < 4; i++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const bit = i * 11 + b;
      idx = (idx << 1) | ((h[bit >> 3]! >> (7 - (bit & 7))) & 1);
    }
    out.push(WORDLIST[idx]!);
  }
  return out.join('-');
}

/**
 * Match code for a proposal: both the proposing wallet and the guardian page
 * compute it from the proposal's effect, so the user can check that both
 * screens describe the same send.
 */
export function proposalCode(vault: Uint8Array, id: bigint, mint: Uint8Array, destination: Uint8Array, amount: bigint): string {
  const n = new Uint8Array(16);
  const dv = new DataView(n.buffer);
  dv.setBigUint64(0, id, true);
  dv.setBigUint64(8, amount, true);
  const all = new Uint8Array(32 * 3 + 16);
  all.set(vault, 0);
  all.set(mint, 32);
  all.set(destination, 64);
  all.set(n, 96);
  return fingerprint(all);
}

/**
 * The recipient to show for a proposal. A token send pays a token account;
 * the wallet that owns it comes from the link (`owner`), which the computer
 * that made the proposal controls. It is shown only if the token account
 * really is that wallet's associated account for this mint; otherwise the
 * raw token account is shown and `mismatch` is set.
 */
export function proposalRecipient(
  p: Pick<ProposalState, 'assetType' | 'mint' | 'destination'>,
  owner: string | null,
): { shown: string; owner: string | null; mismatch: boolean } {
  const raw = toBase58(p.destination);
  if (p.assetType === AssetType.Sol || owner === null) return { shown: raw, owner: null, mismatch: false };
  const program = tokenProgramFor(p.assetType);
  let ok = false;
  try {
    ok = program !== null && toBase58(associatedTokenAddress(address(owner), p.mint, program)) === raw;
  } catch {
    ok = false;
  }
  return ok ? { shown: owner, owner, mismatch: false } : { shown: raw, owner: null, mismatch: true };
}
