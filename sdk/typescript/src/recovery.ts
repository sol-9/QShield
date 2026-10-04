/**
 * QShield recovery phrase v1 (same as crates/qshield-client/src/recovery.rs):
 * 24 BIP-39 English words encoding the 32-byte key seed plus an 8-bit
 * domain-separated checksum. The phrase is the key — never a password.
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, utf8 } from './bytes.js';
import { WORDLIST } from './wordlist.js';

const DOMAIN = utf8('QSHIELD_RECOVERY_PHRASE_V1');

function checksum(seed: Uint8Array): number {
  return sha256(concat(DOMAIN, Uint8Array.of(1), seed))[0]!;
}

export function phraseFromSeed(seed: Uint8Array): string {
  if (seed.length !== 32) throw new Error('seed must be 32 bytes');
  const bits = concat(seed, Uint8Array.of(checksum(seed)));
  const out: string[] = [];
  for (let i = 0; i < 24; i++) {
    let idx = 0;
    for (let b = 0; b < 11; b++) {
      const bit = i * 11 + b;
      idx = (idx << 1) | ((bits[bit >> 3]! >> (7 - (bit & 7))) & 1);
    }
    out.push(WORDLIST[idx]!);
  }
  bits.fill(0);
  return out.join(' ');
}

/** Decodes a phrase (any case/whitespace; unique 4-letter prefixes accepted). Throws on error. */
export function seedFromPhrase(phrase: string): Uint8Array {
  const ws = phrase.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (ws.length !== 24) throw new Error(`a recovery phrase has 24 words, got ${ws.length}`);
  const bits = new Uint8Array(33);
  ws.forEach((w, i) => {
    let idx = WORDLIST.indexOf(w);
    if (idx < 0 && w.length >= 4) {
      const m = WORDLIST.flatMap((x, j) => (x.startsWith(w) ? [j] : []));
      if (m.length === 1) idx = m[0]!;
    }
    if (idx < 0) throw new Error(`word ${i + 1} is not in the word list`);
    for (let b = 0; b < 11; b++) {
      if ((idx >> (10 - b)) & 1) {
        const bit = i * 11 + b;
        bits[bit >> 3]! |= 1 << (7 - (bit & 7));
      }
    }
  });
  const seed = bits.slice(0, 32);
  const ok = checksum(seed) === bits[32];
  bits.fill(0);
  if (!ok) {
    seed.fill(0);
    throw new Error('the recovery phrase checksum does not match (a word is wrong or out of order)');
  }
  return seed;
}

/** Words to quiz the user on after showing the phrase (positions, 1-based). */
export function quizPositions(n = 4): number[] {
  const picks = new Set<number>();
  const r = crypto.getRandomValues(new Uint32Array(32));
  for (const x of r) {
    picks.add((x % 24) + 1);
    if (picks.size === n) break;
  }
  return [...picks].sort((a, b) => a - b);
}
