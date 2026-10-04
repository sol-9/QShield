import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, it } from 'vitest';
import { fromHex, toHex, utf8 } from '../src/bytes.js';
import { LocalKey } from '../src/keys.js';
import { phraseFromSeed, quizPositions, seedFromPhrase } from '../src/recovery.js';
import { WORDLIST } from '../src/wordlist.js';

const V = JSON.parse(readFileSync(new URL('../../../tests/vectors/recovery/recovery-v1.json', import.meta.url), 'utf8'));

describe('recovery phrase (shared vectors with Rust)', () => {
  it('word list is BIP-39 English', () => {
    expect(toHex(sha256(utf8(WORDLIST.join('\n') + '\n')))).toBe(V.wordlist_sha256);
  });
  it('vectors', () => {
    for (const v of V.vectors) {
      expect(phraseFromSeed(fromHex(v.seed_hex))).toBe(v.phrase);
      expect(toHex(seedFromPhrase(v.phrase))).toBe(v.seed_hex);
      expect(toHex(seedFromPhrase(v.phrase.split(' ').map((w: string) => w.slice(0, 4).toUpperCase()).join('   ')))).toBe(v.seed_hex);
      expect(toHex(LocalKey.fromSeed(fromHex(v.seed_hex)).keyId)).toBe(v.key_id_hex);
    }
    for (const bad of V.invalid) expect(() => seedFromPhrase(bad)).toThrow();
    const ws = V.vectors[2].phrase.split(' ');
    [ws[0], ws[1]] = [ws[1], ws[0]];
    expect(() => seedFromPhrase(ws.join(' '))).toThrow(/checksum/);
  });
  it('quiz positions', () => {
    const q = quizPositions(4);
    expect(q).toHaveLength(4);
    expect(new Set(q).size).toBe(4);
    expect(q.every((p) => p >= 1 && p <= 24)).toBe(true);
  });
});
