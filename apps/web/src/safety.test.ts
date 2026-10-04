import { describe, expect, it } from 'vitest';
import { AssetType, address, associatedTokenAddress, toBase58, TOKEN_PROGRAM_ID } from '@qshield/sdk';
import { chunkAddress, fingerprint, lookalike, proposalRecipient } from './safety.js';

describe('review-screen safety helpers', () => {
  const real = '4Hd7kP2xQwErTyUiOpAsDfGhJkLzXcVbNmx9Q2Lm';
  it('chunks', () => {
    expect(chunkAddress(real)).toBe('4Hd7 kP2x … x9Q2 Lm'.replace('x9Q2 Lm', real.slice(-8, -4) + ' ' + real.slice(-4)));
    expect(chunkAddress('short')).toBe('short');
  });
  it('detects look-alike addresses (address poisoning)', () => {
    const poison = '4Hd7' + 'Z'.repeat(real.length - 8) + real.slice(-4);
    expect(lookalike(poison, [real])).toBe(real);
    expect(lookalike(real, [real])).toBeNull();
    expect(lookalike('So11111111111111111111111111111111111111112', [real])).toBeNull();
  });
  it('fingerprints are stable 4-word codes', () => {
    const f = fingerprint(new Uint8Array([1, 2, 3]));
    expect(f.split('-')).toHaveLength(4);
    expect(fingerprint(new Uint8Array([1, 2, 3]))).toBe(f);
    expect(fingerprint(new Uint8Array([1, 2, 4]))).not.toBe(f);
  });
});

describe('proposalRecipient', () => {
  const mint = address('So11111111111111111111111111111111111111112');
  const user = 'Vote111111111111111111111111111111111111111';
  const attacker = 'Stake11111111111111111111111111111111111111';
  const ata = (o: string) => associatedTokenAddress(address(o), mint, TOKEN_PROGRAM_ID);
  it('shows the owner only when the token account is its associated account', () => {
    const p = { assetType: AssetType.SplToken, mint, destination: ata(user) };
    expect(proposalRecipient(p, user)).toEqual({ shown: user, owner: user, mismatch: false });
  });
  it('flags a link whose owner does not own the paid token account', () => {
    const p = { assetType: AssetType.SplToken, mint, destination: ata(attacker) };
    expect(proposalRecipient(p, user)).toEqual({ shown: toBase58(ata(attacker)), owner: null, mismatch: true });
    expect(proposalRecipient(p, 'not-an-address').mismatch).toBe(true);
  });
  it('ignores the link for SOL and shows the raw account without one', () => {
    const p = { assetType: AssetType.Sol, mint: new Uint8Array(32), destination: address(user) };
    expect(proposalRecipient(p, attacker)).toEqual({ shown: user, owner: null, mismatch: false });
    const q = { assetType: AssetType.SplToken, mint, destination: ata(user) };
    expect(proposalRecipient(q, null).shown).toBe(toBase58(ata(user)));
  });
});
