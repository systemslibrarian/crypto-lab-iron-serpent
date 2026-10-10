import { describe, it, expect } from 'vitest';
import { estimateStrength } from '../passphrase-strength';

describe('passphrase guidance', () => {
  it('identifies an empty input without inventing a measurement', () => {
    const est = estimateStrength('');
    expect(est.characterCount).toBe(0);
    expect(est.label).toBe('empty');
    expect(est.bits).toBeNull();
  });

  it('flags its public examples regardless of apparent complexity', () => {
    for (const known of ['password', 'correct horse battery staple', 'Trustno1']) {
      const est = estimateStrength(known);
      expect(est.label).toBe('well-known');
      expect(est.warning).toBeTruthy();
      expect(est.crackTime).toBeNull();
    }
  });

  it('reports longer input as longer without treating repeated length as strength', () => {
    const short = estimateStrength('abcdef');
    const long = estimateStrength('abcdefabcdefabcdef');
    expect(long.characterCount).toBeGreaterThan(short.characterCount);
    expect(long.bits).toBeNull();
    expect(short.bits).toBeNull();
  });

  it('does not award a strength score for mixing character classes', () => {
    const lower = estimateStrength('abcdefghij');
    const mixed = estimateStrength('aB3$eFgH1j');
    expect(mixed.score).toBeNull();
    expect(lower.score).toBeNull();
  });

  it('does not assume typed words were independently sampled from a Diceware list', () => {
    const est = estimateStrength('battery horse stapler cloud');
    expect(est.bits).toBeNull();
    expect(est.explanation).toContain('word selection');
  });

  it('keeps the generation process unknown even when the input looks random', () => {
    const est = estimateStrength('K9$mQ2#vX7@pL4!wN8&zR5^tB3*d');
    expect(est.score).toBeNull();
    expect(est.label).toBe('not estimated');
  });
});
