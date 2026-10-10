import { describe, it, expect } from 'vitest';
import { estimateStrength } from '../passphrase-strength';

describe('typed passphrase evidence boundary', () => {
  for (const value of [
    'aaaaaaaaaaaaaaaaaaaa',
    'passwordpasswordpassword',
    '12345678901234567890',
    'abcdefabcdefabcdef',
    'qwertyqwertyqwerty',
    'Password1!Password1!',
    'battery horse stapler cloud',
    'K9$mQ2#vX7@pL4!wN8&zR5^tB3*d',
  ]) {
    it(`does not infer a generation process or crack time from ${JSON.stringify(value)}`, () => {
      const result = estimateStrength(value);
      expect(result.bits).toBeNull();
      expect(result.score).toBeNull();
      expect(result.crackTime).toBeNull();
      expect(result.label).toBe('not estimated');
      expect(result).toHaveProperty('explanation', expect.stringContaining('independent, uniform random'));
      expect(result).toHaveProperty('explanation', expect.stringContaining('not measured'));
      expect(result).toHaveProperty('explanation', expect.not.stringMatching(/excellent|million years|10,000/));
    });
  }

  it('counts Unicode code points rather than treating surrogate halves as extra evidence', () => {
    expect(estimateStrength('🔐🔐e\u0301')).toMatchObject({ characterCount: 4 });
  });

  it('does not expose the entered passphrase in its returned guidance', () => {
    const value = 'my private secret 4429';
    expect(JSON.stringify(estimateStrength(value))).not.toContain(value);
  });

  it('gives known-example warnings without claiming a complete blocklist or instant cracking', () => {
    const result = estimateStrength('  Trustno1  ');
    expect(result.label).toBe('well-known');
    expect(result.warning).toContain('small example list');
    expect(result.crackTime).toBeNull();
    expect(result.bits).toBeNull();
  });
});
