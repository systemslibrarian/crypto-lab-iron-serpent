import { describe, it, expect } from 'vitest';
import { estimateStrength } from '../passphrase-strength';

describe('passphrase strength estimator', () => {
  it('rates an empty passphrase as zero', () => {
    const est = estimateStrength('');
    expect(est.bits).toBe(0);
    expect(est.score).toBe(0);
  });

  it('flags well-known passphrases regardless of apparent entropy', () => {
    for (const known of ['password', 'correct horse battery staple', 'Trustno1']) {
      const est = estimateStrength(known);
      expect(est.score).toBe(0);
      expect(est.warning).toBeTruthy();
      expect(est.crackTime).toBe('instantly');
    }
  });

  it('is monotonic in length for the same charset', () => {
    const short = estimateStrength('abcdef');
    const long = estimateStrength('abcdefabcdefabcdef');
    expect(long.bits).toBeGreaterThan(short.bits);
  });

  it('scores mixed-charset passwords above same-length lowercase', () => {
    const lower = estimateStrength('abcdefghij');
    const mixed = estimateStrength('aB3$eFgH1j');
    expect(mixed.bits).toBeGreaterThan(lower.bits);
  });

  it('uses the word model (not charset model) for word passphrases', () => {
    // 4 dictionary words = ~52 bits under the word model; the charset model
    // would claim ~131 bits for 28 lowercase+space chars. Report the honest one.
    const est = estimateStrength('battery horse stapler cloud');
    expect(est.bits).toBeLessThan(60);
    expect(est.bits).toBeGreaterThan(45);
  });

  it('rates a long random passphrase as excellent', () => {
    const est = estimateStrength('K9$mQ2#vX7@pL4!wN8&zR5^tB3*d');
    expect(est.score).toBe(4);
  });
});
