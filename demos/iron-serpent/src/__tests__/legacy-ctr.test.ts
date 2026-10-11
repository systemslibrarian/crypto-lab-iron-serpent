import {beforeAll, expect, it} from 'vitest';
import {initSerpent} from '../serpent';
import {SerpentCTR} from '../serpent-ctr';

beforeAll(initSerpent);

// Captured independently from the current main's leviathan-crypto@1.4.0.
// Public key/nonce/plaintext; this protects saved iron-serpent-v1 payloads
// against a silent byte-order change while the library is migrated.
const legacyCiphertext = '77897210c0a1e427d5b5c1077b8d675306c9ad629ff1ddde9d27ec0b63b43ab7c63b96bd2f89b624b1e895351ac9fa5b8cea2df5063e88cf86ed75c9fe';

it('preserves legacy CTR bytes, partial blocks and carry without modifying inputs', () => {
  const key = Uint8Array.from({length: 32}, (_, i) => i);
  const nonce = Uint8Array.from({length: 16}, (_, i) => i);
  nonce[0] = 255;
  for (const size of [0, 1, 15, 16, 17, 33, 61]) {
    const plain = Uint8Array.from({length: size}, (_, i) => i);
    const before = [key.slice(), nonce.slice(), plain.slice()];
    const ctr = new SerpentCTR();
    try {
      const cipher = ctr.encrypt(key, nonce, plain);
      expect(Buffer.from(cipher).toString('hex')).toBe(legacyCiphertext.slice(0, size * 2));
      expect(ctr.decrypt(key, nonce, cipher)).toEqual(plain);
      expect([key, nonce, plain]).toEqual(before);
    } finally {
      ctr.dispose();
    }
  }
});
