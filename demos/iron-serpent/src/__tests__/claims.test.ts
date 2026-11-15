/**
 * The prose this lab prints beside its own code, held to the code.
 *
 * Two statements had drifted: the Encrypt pipeline diagram showed a shorter HMAC
 * input than crypto.ts actually authenticates, and the README's nonce-reuse
 * warning claimed more than XORing two ciphertexts yields. Both are read back
 * from the source here so neither can drift again.
 *
 * The README lives at the repository root, two levels above this package, which
 * is where vitest runs from.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { xorBytes } from '../ctr-explainer';

const read = (relativePath: string): string =>
  readFileSync(resolve(process.cwd(), relativePath), 'utf-8');

const toHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * The arguments of each `concat(...)` that builds an HMAC input in crypto.ts,
 * as field names: `ciphertextBytes` and `versionBytes` name the same fields the
 * diagram calls `ciphertext` and `version`.
 */
function macInputFields(): string[][] {
  const matches = [...read('src/crypto.ts').matchAll(/const macData = concat\(([^)]*)\)/g)];
  expect(matches.length, 'crypto.ts no longer builds macData with concat(...)').toBe(2);
  return matches.map((m) => m[1].split(',').map((arg) => arg.trim().replace(/Bytes$/, '')));
}

describe('the page text matches the code it describes', () => {
  it('encrypt and decrypt authenticate the same fields', () => {
    const [onEncrypt, onDecrypt] = macInputFields();
    expect(onEncrypt).toEqual(['salt', 'nonce', 'ciphertext', 'version']);
    expect(onDecrypt).toEqual(onEncrypt);
  });

  it('the pipeline diagram shows every field the HMAC covers, in order', () => {
    const stage = read('index.html').match(/HMAC-SHA256\(macKey,\s*([^)]*)\)/);
    expect(stage, 'index.html has no HMAC stage in the pipeline diagram').not.toBeNull();
    // &#8214; is the double vertical bar the diagram puts between fields.
    const shown = stage![1].split('&#8214;').map((field) => field.trim());
    expect(shown).toEqual(macInputFields()[0]);
  });

  it('the tamper panel names the same MAC input as the diagram', () => {
    expect(read('src/main.ts')).toContain('covers salt‖nonce‖ciphertext‖version');
  });

  it('the nonce-reuse warning claims only what the XOR actually yields', () => {
    const keystream = new Uint8Array([
      0x9e, 0x3f, 0x01, 0xa7, 0x55, 0xc8, 0x12, 0xbb,
      0x04, 0xde, 0x7a, 0x60, 0x33, 0x91, 0xff, 0x2c,
    ]);
    const pt1 = new TextEncoder().encode('attack at dawn!!');
    const pt2 = new TextEncoder().encode('retreat at noon!');
    const ct1 = xorBytes(pt1, keystream);
    const ct2 = xorBytes(pt2, keystream);

    // What the attacker gets, and all they get: the XOR of the two plaintexts.
    const leaked = xorBytes(ct1, ct2);
    expect(toHex(leaked)).toBe(toHex(xorBytes(pt1, pt2)));
    expect(toHex(leaked)).not.toBe(toHex(keystream));
    expect(toHex(leaked)).not.toBe(toHex(pt1));
    expect(toHex(leaked)).not.toBe(toHex(pt2));

    // Either plaintext follows only once the other is known or guessed.
    expect(toHex(xorBytes(leaked, pt1))).toBe(toHex(pt2));
    expect(toHex(xorBytes(ct1, pt1))).toBe(toHex(keystream));

    const bullet = read('../../README.md')
      .split('\n')
      .find((line) => line.includes('Counter/nonce reuse under the same key'));
    expect(bullet, '"What Can Go Wrong" has no counter/nonce-reuse bullet').toBeDefined();
    expect(bullet).toContain('CT1 ⊕ CT2 = PT1 ⊕ PT2');
    expect(bullet).not.toContain('recovers the keystream and both plaintexts');
  });
});
