/**
 * The CTR explainer claims to show the exact construction SerpentCtr uses.
 * These tests hold it to that: the manually-built keystream (Serpent-ECB over
 * counter blocks) must match SerpentCtr's real output byte-for-byte, including
 * across a carry boundary in the little-endian counter increment.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initSerpent, Serpent256 } from '../serpent';
import { SerpentCTR } from '../serpent-ctr';
import { counterBlock, xorBytes, BLOCK_SIZE } from '../ctr-explainer';

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('CTR explainer construction', () => {
  beforeAll(async () => {
    await initSerpent();
  });

  it('counterBlock increments little-endian with carry', () => {
    const nonce = new Uint8Array(16);
    nonce[0] = 0xff;
    nonce[1] = 0xff;
    nonce[2] = 0x01;

    expect(bytesToHex(counterBlock(nonce, 0))).toBe(bytesToHex(nonce));

    const plusOne = counterBlock(nonce, 1);
    expect(plusOne[0]).toBe(0x00); // 0xff rolls over…
    expect(plusOne[1]).toBe(0x00); // …carry propagates…
    expect(plusOne[2]).toBe(0x02); // …and stops here
    expect(plusOne[3]).toBe(0x00);
  });

  it('manual counter/keystream/XOR matches SerpentCtr exactly (multi-block, carry boundary)', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    nonce[0] = 0xff; // force a carry between block 0 and block 1
    const plaintext = new TextEncoder().encode(
      'CTR mode turns a block cipher into a stream cipher — 61 bytes.!'
    );

    const ctr = new SerpentCTR();
    const expected = ctr.encrypt(key, nonce, plaintext);
    ctr.dispose();

    const ecb = new Serpent256();
    ecb.loadKey(key);
    const manual = new Uint8Array(plaintext.length);
    for (let i = 0; i * BLOCK_SIZE < plaintext.length; i++) {
      const keystream = ecb.encryptBlock(counterBlock(nonce, i));
      const chunk = plaintext.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
      manual.set(xorBytes(chunk, keystream.subarray(0, chunk.length)), i * BLOCK_SIZE);
    }
    ecb.dispose();

    expect(bytesToHex(manual)).toBe(bytesToHex(expected));
  });

  it('xorBytes is its own inverse (decryption is the same operation)', () => {
    const a = new Uint8Array(16);
    const b = new Uint8Array(16);
    crypto.getRandomValues(a);
    crypto.getRandomValues(b);
    expect(bytesToHex(xorBytes(xorBytes(a, b), b))).toBe(bytesToHex(a));
  });
});
