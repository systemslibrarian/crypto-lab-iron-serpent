/**
 * Proves the round-visualizer's reference Serpent (serpent-rounds.ts) is
 * spec-accurate: it must produce byte-identical output to (a) the official AES
 * submission test vectors and (b) the production WASM engine on random blocks.
 *
 * If this ever fails, the visualizer is lying about what the real cipher does,
 * so it is a hard gate.
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { encryptBlock, decryptBlock, encryptBlockTraced, SBOX } from '../serpent-rounds';
import { initSerpent, Serpent256 } from '../serpent';

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return bytes;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

describe('Serpent round-visualizer reference cipher', () => {
  it('matches official variable-text vector #1 (256-bit key)', () => {
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('80000000000000000000000000000000');
    expect(bytesToHex(encryptBlock(pt, key))).toBe('da5a7992b1b4ae6f8c004bc8a7de5520');
  });

  it('matches official variable-key vector #1 (256-bit key)', () => {
    const key = hexToBytes('8000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('00000000000000000000000000000000');
    expect(bytesToHex(encryptBlock(pt, key))).toBe('abed96e766bf28cbc0ebd21a82ef0819');
  });

  it('matches additional official variable-text vectors', () => {
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const vectors = [
      { pt: '40000000000000000000000000000000', ct: 'f351351b823e3d7a4f3bf390c4f198cb' },
      { pt: '20000000000000000000000000000000', ct: 'a477a65d9db75c8ed7218c52b64c65bb' },
      { pt: '10000000000000000000000000000000', ct: 'f8019452cba4fe618d80a6756183b2e0' },
    ];
    for (const v of vectors) {
      expect(bytesToHex(encryptBlock(hexToBytes(v.pt), key))).toBe(v.ct);
    }
  });

  it('round-trips encrypt→decrypt', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const pt = new Uint8Array(16);
    crypto.getRandomValues(pt);
    expect(bytesToHex(decryptBlock(encryptBlock(pt, key), key))).toBe(bytesToHex(pt));
  });

  it('produces byte-identical output to the production WASM engine on random blocks', async () => {
    await initSerpent();
    const cipher = new Serpent256();
    for (let i = 0; i < 25; i++) {
      const key = new Uint8Array(32);
      const pt = new Uint8Array(16);
      crypto.getRandomValues(key);
      crypto.getRandomValues(pt);
      cipher.loadKey(key);
      const wasm = cipher.encryptBlock(pt);
      const ref = encryptBlock(pt, key);
      expect(bytesToHex(ref)).toBe(bytesToHex(wasm));
    }
    cipher.dispose();
  });

  it('exposes a 32-stage trace whose final state equals the ciphertext', () => {
    const key = hexToBytes('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');
    const pt = hexToBytes('53657270656e742d3235362064656d6f');
    const trace = encryptBlockTraced(pt, key);
    expect(trace.stages).toHaveLength(32);
    expect(trace.stages[0].round).toBe(1);
    expect(trace.stages[31].round).toBe(32);
    expect(trace.stages[31].isFinal).toBe(true);
    // The last stage's output IS the ciphertext.
    expect(trace.ciphertext).toEqual(trace.stages[31].afterLinear);
  });

  it('S-boxes are genuine 4-bit permutations (each value 0..15 appears once)', () => {
    for (const box of SBOX) {
      expect([...box].sort((a, b) => a - b)).toEqual(Array.from({ length: 16 }, (_, i) => i));
    }
  });
});
