/**
 * Serpent-256 reference implementation with per-round introspection.
 *
 * WHY THIS EXISTS
 * ---------------
 * The production cipher (serpent.ts) is the WASM engine from leviathan-crypto —
 * that is what actually encrypts your data, verified against the official AES
 * submission test vectors. But WASM is a black box: it gives you a ciphertext,
 * not the 32 intermediate round states in between.
 *
 * The Serpent *round visualizer* needs those intermediate states to SHOW the
 * cipher working — key mixing, the 4-bit S-box substitution, the linear
 * transformation, one round at a time. So this file is a second, independent,
 * spec-accurate Serpent-256 whose ONLY extra job is to expose every round's
 * state as it goes.
 *
 * This is NOT a toy or a simplification. It is the full Serpent round function
 * (all 32 rounds, all 8 S-boxes, the real linear transform, the real 132-word
 * key schedule) and it is verified byte-for-byte against the SAME official AES
 * submission vectors the WASM engine passes (see serpent-rounds.test.ts). If it
 * ever diverged from spec by a single bit, the KAT test would fail.
 *
 * Convention: this is the standard "bitslice" Serpent representation, in which
 * the initial and final permutations become the identity (the block is loaded
 * as four little-endian 32-bit words). This matches leviathan-crypto and the
 * ecb_vt.txt / ecb_vk.txt vectors exactly.
 *
 * Reference: Anderson, Biham, Knudsen — "Serpent: A Proposal for the Advanced
 * Encryption Standard." https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
 */

export const ROUNDS = 32;
export const PHI = 0x9e3779b9; // fractional part of the golden ratio, as in the spec

/**
 * The eight Serpent S-boxes as 4-bit lookup tables (S0..S7), and their inverses.
 * Each maps a 4-bit input (0..15) to a 4-bit output. Round i uses S-box (i mod 8).
 * These are the exact tables from the Serpent specification.
 */
export const SBOX: readonly (readonly number[])[] = [
  [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
  [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
  [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
  [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
  [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
  [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
  [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
  [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
];

const SBOX_INV: number[][] = SBOX.map((box) => {
  const inv = new Array(16);
  for (let i = 0; i < 16; i++) inv[box[i]] = i;
  return inv;
});

/** 32-bit left rotate. */
function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}

/**
 * Byte-order note: the Serpent AES-submission test vectors number the block's
 * bits so that, to load them into little-endian 32-bit words for the bitslice
 * representation, the 16-byte string must be REVERSED first (and the output
 * reversed back). Both the block and the 256-bit key follow this convention.
 * This matches the production WASM engine exactly (see serpent-rounds.test.ts).
 */
function reversed(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b[b.length - 1 - i];
  return out;
}

/**
 * Load 16 bytes as four little-endian 32-bit words [x0,x1,x2,x3], applying the
 * Serpent test-vector byte reversal so the round state matches the real cipher.
 */
export function bytesToWords(b: Uint8Array): number[] {
  const r = reversed(b);
  const w = [0, 0, 0, 0];
  for (let i = 0; i < 4; i++) {
    w[i] = (r[i * 4] | (r[i * 4 + 1] << 8) | (r[i * 4 + 2] << 16) | (r[i * 4 + 3] << 24)) >>> 0;
  }
  return w;
}

export function wordsToBytes(w: number[]): Uint8Array {
  const out = new Uint8Array(16);
  for (let i = 0; i < 4; i++) {
    out[i * 4] = w[i] & 0xff;
    out[i * 4 + 1] = (w[i] >>> 8) & 0xff;
    out[i * 4 + 2] = (w[i] >>> 16) & 0xff;
    out[i * 4 + 3] = (w[i] >>> 24) & 0xff;
  }
  return reversed(out);
}

/**
 * Apply S-box `which` in bitslice form to the four words. Bit j of each word
 * forms a 4-bit nibble (x0[j],x1[j],x2[j],x3[j]); that nibble is substituted
 * through the S-box and written back. Done for all 32 bit-positions at once.
 */
function applySBox(which: number, x: number[]): number[] {
  const box = SBOX[which];
  const out = [0, 0, 0, 0];
  for (let bit = 0; bit < 32; bit++) {
    const nib =
      ((x[0] >>> bit) & 1) |
      (((x[1] >>> bit) & 1) << 1) |
      (((x[2] >>> bit) & 1) << 2) |
      (((x[3] >>> bit) & 1) << 3);
    const s = box[nib];
    out[0] |= (s & 1) << bit;
    out[1] |= ((s >>> 1) & 1) << bit;
    out[2] |= ((s >>> 2) & 1) << bit;
    out[3] |= ((s >>> 3) & 1) << bit;
  }
  return [out[0] >>> 0, out[1] >>> 0, out[2] >>> 0, out[3] >>> 0];
}

function applySBoxInv(which: number, x: number[]): number[] {
  const box = SBOX_INV[which];
  const out = [0, 0, 0, 0];
  for (let bit = 0; bit < 32; bit++) {
    const nib =
      ((x[0] >>> bit) & 1) |
      (((x[1] >>> bit) & 1) << 1) |
      (((x[2] >>> bit) & 1) << 2) |
      (((x[3] >>> bit) & 1) << 3);
    const s = box[nib];
    out[0] |= (s & 1) << bit;
    out[1] |= ((s >>> 1) & 1) << bit;
    out[2] |= ((s >>> 2) & 1) << bit;
    out[3] |= ((s >>> 3) & 1) << bit;
  }
  return [out[0] >>> 0, out[1] >>> 0, out[2] >>> 0, out[3] >>> 0];
}

/** The Serpent linear transformation (used in rounds 0..30). */
export function linearTransform(x: number[]): number[] {
  let [x0, x1, x2, x3] = x;
  x0 = rotl(x0, 13);
  x2 = rotl(x2, 3);
  x1 = (x1 ^ x0 ^ x2) >>> 0;
  x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
  x1 = rotl(x1, 1);
  x3 = rotl(x3, 7);
  x0 = (x0 ^ x1 ^ x3) >>> 0;
  x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
  x0 = rotl(x0, 5);
  x2 = rotl(x2, 22);
  return [x0 >>> 0, x1 >>> 0, x2 >>> 0, x3 >>> 0];
}

function linearTransformInv(x: number[]): number[] {
  let [x0, x1, x2, x3] = x;
  x2 = rotl(x2, 32 - 22);
  x0 = rotl(x0, 32 - 5);
  x2 = (x2 ^ x3 ^ ((x1 << 7) >>> 0)) >>> 0;
  x0 = (x0 ^ x1 ^ x3) >>> 0;
  x3 = rotl(x3, 32 - 7);
  x1 = rotl(x1, 32 - 1);
  x3 = (x3 ^ x2 ^ ((x0 << 3) >>> 0)) >>> 0;
  x1 = (x1 ^ x0 ^ x2) >>> 0;
  x2 = rotl(x2, 32 - 3);
  x0 = rotl(x0, 32 - 13);
  return [x0 >>> 0, x1 >>> 0, x2 >>> 0, x3 >>> 0];
}

/**
 * Expand a 256-bit key into 33 round subkeys (each 4 words = 128 bits).
 * Serpent derives 132 prekey words w[0..131] via an affine recurrence, then
 * passes them through the S-boxes to form the round keys K[0..32].
 */
export function keySchedule(key: Uint8Array): number[][] {
  if (key.length !== 32) throw new Error('Serpent-256 requires a 32-byte key');

  // The 256-bit key is byte-reversed (same convention as the block), then loaded
  // as eight little-endian 32-bit words (256-bit key: no padding).
  const k = reversed(key);
  const w: number[] = new Array(140).fill(0);
  for (let i = 0; i < 8; i++) {
    w[i] =
      (k[i * 4] | (k[i * 4 + 1] << 8) | (k[i * 4 + 2] << 16) | (k[i * 4 + 3] << 24)) >>> 0;
  }
  // Prekey recurrence: w[i] = rotl(w[i-8]^w[i-5]^w[i-3]^w[i-1]^PHI^(i-8), 11)
  // Indexing w[] here is offset by 8 so w[8..139] hold the 132 prekey words.
  for (let i = 8; i < 140; i++) {
    const t = (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ (i - 8)) >>> 0;
    w[i] = rotl(t, 11);
  }

  // Round keys: apply the S-boxes to groups of four prekey words.
  // The S-box index for round-key group k is (32 + 3 - k) mod 8 = (35 - k) mod 8.
  const roundKeys: number[][] = [];
  for (let k = 0; k <= ROUNDS; k++) {
    const which = (32 + 3 - k) % 8;
    const base = 8 + 4 * k;
    const group = [w[base], w[base + 1], w[base + 2], w[base + 3]];
    roundKeys.push(applySBox(which, group));
  }
  return roundKeys;
}

/** One captured stage of the block as it moves through a round. */
export interface RoundStage {
  round: number; // 1..32 (human-facing)
  /** Block state going INTO this round (before key mixing). */
  input: number[];
  /** After XOR with this round's subkey. */
  afterKeyMix: number[];
  /** After the 4-bit S-box substitution. */
  afterSBox: number[];
  /** After the linear transform (round 32 XORs the final subkey instead). */
  afterLinear: number[];
  /** Which of the eight S-boxes (0..7) this round applied. */
  sboxIndex: number;
  /** True for the final round (no linear transform; XOR final subkey). */
  isFinal: boolean;
}

export interface EncryptTrace {
  plaintext: number[];
  ciphertext: number[];
  roundKeys: number[][];
  stages: RoundStage[];
}

/**
 * Full Serpent-256 encryption that records every intermediate round state.
 * Returns the same ciphertext the production WASM engine produces (verified in
 * serpent-rounds.test.ts), plus the 32-stage trace the visualizer renders.
 */
export function encryptBlockTraced(plaintext: Uint8Array, key: Uint8Array): EncryptTrace {
  if (plaintext.length !== 16) throw new Error('Serpent block size is 16 bytes');
  const roundKeys = keySchedule(key);
  let x = bytesToWords(plaintext);
  const stages: RoundStage[] = [];

  for (let r = 0; r < ROUNDS; r++) {
    const input = x.slice();
    const afterKeyMix = [
      (x[0] ^ roundKeys[r][0]) >>> 0,
      (x[1] ^ roundKeys[r][1]) >>> 0,
      (x[2] ^ roundKeys[r][2]) >>> 0,
      (x[3] ^ roundKeys[r][3]) >>> 0,
    ];
    const sboxIndex = r % 8;
    const afterSBox = applySBox(sboxIndex, afterKeyMix);

    let afterLinear: number[];
    if (r === ROUNDS - 1) {
      // Final round: no linear transform; XOR the last (33rd) subkey.
      afterLinear = [
        (afterSBox[0] ^ roundKeys[ROUNDS][0]) >>> 0,
        (afterSBox[1] ^ roundKeys[ROUNDS][1]) >>> 0,
        (afterSBox[2] ^ roundKeys[ROUNDS][2]) >>> 0,
        (afterSBox[3] ^ roundKeys[ROUNDS][3]) >>> 0,
      ];
    } else {
      afterLinear = linearTransform(afterSBox);
    }

    stages.push({
      round: r + 1,
      input,
      afterKeyMix,
      afterSBox,
      afterLinear,
      sboxIndex,
      isFinal: r === ROUNDS - 1,
    });
    x = afterLinear;
  }

  return {
    plaintext: bytesToWords(plaintext),
    ciphertext: x,
    roundKeys,
    stages,
  };
}

/** Plain encryption (no trace) — used by the KAT test to prove spec accuracy. */
export function encryptBlock(plaintext: Uint8Array, key: Uint8Array): Uint8Array {
  return wordsToBytes(encryptBlockTraced(plaintext, key).ciphertext);
}

/** Inverse, provided for completeness and round-trip testing. */
export function decryptBlock(ciphertext: Uint8Array, key: Uint8Array): Uint8Array {
  if (ciphertext.length !== 16) throw new Error('Serpent block size is 16 bytes');
  const rk = keySchedule(key);
  let x = bytesToWords(ciphertext);
  for (let r = ROUNDS - 1; r >= 0; r--) {
    if (r === ROUNDS - 1) {
      x = [
        (x[0] ^ rk[ROUNDS][0]) >>> 0,
        (x[1] ^ rk[ROUNDS][1]) >>> 0,
        (x[2] ^ rk[ROUNDS][2]) >>> 0,
        (x[3] ^ rk[ROUNDS][3]) >>> 0,
      ];
    } else {
      x = linearTransformInv(x);
    }
    x = applySBoxInv(r % 8, x);
    x = [
      (x[0] ^ rk[r][0]) >>> 0,
      (x[1] ^ rk[r][1]) >>> 0,
      (x[2] ^ rk[r][2]) >>> 0,
      (x[3] ^ rk[r][3]) >>> 0,
    ];
  }
  return wordsToBytes(x);
}

/**
 * Render an intermediate round-state (4 words) as the 16 display bytes in the
 * cipher's external byte order — what the learner should see mid-cipher.
 */
export function stateToDisplayBytes(words: number[]): Uint8Array {
  return wordsToBytes(words);
}

/** Count how many of the 128 block bits are set (used for the diffusion meter). */
export function popcount128(words: number[]): number {
  let c = 0;
  for (const w of words) {
    let v = w >>> 0;
    while (v) { c += v & 1; v >>>= 1; }
  }
  return c;
}

/** Indices [0..127] of bits that differ between two 128-bit block states. */
export function diffBits(a: number[], b: number[]): boolean[] {
  const out: boolean[] = [];
  for (let word = 0; word < 4; word++) {
    const x = (a[word] ^ b[word]) >>> 0;
    for (let bit = 0; bit < 32; bit++) out.push(((x >>> bit) & 1) === 1);
  }
  return out;
}
