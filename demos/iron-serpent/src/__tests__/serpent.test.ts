/**
 * Serpent-256 test suite.
 *
 * Test vector source: Official AES submission package
 * https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
 * https://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz (floppy4/ecb_vk.txt, ecb_vt.txt)
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { initSerpent, Serpent256 } from '../serpent';
import { SerpentCTR } from '../serpent-ctr';
import { decrypt, encrypt } from '../crypto';
import { deriveMACKey, computeMAC, verifyMAC } from '../mac';
import { deriveKey } from '../kdf';

interface Argon2Stub {
  ArgonType: {
    Argon2d: number;
    Argon2i: number;
    Argon2id: number;
  };
  hash(options: {
    pass: string | Uint8Array;
    salt: string | Uint8Array;
    hashLen?: number;
  }): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }>;
}

declare global {
  var argon2: Argon2Stub;
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toBytes(value: string | Uint8Array): Uint8Array {
  if (typeof value === 'string') {
    return new TextEncoder().encode(value);
  }
  return value;
}

async function stubArgon2Hash(options: {
  pass: string | Uint8Array;
  salt: string | Uint8Array;
  hashLen?: number;
}): Promise<{ hash: Uint8Array; hashHex: string; encoded: string }> {
  const passBytes = toBytes(options.pass);
  const saltBytes = toBytes(options.salt);
  const input = new Uint8Array(passBytes.length + saltBytes.length);
  input.set(passBytes);
  input.set(saltBytes, passBytes.length);

  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', input));
  const hash = digest.slice(0, options.hashLen ?? 32);

  return {
    hash,
    hashHex: bytesToHex(hash),
    encoded: bytesToHex(hash),
  };
}

function installArgon2Stub(): void {
  globalThis.argon2 = {
    ArgonType: {
      Argon2d: 0,
      Argon2i: 1,
      Argon2id: 2,
    },
    hash: stubArgon2Hash,
  };
}

describe('Serpent-256 Block Cipher', () => {
  beforeAll(async () => {
    installArgon2Stub();
    await initSerpent();
  });

  it('encrypts official variable-text vector #1 (256-bit key)', () => {
    // From ecb_vt.txt KEYSIZE=256:
    // KEY=0000...0000 (32 bytes), PT=80000000000000000000000000000000
    // CT=da5a7992b1b4ae6f8c004bc8a7de5520
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('80000000000000000000000000000000');
    const expectedCt = 'da5a7992b1b4ae6f8c004bc8a7de5520';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const ct = cipher.encryptBlock(pt);
    expect(bytesToHex(ct)).toBe(expectedCt);
    cipher.dispose();
  });

  it('encrypts official variable-key vector #1 (256-bit key)', () => {
    // From ecb_vk.txt KEYSIZE=256:
    // KEY=8000...0000, PT=0000...0000
    // CT=abed96e766bf28cbc0ebd21a82ef0819
    const key = hexToBytes('8000000000000000000000000000000000000000000000000000000000000000');
    const pt = hexToBytes('00000000000000000000000000000000');
    const expectedCt = 'abed96e766bf28cbc0ebd21a82ef0819';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const ct = cipher.encryptBlock(pt);
    expect(bytesToHex(ct)).toBe(expectedCt);
    cipher.dispose();
  });

  it('decrypts official variable-key vector #1 (256-bit key)', () => {
    const key = hexToBytes('8000000000000000000000000000000000000000000000000000000000000000');
    const ct = hexToBytes('abed96e766bf28cbc0ebd21a82ef0819');
    const expectedPt = '00000000000000000000000000000000';

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const pt = cipher.decryptBlock(ct);
    expect(bytesToHex(pt)).toBe(expectedPt);
    cipher.dispose();
  });

  it('exhibits the avalanche effect: one input bit flips ~50% of output bits', () => {
    // Strict Avalanche Criterion — averaged over all 128 single-bit input flips,
    // the fraction of changed output bits should sit close to 50%.
    const key = hexToBytes('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');
    const base = hexToBytes('53657270656e742d3235362064656d6f');

    const cipher = new Serpent256();
    cipher.loadKey(key);
    const ctBase = cipher.encryptBlock(base);

    let totalChanged = 0;
    for (let bit = 0; bit < 128; bit++) {
      const flipped = base.slice();
      flipped[bit >> 3] ^= 0x80 >> (bit & 7);
      const ct = cipher.encryptBlock(flipped);
      for (let b = 0; b < 16; b++) {
        let x = ctBase[b] ^ ct[b];
        while (x) { totalChanged += x & 1; x >>= 1; }
      }
    }
    cipher.dispose();

    const avgFraction = totalChanged / (128 * 128);
    expect(avgFraction).toBeGreaterThan(0.45);
    expect(avgFraction).toBeLessThan(0.55);
  });

  it('encrypts additional variable-text vectors (256-bit key)', () => {
    const key = hexToBytes('0000000000000000000000000000000000000000000000000000000000000000');
    const vectors = [
      { pt: '40000000000000000000000000000000', ct: 'f351351b823e3d7a4f3bf390c4f198cb' },
      { pt: '20000000000000000000000000000000', ct: 'a477a65d9db75c8ed7218c52b64c65bb' },
      { pt: '10000000000000000000000000000000', ct: 'f8019452cba4fe618d80a6756183b2e0' },
    ];

    const cipher = new Serpent256();
    cipher.loadKey(key);
    for (const v of vectors) {
      const ct = cipher.encryptBlock(hexToBytes(v.pt));
      expect(bytesToHex(ct)).toBe(v.ct);
    }
    cipher.dispose();
  });
});

describe('Serpent-256-CTR', () => {
  beforeAll(async () => {
    installArgon2Stub();
    await initSerpent();
  });

  it('encrypts and decrypts a known string (round-trip)', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce = new Uint8Array(16);
    crypto.getRandomValues(nonce);
    const plaintext = new TextEncoder().encode('Hello, Serpent-256-CTR! This is a round-trip test.');

    const encCTR = new SerpentCTR();
    const ciphertext = encCTR.encrypt(key, nonce, plaintext);
    encCTR.dispose();

    // Ciphertext must differ from plaintext
    expect(bytesToHex(ciphertext)).not.toBe(bytesToHex(plaintext));

    const decCTR = new SerpentCTR();
    const decrypted = decCTR.decrypt(key, nonce, ciphertext);
    decCTR.dispose();

    expect(new TextDecoder().decode(decrypted)).toBe('Hello, Serpent-256-CTR! This is a round-trip test.');
  });

  it('produces different ciphertext with different nonces', () => {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    const nonce1 = new Uint8Array(16);
    crypto.getRandomValues(nonce1);
    const nonce2 = new Uint8Array(16);
    crypto.getRandomValues(nonce2);
    const plaintext = new TextEncoder().encode('Same plaintext, different nonces');

    const ctr1 = new SerpentCTR();
    const ct1 = ctr1.encrypt(key, nonce1, plaintext);
    ctr1.dispose();

    const ctr2 = new SerpentCTR();
    const ct2 = ctr2.encrypt(key, nonce2, plaintext);
    ctr2.dispose();

    expect(bytesToHex(ct1)).not.toBe(bytesToHex(ct2));
  });

  it('rejects a tampered ciphertext before any decryption attempt', async () => {
    const payload = await encrypt(new TextEncoder().encode('Tamper detection must fail closed.'), new TextEncoder().encode('correct horse battery staple'));
    const ciphertext = Uint8Array.from(atob(payload.ciphertext), (char) => char.charCodeAt(0));

    ciphertext[0] ^= 0x01;

    let tamperedBinary = '';
    for (let i = 0; i < ciphertext.length; i++) {
      tamperedBinary += String.fromCharCode(ciphertext[i]);
    }

    const tamperedPayload = {
      ...payload,
      ciphertext: btoa(tamperedBinary),
    };

    await expect(decrypt(tamperedPayload, new TextEncoder().encode('correct horse battery staple'))).rejects.toThrow(
      'Authentication failed — ciphertext has been tampered with'
    );
  });

  it('rejects malformed payload fields before KDF/decryption', async () => {
    await expect(
      decrypt(
        {
          salt: '%%%not-base64%%%',
          nonce: 'AQIDBAUGBwgJCgsMDQ4PEA==',
          ciphertext: 'AQID',
          mac: 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHw==',
          version: 'iron-serpent-v1',
        },
        new TextEncoder().encode('passphrase')
      )
    ).rejects.toThrow('Invalid encrypted payload: base64 field could not be decoded');
  });

  it('rejects empty plaintext on encrypt', async () => {
    await expect(
      encrypt(new Uint8Array(0), new TextEncoder().encode('passphrase'))
    ).rejects.toThrow('Plaintext must not be empty');
  });
});

describe('HMAC-SHA256 (mac.ts)', () => {
  it('deriveMACKey returns a CryptoKey with HMAC algorithm', async () => {
    const fakeEncKey = new Uint8Array(32).fill(0xab);
    const macKey = await deriveMACKey(fakeEncKey);
    expect(macKey).toBeInstanceOf(CryptoKey);
    expect(macKey.algorithm.name).toBe('HMAC');
  });

  it('computeMAC returns a 32-byte tag', async () => {
    const macKey = await deriveMACKey(new Uint8Array(32).fill(0x01));
    const mac = await computeMAC(macKey, new Uint8Array(64).fill(0x02));
    expect(mac).toBeInstanceOf(Uint8Array);
    expect(mac.length).toBe(32);
  });

  it('verifyMAC returns true for a correct tag', async () => {
    const macKey = await deriveMACKey(new Uint8Array(32).fill(0x03));
    const data = new Uint8Array(64).fill(0x04);
    const mac = await computeMAC(macKey, data);
    expect(await verifyMAC(macKey, data, mac)).toBe(true);
  });

  it('verifyMAC returns false when data is modified', async () => {
    const macKey = await deriveMACKey(new Uint8Array(32).fill(0x05));
    const data = new Uint8Array(64).fill(0x06);
    const mac = await computeMAC(macKey, data);
    data[0] ^= 0x01;
    expect(await verifyMAC(macKey, data, mac)).toBe(false);
  });

  it('verifyMAC returns false when mac is modified', async () => {
    const macKey = await deriveMACKey(new Uint8Array(32).fill(0x07));
    const data = new Uint8Array(64).fill(0x08);
    const mac = await computeMAC(macKey, data);
    mac[0] ^= 0x01;
    expect(await verifyMAC(macKey, data, mac)).toBe(false);
  });
});

describe('KDF (kdf.ts)', () => {
  beforeAll(() => {
    installArgon2Stub();
  });

  it('deriveKey returns a 32-byte key', async () => {
    const salt = new Uint8Array(16).fill(0xaa);
    const key = await deriveKey(new TextEncoder().encode('test-passphrase'), salt);
    expect(key).toBeInstanceOf(Uint8Array);
    expect(key.length).toBe(32);
  });

  it('deriveKey is deterministic for the same inputs', async () => {
    const salt = new Uint8Array(16).fill(0xbb);
    const key1 = await deriveKey(new TextEncoder().encode('same-pass'), salt);
    const key2 = await deriveKey(new TextEncoder().encode('same-pass'), salt);
    expect(key1).toEqual(key2);
  });

  it('deriveKey produces different output for different passphrases', async () => {
    const salt = new Uint8Array(16).fill(0xcc);
    const key1 = await deriveKey(new TextEncoder().encode('pass-one'), salt);
    const key2 = await deriveKey(new TextEncoder().encode('pass-two'), salt);
    expect(key1).not.toEqual(key2);
  });

  it('deriveKey produces different output for different salts', async () => {
    const key1 = await deriveKey(new TextEncoder().encode('same'), new Uint8Array(16).fill(0x01));
    const key2 = await deriveKey(new TextEncoder().encode('same'), new Uint8Array(16).fill(0x02));
    expect(key1).not.toEqual(key2);
  });

  it('deriveKey rejects a salt of wrong length', async () => {
    await expect(deriveKey(new TextEncoder().encode('pass'), new Uint8Array(8))).rejects.toThrow('Salt must be 16 bytes');
  });
});
