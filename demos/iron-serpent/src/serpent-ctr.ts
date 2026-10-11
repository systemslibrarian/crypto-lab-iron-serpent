/**
 * Serpent-256 in CTR (Counter) mode.
 *
 * Retains the iron-serpent-v1 CTR byte convention over the Serpent block wrapper:
 * - 128-bit nonce/counter block
 * - Counter increment per block
 * - XOR keystream against plaintext/ciphertext
 *
 * Reference: https://www.cl.cam.ac.uk/~rja14/serpent.html
 */
import { Serpent256 } from './serpent';

export class SerpentCTR {
  private core: Serpent256;

  constructor() {
    this.core = new Serpent256();
  }

  encrypt(key: Uint8Array, nonce: Uint8Array, plaintext: Uint8Array): Uint8Array {
    if (key.length !== 32) throw new Error('Serpent-256-CTR requires a 32-byte key');
    if (nonce.length !== 16) throw new Error('Serpent-256-CTR requires a 16-byte nonce');
    // Leviathan 3's SerpentCtr also changed external byte order. Its output
    // cannot silently replace the cipher inside an iron-serpent-v1 payload.
    // Build the original little-endian counter/XOR framing over the documented
    // block adapter instead; the existing explainer and legacy-byte controls
    // independently check the construction across partial blocks and carries.
    this.core.loadKey(key);
    const counter = nonce.slice();
    const ciphertext = new Uint8Array(plaintext.length);
    for (let offset = 0; offset < plaintext.length; offset += 16) {
      const keystream = this.core.encryptBlock(counter);
      for (let i = 0; i < Math.min(16, plaintext.length - offset); i++) {
        ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
      }
      keystream.fill(0);
      for (let i = 0; i < counter.length; i++) {
        counter[i] = (counter[i] + 1) & 0xff;
        if (counter[i] !== 0) break;
      }
    }
    return ciphertext;
  }

  decrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
    return this.encrypt(key, nonce, ciphertext);
  }

  dispose(): void {
    this.core.dispose();
  }
}
