/**
 * Serpent-256 block cipher wrapper.
 *
 * Implementation source: leviathan-crypto (npm) v3.0.1
 * - WASM-based Serpent-256 with bitslice S-boxes
 * - Verified against official AES submission test vectors
 * - Reference specification: https://www.cl.cam.ac.uk/~rja14/serpent.html
 */
import { serpentInit, Serpent as SerpentCore } from 'leviathan-crypto/serpent';
import { serpentWasm } from 'leviathan-crypto/serpent/embedded';

let initialized = false;

export async function initSerpent(): Promise<void> {
  if (initialized) return;
  await serpentInit(serpentWasm);
  initialized = true;
}

export class Serpent256 {
  private core: SerpentCore;

  constructor() {
    this.core = new SerpentCore();
  }

  loadKey(key: Uint8Array): void {
    if (key.length !== 32) throw new Error('Serpent-256 requires a 32-byte (256-bit) key');
    // The lab and AES-submission floppy vectors use big-endian external
    // notation. Leviathan 3 uses natural byte order, so retain the lab's
    // existing interface with the conversion documented by upstream's
    // prepareFloppyKey/Plaintext/Ciphertext helpers. Do not mutate caller bytes.
    const naturalKey = key.slice().reverse();
    try {
      this.core.loadKey(naturalKey);
    } finally {
      naturalKey.fill(0);
    }
  }

  encryptBlock(plaintext: Uint8Array): Uint8Array {
    if (plaintext.length !== 16) throw new Error('Serpent block size is 16 bytes (128 bits)');
    return this.core.encryptBlock(plaintext.slice().reverse()).reverse();
  }

  decryptBlock(ciphertext: Uint8Array): Uint8Array {
    if (ciphertext.length !== 16) throw new Error('Serpent block size is 16 bytes (128 bits)');
    return this.core.decryptBlock(ciphertext.slice().reverse()).reverse();
  }

  dispose(): void {
    this.core.dispose();
  }
}
