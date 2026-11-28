/**
 * Key derivation and HMAC-SHA256 Encrypt-then-MAC using Web Crypto API.
 *
 * Key hierarchy (proper domain separation):
 *   Argon2id(passphrase, salt) → masterKey
 *   HKDF-SHA256(masterKey, info="iron-serpent-v1-enc") → encKey  (raw 256-bit)
 *   HKDF-SHA256(masterKey, info="iron-serpent-v1-mac") → macKey  (CryptoKey HMAC)
 *   masterKey.fill(0)
 *
 * Leaking encKey from WASM memory cannot recover macKey, and vice versa.
 */

const ENC_HKDF_INFO = new TextEncoder().encode('iron-serpent-v1-enc');
const MAC_HKDF_INFO = new TextEncoder().encode('iron-serpent-v1-mac');
const HKDF_SALT = new Uint8Array(32); // zero-filled per RFC 5869 when no salt

async function hkdfDeriveBits(masterKey: Uint8Array, info: Uint8Array, bits: number): Promise<ArrayBuffer> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    masterKey.slice().buffer as ArrayBuffer,
    'HKDF',
    false,
    ['deriveBits']
  );
  return crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: info.slice().buffer as ArrayBuffer },
    baseKey,
    bits
  );
}

export async function deriveEncKey(masterKey: Uint8Array): Promise<Uint8Array> {
  const bits = await hkdfDeriveBits(masterKey, ENC_HKDF_INFO, 256);
  return new Uint8Array(bits);
}

export async function deriveMACKey(masterKey: Uint8Array): Promise<CryptoKey> {
  const macKeyBits = await hkdfDeriveBits(masterKey, MAC_HKDF_INFO, 256);
  try {
    return await crypto.subtle.importKey('raw', macKeyBits, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  } finally {
    // Best-effort cleanup of the temporary HKDF output after Web Crypto imports it.
    new Uint8Array(macKeyBits).fill(0);
  }
}

export async function computeMAC(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
  const sig = await crypto.subtle.sign('HMAC', key, data.slice().buffer as ArrayBuffer);
  return new Uint8Array(sig);
}

export async function verifyMAC(key: CryptoKey, data: Uint8Array, mac: Uint8Array): Promise<boolean> {
  return crypto.subtle.verify('HMAC', key, mac.slice().buffer as ArrayBuffer, data.slice().buffer as ArrayBuffer);
}
