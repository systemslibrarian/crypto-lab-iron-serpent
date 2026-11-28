/**
 * Serpent-256-CTR encrypt/decrypt pipeline with Argon2id KDF and HMAC-SHA256 authentication.
 *
 * Security boundary: this module operates exclusively on Uint8Array.
 * No plaintext or passphrase ever exists as a JS string inside this layer.
 * Strings are immutable and GC-managed — they cannot be zeroed.
 * The caller (UI layer) is responsible for encoding strings to bytes
 * and zeroing those bytes after use.
 *
 * Flow:
 * Encrypt: passphrase bytes → Argon2id → masterKey → HKDF → encKey + macKey
 *          plaintext bytes → Serpent-256-CTR encrypt → HMAC-SHA256 tag
 * Decrypt: verify HMAC first → Serpent-256-CTR decrypt → plaintext bytes
 */
import { SerpentCTR } from './serpent-ctr';
import { deriveKey, generateSalt } from './kdf';
import { deriveEncKey, deriveMACKey, computeMAC, verifyMAC } from './mac';

export interface EncryptedPayload {
  salt: string;       // base64
  nonce: string;      // base64
  ciphertext: string; // base64
  mac: string;        // base64
  version: string;    // 'iron-serpent-v1'
}

const PAYLOAD_VERSION = 'iron-serpent-v1';
export class AuthenticationError extends Error {
  constructor() {
    super('Authentication failed');
    this.name = 'AuthenticationError';
  }
}

function toBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

function fromBase64(b64: string): Uint8Array {
  let binary = '';
  try {
    binary = atob(b64);
  } catch {
    throw new Error('Invalid encrypted payload: base64 field could not be decoded');
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

function assertPayloadShape(payload: EncryptedPayload): void {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Invalid encrypted payload: expected an object');
  }

  const requiredFields: Array<keyof EncryptedPayload> = ['salt', 'nonce', 'ciphertext', 'mac', 'version'];
  for (const field of requiredFields) {
    if (typeof payload[field] !== 'string' || payload[field].length === 0) {
      throw new Error(`Invalid encrypted payload: ${field} must be a non-empty string`);
    }
  }

  if (payload.version !== PAYLOAD_VERSION) {
    throw new Error('Unsupported payload version');
  }
}

function assertDecodedLengths(salt: Uint8Array, nonce: Uint8Array, mac: Uint8Array, ciphertext: Uint8Array): void {
  if (salt.length !== 16) {
    throw new Error('Invalid encrypted payload: salt must decode to 16 bytes');
  }
  if (nonce.length !== 16) {
    throw new Error('Invalid encrypted payload: nonce must decode to 16 bytes');
  }
  if (mac.length !== 32) {
    throw new Error('Invalid encrypted payload: mac must decode to 32 bytes');
  }
  if (ciphertext.length < 1) {
    throw new Error('Invalid encrypted payload: ciphertext must not be empty');
  }
}

export async function encrypt(plaintext: Uint8Array, passphrase: Uint8Array): Promise<EncryptedPayload> {
  if (plaintext.length === 0) {
    throw new Error('Plaintext must not be empty');
  }
  const salt = generateSalt();
  const nonce = new Uint8Array(16);
  crypto.getRandomValues(nonce);

  // Key hierarchy: Argon2id → masterKey → HKDF → separate encKey + macKey
  const masterKey = await deriveKey(passphrase, salt);
  const encKey = await deriveEncKey(masterKey);
  const macKey = await deriveMACKey(masterKey);
  masterKey.fill(0);

  const ctr = new SerpentCTR();
  let ciphertextBytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    ciphertextBytes = ctr.encrypt(encKey, nonce, plaintext);
  } finally {
    ctr.dispose();
    encKey.fill(0);
  }

  const versionBytes = new TextEncoder().encode(PAYLOAD_VERSION);
  const macData = concat(salt, nonce, ciphertextBytes, versionBytes);
  const mac = await computeMAC(macKey, macData);

  return {
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertextBytes),
    mac: toBase64(mac),
    version: PAYLOAD_VERSION,
  };
}

export async function decrypt(payload: EncryptedPayload, passphrase: Uint8Array): Promise<Uint8Array> {
  assertPayloadShape(payload);

  const salt = fromBase64(payload.salt);
  const nonce = fromBase64(payload.nonce);
  const ciphertextBytes = fromBase64(payload.ciphertext);
  const mac = fromBase64(payload.mac);

  assertDecodedLengths(salt, nonce, mac, ciphertextBytes);

  // Key hierarchy: Argon2id → masterKey → HKDF → separate encKey + macKey
  const masterKey = await deriveKey(passphrase, salt);
  const encKey = await deriveEncKey(masterKey);
  const macKey = await deriveMACKey(masterKey);
  masterKey.fill(0);

  // Verify MAC BEFORE decryption — Encrypt-then-MAC
  const versionBytes = new TextEncoder().encode(PAYLOAD_VERSION);
  const macData = concat(salt, nonce, ciphertextBytes, versionBytes);
  const valid = await verifyMAC(macKey, macData, mac);
  if (!valid) {
    encKey.fill(0);
    throw new AuthenticationError();
  }

  const ctr = new SerpentCTR();
  let plaintextBytes: Uint8Array<ArrayBufferLike> = new Uint8Array(0);
  try {
    plaintextBytes = ctr.decrypt(encKey, nonce, ciphertextBytes);
  } finally {
    ctr.dispose();
    encKey.fill(0);
  }

  return plaintextBytes;
}
