/**
 * CTR mode explainer: how a block cipher becomes a stream cipher.
 *
 * Serpent can only encrypt 16-byte blocks — so in CTR mode it never touches
 * the plaintext at all. It encrypts a counter block (nonce, nonce+1, nonce+2…)
 * to produce a keystream, and the plaintext is simply XORed against it.
 * Decryption is the identical operation; Serpent's decryptBlock is never used.
 *
 * The counter convention here matches leviathan-crypto's SerpentCtr exactly
 * (verified in __tests__/ctr-explainer.test.ts): the first counter block IS
 * the nonce, incremented little-endian (byte 0 first) for each later block.
 *
 * Like the avalanche panel, this uses a fixed, publicly-visible demo key —
 * it illustrates the mode's structure, not secrecy.
 */
import { Serpent256 } from './serpent';

export const BLOCK_SIZE = 16;
export const MAX_MESSAGE_BYTES = 48; // 3 blocks — enough to show the counter advancing

/** Counter block i: nonce incremented i times, little-endian (matches SerpentCtr). */
export function counterBlock(nonce: Uint8Array, index: number): Uint8Array {
  const block = nonce.slice();
  for (let n = 0; n < index; n++) {
    for (let i = 0; i < block.length; i++) {
      block[i] = (block[i] + 1) & 0xff;
      if (block[i] !== 0) break;
    }
  }
  return block;
}

export function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

/**
 * Renders one hex row: label + per-byte spans.
 * `hot` marks bytes to highlight (e.g. counter bytes that differ from the nonce);
 * `dim` marks bytes to de-emphasize (e.g. unused keystream tail).
 */
function hexRow(label: string, bytes: Uint8Array, opts?: { hot?: (i: number) => boolean; dim?: (i: number) => boolean }): HTMLElement {
  const row = el('div', 'ctr-row');
  row.appendChild(el('span', 'ctr-row-label', label));
  const hex = el('code', 'ctr-hex');
  for (let i = 0; i < bytes.length; i++) {
    let cls = 'ctr-byte';
    if (opts?.hot?.(i)) cls += ' hot';
    if (opts?.dim?.(i)) cls += ' dim';
    hex.appendChild(el('span', cls, bytes[i].toString(16).padStart(2, '0')));
  }
  row.appendChild(hex);
  return row;
}

const DEMO_KEY = hexToBytes('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');
const DEFAULT_MESSAGE = 'Attack at dawn. -Serpent';

export function renderCtrExplainer(container: HTMLElement): void {
  container.innerHTML = '';

  // --- Controls ---
  const controls = el('div', 'avalanche-controls');

  const msgField = el('div', 'avalanche-field');
  const msgLabel = el('label', undefined, `Message (up to ${MAX_MESSAGE_BYTES} ASCII characters)`);
  msgLabel.htmlFor = 'ctr-message';
  const msgInput = el('input');
  msgInput.type = 'text';
  msgInput.id = 'ctr-message';
  msgInput.maxLength = MAX_MESSAGE_BYTES;
  msgInput.spellcheck = false;
  msgInput.value = DEFAULT_MESSAGE;
  msgField.append(msgLabel, msgInput);

  const nonceField = el('div', 'avalanche-field');
  const nonceLabel = el('label', undefined, 'Nonce (16 bytes · 32 hex chars)');
  nonceLabel.htmlFor = 'ctr-nonce';
  const nonceInput = el('input');
  nonceInput.type = 'text';
  nonceInput.id = 'ctr-nonce';
  nonceInput.maxLength = 32;
  nonceInput.spellcheck = false;
  nonceField.append(nonceLabel, nonceInput);

  const randomBtn = el('button', 'icon-btn', 'Randomize nonce');
  randomBtn.type = 'button';
  randomBtn.id = 'ctr-random';
  randomBtn.title = 'Generate a random 16-byte nonce';

  controls.append(msgField, nonceField, randomBtn);

  const blocksWrap = el('div', 'ctr-blocks');
  const stat = el('div', 'avalanche-stat');
  stat.id = 'ctr-stat';
  stat.setAttribute('role', 'status');
  stat.setAttribute('aria-live', 'polite');

  const note = el('p', 'ctr-note');
  note.innerHTML =
    'Serpent never encrypts your message — it encrypts the <strong>counter</strong>. ' +
    'Decryption regenerates the identical keystream and XORs it off again, so ' +
    '<code>decryptBlock</code> is never used in CTR mode. This is also why a ' +
    '<strong>nonce must never be reused</strong> with the same key: two messages would share ' +
    'a keystream, and XORing their ciphertexts together would cancel it out entirely.';

  container.append(controls, blocksWrap, stat, note);

  const cipher = new Serpent256();
  cipher.loadKey(DEMO_KEY);

  const randomizeNonce = () => {
    const rnd = new Uint8Array(BLOCK_SIZE);
    crypto.getRandomValues(rnd);
    nonceInput.value = bytesToHex(rnd);
  };
  randomizeNonce();

  const recompute = () => {
    const nonceHex = nonceInput.value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nonceHex)) {
      blocksWrap.innerHTML = '';
      stat.textContent = 'Nonce must be exactly 32 hexadecimal characters (16 bytes).';
      stat.className = 'avalanche-stat warn';
      return;
    }
    const message = msgInput.value;
    if (message.length === 0) {
      blocksWrap.innerHTML = '';
      stat.textContent = 'Enter a message to see its keystream.';
      stat.className = 'avalanche-stat warn';
      return;
    }

    const nonce = hexToBytes(nonceHex);
    const plaintext = new TextEncoder().encode(message.slice(0, MAX_MESSAGE_BYTES));
    const nBlocks = Math.ceil(plaintext.length / BLOCK_SIZE);

    blocksWrap.innerHTML = '';
    for (let i = 0; i < nBlocks; i++) {
      const counter = counterBlock(nonce, i);
      const keystream = cipher.encryptBlock(counter);
      const ptChunk = plaintext.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
      const ctChunk = xorBytes(ptChunk, keystream.subarray(0, ptChunk.length));

      const block = el('div', 'ctr-block');
      const used = ptChunk.length;

      const title = el('div', 'ctr-block-title', `Block ${i + 1} of ${nBlocks}`);
      block.appendChild(title);

      block.appendChild(hexRow(i === 0 ? 'Counter = nonce' : `Counter = nonce + ${i}`, counter, {
        hot: (b) => counter[b] !== nonce[b],
      }));
      block.appendChild(el('div', 'ctr-op', '↓ Serpent-256 encrypts the counter (all 32 rounds)'));
      block.appendChild(hexRow('Keystream', keystream, {
        dim: (b) => b >= used,
      }));
      const ptRow = hexRow('Plaintext', ptChunk);
      ptRow.querySelector('.ctr-hex')?.setAttribute('title', new TextDecoder().decode(ptChunk));
      block.appendChild(el('div', 'ctr-op', '⊕ XOR keystream with plaintext bytes'));
      block.appendChild(ptRow);
      block.appendChild(hexRow('Ciphertext', ctChunk));
      if (used < BLOCK_SIZE) {
        block.appendChild(el('div', 'ctr-op', `(final block uses only ${used} of 16 keystream bytes — no padding needed)`));
      }
      blocksWrap.appendChild(block);
    }

    stat.innerHTML = `<strong>${plaintext.length} bytes</strong> → <strong>${nBlocks} counter block${nBlocks > 1 ? 's' : ''}</strong>. ` +
      'The ciphertext is exactly the same length as the plaintext.';
    stat.className = 'avalanche-stat';
  };

  msgInput.addEventListener('input', recompute);
  nonceInput.addEventListener('input', recompute);
  randomBtn.addEventListener('click', () => {
    randomizeNonce();
    recompute();
  });

  recompute();
}
