/**
 * Avalanche effect demo (Strict Avalanche Criterion).
 *
 * Flipping a single bit of the input to Serpent-256 changes roughly half of
 * the 128 output bits. This panel encrypts one 128-bit block, flips one input
 * bit, encrypts again, and visualizes exactly which output bits changed.
 *
 * Uses the raw Serpent-256 block cipher (single ECB block) with a fixed,
 * publicly-visible demo key — this illustrates diffusion, not secrecy.
 */
import { Serpent256 } from './serpent';

const DEMO_KEY = hexToBytes('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');
const DEFAULT_BLOCK_HEX = '53657270656e742d3235362064656d6f'; // ASCII "Serpent-256 demo"
const BLOCK_BITS = 128;

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Returns the set of output-bit indices [0..127] that differ between a and b. */
function differingBits(a: Uint8Array, b: Uint8Array): boolean[] {
  const bits: boolean[] = [];
  for (let byte = 0; byte < a.length; byte++) {
    const x = a[byte] ^ b[byte];
    for (let bit = 0; bit < 8; bit++) {
      bits.push((x & (0x80 >> bit)) !== 0);
    }
  }
  return bits;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function renderAvalanche(container: HTMLElement): void {
  container.innerHTML = '';

  // --- Controls ---
  const controls = el('div', 'avalanche-controls');

  const blockField = el('div', 'avalanche-field');
  const blockLabel = el('label', undefined, 'Plaintext block (16 bytes · 32 hex chars)');
  blockLabel.htmlFor = 'aval-block';
  blockField.appendChild(blockLabel);
  const blockInput = el('input');
  blockInput.type = 'text';
  blockInput.id = 'aval-block';
  blockInput.maxLength = 32;
  blockInput.spellcheck = false;
  blockInput.value = DEFAULT_BLOCK_HEX;
  blockField.appendChild(blockInput);

  const randomBtn = el('button', 'icon-btn', 'Randomize');
  randomBtn.type = 'button';
  randomBtn.id = 'aval-random';
  randomBtn.title = 'Generate a random 16-byte block';

  const bitField = el('div', 'avalanche-field');
  const bitLabel = el('label', undefined, 'Flip input bit # (0–127)');
  bitLabel.htmlFor = 'aval-bit';
  bitField.appendChild(bitLabel);
  const bitInput = el('input');
  bitInput.type = 'number';
  bitInput.id = 'aval-bit';
  bitInput.min = '0';
  bitInput.max = String(BLOCK_BITS - 1);
  bitInput.value = '0';
  bitField.appendChild(bitInput);

  controls.append(blockField, randomBtn, bitField);

  // --- Results ---
  const result = el('div', 'avalanche-result');
  const rowA = el('div', 'avalanche-ct');
  rowA.append(el('span', 'avalanche-ct-label', 'Original ciphertext'));
  const ctA = el('code', 'avalanche-ct-value');
  ctA.id = 'aval-ct-a';
  rowA.appendChild(ctA);

  const rowB = el('div', 'avalanche-ct');
  rowB.append(el('span', 'avalanche-ct-label', 'After flipping 1 input bit'));
  const ctB = el('code', 'avalanche-ct-value');
  ctB.id = 'aval-ct-b';
  rowB.appendChild(ctB);

  const grid = el('div', 'avalanche-grid');
  grid.id = 'aval-grid';
  grid.setAttribute('role', 'img');

  const stat = el('div', 'avalanche-stat');
  stat.id = 'aval-stat';
  stat.setAttribute('role', 'status');
  stat.setAttribute('aria-live', 'polite');

  result.append(rowA, rowB, grid, stat);
  container.append(controls, result);

  const cipher = new Serpent256();
  cipher.loadKey(DEMO_KEY);

  const recompute = () => {
    const hex = blockInput.value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(hex)) {
      grid.innerHTML = '';
      ctA.textContent = '—';
      ctB.textContent = '—';
      stat.textContent = 'Enter exactly 32 hexadecimal characters (16 bytes).';
      stat.className = 'avalanche-stat warn';
      return;
    }

    let bit = parseInt(bitInput.value, 10);
    if (!Number.isFinite(bit)) bit = 0;
    bit = Math.max(0, Math.min(BLOCK_BITS - 1, bit));

    const ptA = hexToBytes(hex);
    const ptB = ptA.slice();
    ptB[bit >> 3] ^= 0x80 >> (bit & 7);

    const outA = cipher.encryptBlock(ptA);
    const outB = cipher.encryptBlock(ptB);
    ctA.textContent = bytesToHex(outA);
    ctB.textContent = bytesToHex(outB);

    const diff = differingBits(outA, outB);
    const changed = diff.filter(Boolean).length;
    const pct = (changed / BLOCK_BITS) * 100;

    grid.innerHTML = '';
    grid.setAttribute('aria-label', `${changed} of ${BLOCK_BITS} output bits changed`);
    diff.forEach((changedBit, i) => {
      const cell = el('span', changedBit ? 'aval-cell on' : 'aval-cell');
      cell.title = `Output bit ${i}: ${changedBit ? 'changed' : 'unchanged'}`;
      grid.appendChild(cell);
    });

    stat.innerHTML = `<strong>${changed} of ${BLOCK_BITS}</strong> output bits changed ` +
      `(<strong>${pct.toFixed(1)}%</strong>) from a single-bit input change — ideal diffusion is ~50%.`;
    stat.className = 'avalanche-stat';
  };

  blockInput.addEventListener('input', recompute);
  bitInput.addEventListener('input', recompute);
  randomBtn.addEventListener('click', () => {
    const rnd = new Uint8Array(16);
    crypto.getRandomValues(rnd);
    blockInput.value = bytesToHex(rnd);
    recompute();
  });

  recompute();
}
