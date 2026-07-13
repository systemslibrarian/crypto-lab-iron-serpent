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

/** ASCII rendering of a 16-byte block for the text-entry mode. */
function asciiFromHex(hex: string): string {
  let s = '';
  for (let i = 0; i < hex.length; i += 2) {
    const b = parseInt(hex.slice(i, i + 2), 16);
    if (b === 0) continue;
    s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
  }
  return s;
}

/** Pad an ASCII string to a 16-byte block and return its 32-char hex. */
function asciiToBlockHex(s: string): string {
  const src = new TextEncoder().encode(s);
  const b = new Uint8Array(16);
  b.set(src.subarray(0, 16));
  return bytesToHex(b);
}

export function renderAvalanche(container: HTMLElement): void {
  container.innerHTML = '';

  // --- Controls ---
  const controls = el('div', 'avalanche-controls');

  const blockField = el('div', 'avalanche-field');
  // Input-format toggle so a coder can type ASCII instead of hand-writing hex.
  const modeWrap = el('div', 'sv-mode');
  const modeText = el('button', 'sv-mode-btn active', 'Type text');
  modeText.type = 'button';
  modeText.setAttribute('aria-pressed', 'true');
  const modeHex = el('button', 'sv-mode-btn', 'Enter hex');
  modeHex.type = 'button';
  modeHex.setAttribute('aria-pressed', 'false');
  modeWrap.append(modeText, modeHex);
  blockField.appendChild(modeWrap);

  const blockLabel = el('label', undefined, 'Plaintext block (16 bytes)');
  blockLabel.htmlFor = 'aval-block';
  blockField.appendChild(blockLabel);
  const blockInput = el('input');
  blockInput.type = 'text';
  blockInput.id = 'aval-block';
  blockInput.maxLength = 16;
  blockInput.spellcheck = false;
  blockInput.value = asciiFromHex(DEFAULT_BLOCK_HEX);
  blockField.appendChild(blockInput);
  // The hex the cipher actually sees, kept in sync with whichever mode is active.
  let blockHex = DEFAULT_BLOCK_HEX;
  let hexMode = false;
  const hexEcho = el('p', 'sv-help');
  hexEcho.id = 'aval-hex-echo';
  blockField.appendChild(hexEcho);

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

  // Input block, shown as 128 bit-cells so "flip bit #N" points at a real cell.
  const inputRow = el('div', 'avalanche-input');
  inputRow.append(el('span', 'avalanche-ct-label', 'Input block bits (flipped bit highlighted)'));
  const inputGrid = el('div', 'aval-input-grid');
  inputGrid.id = 'aval-input-grid';
  inputGrid.setAttribute('role', 'img');
  inputRow.appendChild(inputGrid);
  result.appendChild(inputRow);

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

  // Keep blockHex in sync with whichever input mode is active. Returns false
  // (and shows guidance) if the hex-mode field isn't yet a full 16-byte block.
  const syncBlockHex = (): boolean => {
    if (hexMode) {
      const h = blockInput.value.trim().toLowerCase();
      if (!/^[0-9a-f]{32}$/.test(h)) {
        hexEcho.textContent = 'Enter exactly 32 hexadecimal characters (16 bytes).';
        return false;
      }
      blockHex = h;
    } else {
      blockHex = asciiToBlockHex(blockInput.value);
      hexEcho.textContent = `As hex: ${blockHex}`;
    }
    return true;
  };

  const recompute = () => {
    if (!syncBlockHex()) {
      grid.innerHTML = '';
      inputGrid.innerHTML = '';
      ctA.textContent = '—';
      ctB.textContent = '—';
      stat.textContent = 'Enter exactly 32 hexadecimal characters (16 bytes).';
      stat.className = 'avalanche-stat warn';
      return;
    }

    let bit = parseInt(bitInput.value, 10);
    if (!Number.isFinite(bit)) bit = 0;
    bit = Math.max(0, Math.min(BLOCK_BITS - 1, bit));

    const ptA = hexToBytes(blockHex);
    const ptB = ptA.slice();
    ptB[bit >> 3] ^= 0x80 >> (bit & 7);

    // Input bit grid: show all 128 input bits, spotlight the one being flipped.
    inputGrid.innerHTML = '';
    inputGrid.setAttribute('aria-label', `Input block; bit ${bit} is flipped`);
    for (let i = 0; i < BLOCK_BITS; i++) {
      const on = (ptA[i >> 3] & (0x80 >> (i & 7))) !== 0;
      let cls = on ? 'aval-in-cell on' : 'aval-in-cell';
      if (i === bit) cls += ' flip';
      const cell = el('span', cls);
      cell.title = i === bit ? `Bit ${i} (flipped)` : `Bit ${i}: ${on ? 1 : 0}`;
      inputGrid.appendChild(cell);
    }

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

  const setMode = (hex: boolean) => {
    hexMode = hex;
    modeText.classList.toggle('active', !hex);
    modeHex.classList.toggle('active', hex);
    modeText.setAttribute('aria-pressed', String(!hex));
    modeHex.setAttribute('aria-pressed', String(hex));
    if (hex) {
      blockLabel.textContent = 'Plaintext block (16 bytes · 32 hex chars)';
      blockInput.maxLength = 32;
      blockInput.value = blockHex;
    } else {
      blockLabel.textContent = 'Plaintext block (16 bytes)';
      blockInput.maxLength = 16;
      blockInput.value = asciiFromHex(blockHex);
    }
    recompute();
  };
  modeText.addEventListener('click', () => setMode(false));
  modeHex.addEventListener('click', () => setMode(true));

  blockInput.addEventListener('input', recompute);
  bitInput.addEventListener('input', recompute);
  randomBtn.addEventListener('click', () => {
    const rnd = new Uint8Array(16);
    crypto.getRandomValues(rnd);
    blockHex = bytesToHex(rnd);
    blockInput.value = hexMode ? blockHex : asciiFromHex(blockHex);
    recompute();
  });

  recompute();
}
