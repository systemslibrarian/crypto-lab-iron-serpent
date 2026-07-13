/**
 * Serpent round visualizer.
 *
 * Serpent is the one cipher this whole lab is named for, yet everywhere else it
 * is a black box: a button says "full 32 rounds" and a ciphertext appears. This
 * panel opens the box. It steps ONE 128-bit block through the real Serpent round
 * function — key mixing → the 4-bit S-box substitution → the linear transform —
 * one round at a time, with a counter ticking 1..32, so "diffusion" and
 * "avalanche" stop being statistics and become something you can watch happen.
 *
 * The states shown here are produced by serpent-rounds.ts, a full spec-accurate
 * Serpent-256 that is verified byte-for-byte against the same official AES test
 * vectors (and the production WASM engine) — see serpent-rounds.test.ts. Nothing
 * here is faked or simplified; it is the real cipher, made visible.
 */
import {
  encryptBlockTraced,
  stateToDisplayBytes,
  diffBits,
  popcount128,
  SBOX,
  type EncryptTrace,
} from './serpent-rounds';

// Fixed, published demo key — like the avalanche/CTR panels, this illustrates
// the cipher's mechanism, not secrecy, so the key is deliberately public.
const DEMO_KEY = hexToBytes('00112233445566778899aabbccddeeff102132435465768798a9bacbdcedfe0f');
const DEFAULT_BLOCK_HEX = '53657270656e742d3235362064656d6f'; // ASCII "Serpent-256 demo"

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
function asciiToHex(s: string): string {
  const bytes = new TextEncoder().encode(s);
  const b = new Uint8Array(16);
  b.set(bytes.subarray(0, 16));
  return bytesToHex(b);
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, cls?: string, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined) node.textContent = text;
  return node;
}

/**
 * Render the 16 bytes as a row of byte cells, marking which changed vs a
 * previous state (for the "watch diffusion spread" effect).
 */
function byteRow(bytes: Uint8Array, changed?: boolean[]): HTMLElement {
  const row = el('div', 'sv-bytes');
  for (let i = 0; i < bytes.length; i++) {
    const cell = el('span', 'sv-byte', bytes[i].toString(16).padStart(2, '0'));
    if (changed && (changed[i * 8] || changed[i * 8 + 1] || changed[i * 8 + 2] || changed[i * 8 + 3] ||
      changed[i * 8 + 4] || changed[i * 8 + 5] || changed[i * 8 + 6] || changed[i * 8 + 7])) {
      cell.classList.add('changed');
    }
    row.appendChild(cell);
  }
  return row;
}

/** Extract the 4-bit nibble at bitslice position `bit` from four 32-bit words. */
function nibbleAt(words: number[], bit: number): number {
  return (
    ((words[0] >>> bit) & 1) |
    (((words[1] >>> bit) & 1) << 1) |
    (((words[2] >>> bit) & 1) << 2) |
    (((words[3] >>> bit) & 1) << 3)
  );
}

export function renderRoundVisualizer(container: HTMLElement): void {
  container.innerHTML = '';

  let inputHex = DEFAULT_BLOCK_HEX;
  let trace: EncryptTrace = encryptBlockTraced(hexToBytes(inputHex), DEMO_KEY);
  let current = 1; // 1..32
  // Which bitslice position's nibble to spotlight entering the S-box (0..31).
  let spotlight = 0;

  // --- Input controls -------------------------------------------------------
  const controls = el('div', 'sv-controls');

  const modeWrap = el('div', 'sv-mode');
  const modeText = el('button', 'sv-mode-btn active', 'Type text');
  modeText.type = 'button';
  modeText.setAttribute('aria-pressed', 'true');
  const modeHex = el('button', 'sv-mode-btn', 'Enter hex');
  modeHex.type = 'button';
  modeHex.setAttribute('aria-pressed', 'false');
  modeWrap.append(modeText, modeHex);

  const inputField = el('div', 'sv-field');
  const inputLabel = el('label', undefined, 'Plaintext block (16 bytes)');
  inputLabel.htmlFor = 'sv-input';
  const inputEl = el('input');
  inputEl.type = 'text';
  inputEl.id = 'sv-input';
  inputEl.spellcheck = false;
  inputEl.value = 'Serpent-256 demo';
  inputEl.maxLength = 16;
  const inputHelp = el('p', 'sv-help', 'Type up to 16 ASCII characters — they become the 16 bytes below.');
  inputField.append(inputLabel, inputEl, inputHelp);

  controls.append(modeWrap, inputField);
  container.appendChild(controls);

  // --- Round transport ------------------------------------------------------
  const transport = el('div', 'sv-transport');
  const prevBtn = el('button', 'ghost-btn', '← Prev round');
  prevBtn.type = 'button';
  const counter = el('span', 'sv-counter');
  counter.setAttribute('role', 'status');
  counter.setAttribute('aria-live', 'polite');
  const nextBtn = el('button', 'ghost-btn', 'Next round →');
  nextBtn.type = 'button';
  const playBtn = el('button', 'primary-btn sv-play', 'Play all 32 rounds');
  playBtn.type = 'button';
  const resetBtn = el('button', 'ghost-btn', 'Back to round 1');
  resetBtn.type = 'button';
  transport.append(prevBtn, counter, nextBtn, playBtn, resetBtn);
  container.appendChild(transport);

  // Round progress track (1..32) so the "32 rounds" claim is visible at a glance.
  const track = el('div', 'sv-track');
  track.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 32; i++) track.appendChild(el('span', 'sv-tick'));
  container.appendChild(track);

  // --- Round detail ---------------------------------------------------------
  const detail = el('div', 'sv-detail');
  container.appendChild(detail);

  // --- Diffusion tracker ----------------------------------------------------
  const diffusion = el('div', 'sv-diffusion');
  diffusion.setAttribute('role', 'status');
  diffusion.setAttribute('aria-live', 'polite');
  container.appendChild(diffusion);

  const note = el('p', 'sv-note');
  note.innerHTML =
    'Every field above is produced by a full, spec-accurate Serpent-256 that is verified ' +
    'byte-for-byte against the official AES test vectors and the WASM engine that encrypts your ' +
    'real messages. Watch the <strong>diffusion tracker</strong>: change one input bit and, round ' +
    'by round, the S-box and linear transform spread that single change across the whole block — ' +
    'that spreading <em>is</em> the avalanche effect, shown here as mechanism instead of a statistic.';
  container.appendChild(note);

  // --- S-box lookup table (reference) ---------------------------------------
  const sboxWrap = el('details', 'sv-sbox-table info-box');
  const sboxSummary = el('summary', undefined, 'The eight Serpent S-boxes (4-bit lookup tables)');
  sboxWrap.appendChild(sboxSummary);
  container.appendChild(sboxWrap);

  // A block that flips one input bit for the diffusion comparison baseline.
  function baselineTrace(): EncryptTrace {
    const pt = hexToBytes(inputHex);
    return encryptBlockTraced(pt, DEMO_KEY);
  }

  function render(): void {
    const stage = trace.stages[current - 1];
    counter.textContent = `Round ${current} of 32 — S-box S${stage.sboxIndex}`;

    // progress ticks
    Array.from(track.children).forEach((t, i) => {
      t.classList.toggle('done', i < current);
      t.classList.toggle('active', i === current - 1);
    });

    prevBtn.disabled = current === 1;
    nextBtn.disabled = current === 32;

    // Build the three-stage view for this round.
    detail.innerHTML = '';

    const inBytes = stateToDisplayBytes(stage.input);
    const kmBytes = stateToDisplayBytes(stage.afterKeyMix);
    const sbBytes = stateToDisplayBytes(stage.afterSBox);
    const ltBytes = stateToDisplayBytes(stage.afterLinear);

    // Stage 1: key mixing
    const s1 = el('div', 'sv-stage');
    s1.append(el('div', 'sv-stage-head', '1 · Key mixing'));
    s1.append(el('p', 'sv-stage-desc', `The block is XORed with round subkey K${current - 1}. Changed bytes are highlighted.`));
    s1.append(byteRow(inBytes, undefined));
    s1.append(el('div', 'sv-op', '⊕ XOR subkey ↓'));
    s1.append(byteRow(kmBytes, diffBytes(inBytes, kmBytes)));
    detail.appendChild(s1);

    // Stage 2: S-box substitution (the confusion step)
    const s2 = el('div', 'sv-stage');
    s2.append(el('div', 'sv-stage-head', `2 · S-box substitution (S${stage.sboxIndex})`));
    s2.append(el('p', 'sv-stage-desc',
      'Serpent splits the 128-bit block into 32 four-bit groups and pushes each through the ' +
      'same 4-bit lookup table. This nonlinear swap is the cipher’s "confusion". ' +
      'Use the slider to spotlight one group entering and leaving the table.'));

    // spotlight one nibble entering/leaving
    const nibIn = nibbleAt(stage.afterKeyMix, spotlight);
    const nibOut = SBOX[stage.sboxIndex][nibIn];
    const lookup = el('div', 'sv-lookup');
    lookup.append(makeNibbleCard('Group entering', nibIn, 'in'));
    lookup.append(el('div', 'sv-lookup-arrow', `S${stage.sboxIndex}[${nibIn}] = ${nibOut}`));
    lookup.append(makeNibbleCard('Group leaving', nibOut, 'out'));
    s2.appendChild(lookup);

    const sliderWrap = el('div', 'sv-slider');
    const sliderLabel = el('label', undefined, `Spotlight 4-bit group # (0–31): ${spotlight}`);
    sliderLabel.htmlFor = 'sv-spotlight';
    const slider = el('input');
    slider.type = 'range';
    slider.id = 'sv-spotlight';
    slider.min = '0';
    slider.max = '31';
    slider.value = String(spotlight);
    slider.addEventListener('input', () => {
      spotlight = parseInt(slider.value, 10);
      render();
    });
    sliderWrap.append(sliderLabel, slider);
    s2.appendChild(sliderWrap);
    s2.append(byteRow(sbBytes, diffBytes(kmBytes, sbBytes)));
    detail.appendChild(s2);

    // Stage 3: linear transform (the diffusion step) — or final key XOR
    const s3 = el('div', 'sv-stage');
    if (stage.isFinal) {
      s3.append(el('div', 'sv-stage-head', '3 · Final subkey XOR (round 32)'));
      s3.append(el('p', 'sv-stage-desc',
        'The last round skips the linear transform and instead XORs the 33rd subkey K32. ' +
        'The result below IS the ciphertext.'));
    } else {
      s3.append(el('div', 'sv-stage-head', '3 · Linear transformation'));
      s3.append(el('p', 'sv-stage-desc',
        'A fixed mix of rotations and XORs spreads each bit’s influence across the block — ' +
        'the cipher’s "diffusion". This is why one flipped input bit avalanches into many.'));
    }
    s3.append(byteRow(ltBytes, diffBytes(sbBytes, ltBytes)));
    detail.appendChild(s3);

    // Diffusion tracker: how far has ONE flipped input bit spread by now?
    const base = baselineTrace();
    const flipped = flippedTrace();
    const hereBase = current === 32 ? base.ciphertext : base.stages[current - 1].afterLinear;
    const hereFlip = current === 32 ? flipped.ciphertext : flipped.stages[current - 1].afterLinear;
    const spread = diffBits(hereBase, hereFlip).filter(Boolean).length;
    const pct = ((spread / 128) * 100).toFixed(0);
    diffusion.innerHTML =
      `<strong>Diffusion after round ${current}:</strong> flipping input bit&nbsp;#0 changes ` +
      `<strong>${spread} of 128</strong> block bits so far (${pct}%). ` +
      (current < 32
        ? 'Keep stepping — watch it climb toward ~50%.'
        : 'By the final round it sits near 50%: full avalanche.');
    renderDiffGrid(diffusion, diffBits(hereBase, hereFlip));

    // populate S-box table once
    if (!sboxWrap.dataset.filled) {
      const tbl = el('div', 'sv-sbox-grid');
      for (let s = 0; s < 8; s++) {
        const col = el('div', 'sv-sbox-col');
        col.append(el('div', 'sv-sbox-name', `S${s}`));
        for (let i = 0; i < 16; i++) {
          col.append(el('span', 'sv-sbox-cell', `${i}→${SBOX[s][i]}`));
        }
        tbl.appendChild(col);
      }
      sboxWrap.appendChild(tbl);
      sboxWrap.dataset.filled = '1';
    }
  }

  function flippedTrace(): EncryptTrace {
    const pt = hexToBytes(inputHex);
    // Flip input bit #0 in the same external convention the block uses.
    pt[pt.length - 1] ^= 0x01;
    return encryptBlockTraced(pt, DEMO_KEY);
  }

  function makeNibbleCard(title: string, val: number, kind: 'in' | 'out'): HTMLElement {
    const card = el('div', `sv-nib sv-nib-${kind}`);
    card.append(el('div', 'sv-nib-title', title));
    const bits = el('div', 'sv-nib-bits');
    for (let b = 3; b >= 0; b--) bits.append(el('span', 'sv-nib-bit', String((val >>> b) & 1)));
    card.append(bits);
    card.append(el('div', 'sv-nib-val', `= ${val} (0x${val.toString(16)})`));
    return card;
  }

  function diffBytes(a: Uint8Array, b: Uint8Array): boolean[] {
    // Return a per-BIT changed array (8 bits per byte) so byteRow can mark cells.
    const out: boolean[] = [];
    for (let i = 0; i < a.length; i++) {
      for (let bit = 0; bit < 8; bit++) out.push(((a[i] ^ b[i]) & (0x80 >> bit)) !== 0);
    }
    return out;
  }

  function renderDiffGrid(host: HTMLElement, diff: boolean[]): void {
    const grid = el('div', 'sv-diff-grid');
    grid.setAttribute('role', 'img');
    grid.setAttribute('aria-label', `${diff.filter(Boolean).length} of 128 bits differ from the unflipped block`);
    diff.forEach((on) => grid.appendChild(el('span', on ? 'sv-diff-cell on' : 'sv-diff-cell')));
    host.appendChild(grid);
  }

  // --- Wiring ---------------------------------------------------------------
  function reload(): void {
    trace = encryptBlockTraced(hexToBytes(inputHex), DEMO_KEY);
    if (current > 32) current = 32;
    render();
  }

  let hexMode = false;
  function setMode(hex: boolean): void {
    hexMode = hex;
    modeText.classList.toggle('active', !hex);
    modeHex.classList.toggle('active', hex);
    modeText.setAttribute('aria-pressed', String(!hex));
    modeHex.setAttribute('aria-pressed', String(hex));
    if (hex) {
      inputLabel.textContent = 'Plaintext block (16 bytes · 32 hex chars)';
      inputEl.maxLength = 32;
      inputEl.value = inputHex;
      inputHelp.textContent = 'Enter exactly 32 hexadecimal characters (16 bytes).';
    } else {
      inputLabel.textContent = 'Plaintext block (16 bytes)';
      inputEl.maxLength = 16;
      inputEl.value = asciiFromHex(inputHex);
      inputHelp.textContent = 'Type up to 16 ASCII characters — they become the 16 bytes below.';
    }
  }

  function asciiFromHex(hex: string): string {
    const bytes = hexToBytes(hex);
    let s = '';
    for (const b of bytes) if (b !== 0) s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.';
    return s;
  }

  inputEl.addEventListener('input', () => {
    if (hexMode) {
      const h = inputEl.value.trim().toLowerCase();
      if (/^[0-9a-f]{32}$/.test(h)) {
        inputHex = h;
        inputHelp.textContent = 'Valid 16-byte block.';
        reload();
      } else {
        inputHelp.textContent = 'Enter exactly 32 hexadecimal characters (16 bytes).';
      }
    } else {
      inputHex = asciiToHex(inputEl.value);
      reload();
    }
  });
  modeText.addEventListener('click', () => setMode(false));
  modeHex.addEventListener('click', () => setMode(true));

  prevBtn.addEventListener('click', () => { if (current > 1) { current--; render(); } });
  nextBtn.addEventListener('click', () => { if (current < 32) { current++; render(); } });
  resetBtn.addEventListener('click', () => { current = 1; render(); });

  let playTimer: ReturnType<typeof setInterval> | null = null;
  playBtn.addEventListener('click', () => {
    if (playTimer) { stopPlay(); return; }
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (reduce) { current = 32; render(); return; }
    current = 1; render();
    playBtn.textContent = 'Pause';
    playTimer = setInterval(() => {
      if (current >= 32) { stopPlay(); return; }
      current++; render();
    }, 260);
  });
  function stopPlay(): void {
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
    playBtn.textContent = 'Play all 32 rounds';
  }

  render();
}
