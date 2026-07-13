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
const DEFAULT_MESSAGE_2 = 'Retreat at dusk. -Serpent';

/** ASCII-printable rendering of a byte: the char if printable, else '·'. */
function asciiPrintable(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '·';
  return s;
}

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
    'a keystream, and XORing their ciphertexts together would cancel it out entirely. ' +
    'The toggle below lets you watch exactly that happen.';

  container.append(controls, blocksWrap, stat, note);

  // --- Nonce-reuse demonstration ---------------------------------------------
  // The warning above says reusing a nonce cancels the keystream. This makes it
  // demonstrable: encrypt TWO different messages under the SAME nonce (and key),
  // then show that ct1 XOR ct2 equals pt1 XOR pt2 — the keystream is gone.
  const reuseWrap = el('div', 'ctr-reuse');

  const reuseToggleWrap = el('div', 'ctr-reuse-toggle');
  const reuseCheckbox = el('input');
  reuseCheckbox.type = 'checkbox';
  reuseCheckbox.id = 'ctr-reuse-on';
  const reuseToggleLabel = el('label', 'ctr-reuse-toggle-label',
    'Show the danger: reuse this nonce for a second message');
  reuseToggleLabel.htmlFor = 'ctr-reuse-on';
  reuseToggleWrap.append(reuseCheckbox, reuseToggleLabel);

  const reuseBody = el('div', 'ctr-reuse-body hidden');
  reuseBody.id = 'ctr-reuse-body';

  const msg2Field = el('div', 'avalanche-field');
  const msg2Label = el('label', undefined, `Second message, SAME nonce (up to ${MAX_MESSAGE_BYTES} chars)`);
  msg2Label.htmlFor = 'ctr-message-2';
  const msg2Input = el('input');
  msg2Input.type = 'text';
  msg2Input.id = 'ctr-message-2';
  msg2Input.maxLength = MAX_MESSAGE_BYTES;
  msg2Input.spellcheck = false;
  msg2Input.value = DEFAULT_MESSAGE_2;
  msg2Field.append(msg2Label, msg2Input);

  const reuseRows = el('div', 'ctr-reuse-rows');
  reuseRows.id = 'ctr-reuse-rows';

  const reuseStat = el('div', 'avalanche-stat warn');
  reuseStat.id = 'ctr-reuse-stat';
  reuseStat.setAttribute('role', 'status');
  reuseStat.setAttribute('aria-live', 'polite');

  reuseBody.append(msg2Field, reuseRows, reuseStat);
  reuseWrap.append(reuseToggleWrap, reuseBody);
  container.append(reuseWrap);

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

  /** Real CTR keystream-XOR encryption of `pt` under `nonce`, block by block. */
  const ctrEncrypt = (nonce: Uint8Array, pt: Uint8Array): Uint8Array => {
    const out = new Uint8Array(pt.length);
    const nBlocks = Math.ceil(pt.length / BLOCK_SIZE);
    for (let i = 0; i < nBlocks; i++) {
      const keystream = cipher.encryptBlock(counterBlock(nonce, i));
      const chunk = pt.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
      out.set(xorBytes(chunk, keystream.subarray(0, chunk.length)), i * BLOCK_SIZE);
    }
    return out;
  };

  const recomputeReuse = () => {
    if (!reuseCheckbox.checked) return;
    const nonceHex = nonceInput.value.trim().toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(nonceHex)) {
      reuseRows.innerHTML = '';
      reuseStat.textContent = 'Fix the nonce above (32 hex chars) to run the reuse demo.';
      return;
    }
    const m1 = msgInput.value;
    const m2 = msg2Input.value;
    if (m1.length === 0 || m2.length === 0) {
      reuseRows.innerHTML = '';
      reuseStat.textContent = 'Enter both messages to see the keystream cancel out.';
      return;
    }

    const nonce = hexToBytes(nonceHex);
    const pt1 = new TextEncoder().encode(m1.slice(0, MAX_MESSAGE_BYTES));
    const pt2 = new TextEncoder().encode(m2.slice(0, MAX_MESSAGE_BYTES));
    // Compare over the shared prefix length — where both keystreams line up.
    const n = Math.min(pt1.length, pt2.length);
    const p1 = pt1.subarray(0, n);
    const p2 = pt2.subarray(0, n);

    // Same nonce, same key → identical keystream for both messages.
    const ct1 = ctrEncrypt(nonce, p1);
    const ct2 = ctrEncrypt(nonce, p2);
    const ctXor = xorBytes(ct1, ct2);   // keystream cancels: ct1⊕ct2
    const ptXor = xorBytes(p1, p2);     // …equals pt1⊕pt2 exactly

    reuseRows.innerHTML = '';
    reuseRows.appendChild(hexRow('Ciphertext 1', ct1));
    reuseRows.appendChild(hexRow('Ciphertext 2', ct2));
    reuseRows.appendChild(el('div', 'ctr-op', '⊕ XOR the two ciphertexts — the shared keystream cancels'));
    reuseRows.appendChild(hexRow('CT1 ⊕ CT2', ctXor));
    reuseRows.appendChild(hexRow('PT1 ⊕ PT2', ptXor));
    const asciiRow = el('div', 'ctr-reuse-ascii');
    asciiRow.append(
      el('span', 'ctr-row-label', 'PT1 ⊕ PT2 as text'),
      el('code', 'ctr-hex', asciiPrintable(ptXor)),
    );
    reuseRows.appendChild(asciiRow);

    // These two rows are byte-for-byte identical — assert it, don't just claim it.
    const identical = bytesToHex(ctXor) === bytesToHex(ptXor);
    reuseStat.innerHTML = identical
      ? '<strong>CT1 ⊕ CT2 = PT1 ⊕ PT2.</strong> The keystream is gone. An attacker who never had the key ' +
        'now holds the XOR of your two plaintexts — and with any crib or known structure can peel both apart. ' +
        'This is why a nonce must be unique per message.'
      : 'Unexpected mismatch — this should never happen with a correct CTR construction.';
  };

  msgInput.addEventListener('input', () => { recompute(); recomputeReuse(); });
  nonceInput.addEventListener('input', () => { recompute(); recomputeReuse(); });
  msg2Input.addEventListener('input', recomputeReuse);
  reuseCheckbox.addEventListener('change', () => {
    reuseBody.classList.toggle('hidden', !reuseCheckbox.checked);
    recomputeReuse();
  });
  randomBtn.addEventListener('click', () => {
    randomizeNonce();
    recompute();
    recomputeReuse();
  });

  recompute();
}
