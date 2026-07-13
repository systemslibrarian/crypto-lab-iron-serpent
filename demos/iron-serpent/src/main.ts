import './style.css';
import { initSerpent } from './serpent';
import { encrypt, decrypt } from './crypto';
import type { EncryptedPayload } from './crypto';
import { renderVisualization } from './visualization';
import { renderAvalanche } from './avalanche';
import { renderCtrExplainer } from './ctr-explainer';
import { renderRoundVisualizer } from './round-visualizer';
import { runBenchmark } from './benchmark';
import { estimateStrength } from './passphrase-strength';

let lastPayload: EncryptedPayload | null = null;
let outputFormat: 'base64' | 'hex' = 'base64';
// The last payload that decrypted+authenticated cleanly, kept so the tamper lab
// can flip a bit of a known-good payload and let the learner watch the MAC fire.
let lastGoodDecryptPayload: EncryptedPayload | null = null;

function $(id: string): HTMLElement {
  return document.getElementById(id)!;
}

function getTheme(): 'dark' | 'light' {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
}

function syncThemeToggle(theme = getTheme()) {
  const toggle = $('theme-toggle') as HTMLButtonElement;
  const darkMode = theme === 'dark';
  toggle.textContent = darkMode ? '🌙' : '☀️';
  const label = darkMode ? 'Switch to light mode' : 'Switch to dark mode';
  toggle.setAttribute('aria-label', label);
  toggle.title = label;
}

function setTheme(theme: 'dark' | 'light') {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
  syncThemeToggle(theme);
}

function toHexString(b64: string): string {
  const binary = atob(b64);
  return Array.from(binary, (c) => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

/**
 * Flip exactly one bit in a base64-encoded field and return the mutated base64.
 * Decodes to bytes, XORs one bit of one byte, re-encodes — so the field stays
 * valid base64 of the same length but its decoded content differs by a single bit.
 * This is what the tamper lab uses to corrupt a real payload in place.
 */
function flipOneBitInBase64(b64: string): string {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  const byteIndex = Math.floor(Math.random() * bytes.length);
  const bitMask = 0x80 >> Math.floor(Math.random() * 8);
  bytes[byteIndex] ^= bitMask;
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return btoa(out);
}

/** Copy text to the clipboard with visible success/failure feedback on the button. */
async function copyWithFeedback(btn: HTMLButtonElement, text: string): Promise<void> {
  const prev = btn.textContent;
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied!';
  } catch {
    btn.textContent = 'Copy failed';
  }
  setTimeout(() => { btn.textContent = prev; }, 1500);
}

/** Trigger the primary button when Ctrl+Enter (or Cmd+Enter) is pressed inside a panel field. */
function wireSubmitShortcut(fieldIds: string[], buttonId: string): void {
  for (const id of fieldIds) {
    $(id).addEventListener('keydown', (e) => {
      const key = e as KeyboardEvent;
      if (key.key === 'Enter' && (key.ctrlKey || key.metaKey)) {
        key.preventDefault();
        const btn = $(buttonId) as HTMLButtonElement;
        if (!btn.disabled) btn.click();
      }
    });
  }
}

function formatPayload(p: EncryptedPayload, fmt: 'base64' | 'hex'): string {
  if (fmt === 'hex') {
    return JSON.stringify({
      salt: toHexString(p.salt),
      nonce: toHexString(p.nonce),
      ciphertext: toHexString(p.ciphertext),
      mac: toHexString(p.mac),
      version: p.version,
    }, null, 2);
  }
  return JSON.stringify(p, null, 2);
}

async function init() {
  syncThemeToggle();
  ($('theme-toggle') as HTMLButtonElement).addEventListener('click', () => {
    setTheme(getTheme() === 'dark' ? 'light' : 'dark');
  });

  const status = $('init-status');
  try {
    await initSerpent();
    status.textContent = 'Serpent-256 engine ready.';
    status.classList.add('ready');
    ($('enc-btn') as HTMLButtonElement).disabled = false;
    ($('dec-btn') as HTMLButtonElement).disabled = false;
  } catch (e) {
    status.textContent = `Initialization failed: ${e instanceof Error ? e.message : e}`;
    status.classList.add('error');
    return;
  }

  // --- Guided tour / progressive disclosure -------------------------------
  // The advanced exhibits start locked. A clean encrypt→decrypt round trip
  // marks step 1 complete and unlocks the reveal; the reveal button (or an
  // impatient click) opens the analysis panels. Sequencing keeps a newcomer
  // from meeting an entire AEAD scheme plus four analysis panels at once.
  let exhibitsRevealed = false;
  const revealExhibits = (scroll: boolean) => {
    if (exhibitsRevealed) return;
    exhibitsRevealed = true;
    const adv = $('advanced-exhibits');
    adv.classList.remove('exhibits-locked');
    adv.removeAttribute('aria-hidden');
    const revealBtn = $('tour-reveal') as HTMLButtonElement;
    revealBtn.disabled = true;
    revealBtn.textContent = 'Exhibits unlocked ✓';
    $('tour-step-3').classList.add('done');
    if (scroll) {
      const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      $('rounds-section').scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'start' });
    }
  };
  const completeRoundTrip = () => {
    $('tour-step-1').classList.add('done');
    $('tour-step-1').classList.remove('active');
    const step2 = $('tour-step-2');
    step2.classList.add('active');
    $('tour-step-3').classList.add('active');
    const hint = $('tour-hint-1');
    if (hint) hint.textContent = 'Done ✓';
    const revealBtn = $('tour-reveal') as HTMLButtonElement;
    revealBtn.disabled = false;
    revealBtn.textContent = 'Unlock and explore the exhibits →';
  };
  ($('tour-reveal') as HTMLButtonElement).addEventListener('click', () => revealExhibits(true));

  // --- Password toggle ---
  for (const prefix of ['enc', 'dec']) {
    const input = $(`${prefix}-pass`) as HTMLInputElement;
    $(`${prefix}-pass-toggle`).addEventListener('click', () => {
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

  // --- Passphrase strength meter ---
  const passInput = $('enc-pass') as HTMLInputElement;
  passInput.addEventListener('input', () => {
    const wrap = $('pass-strength');
    const fill = $('pass-strength-fill');
    const text = $('pass-strength-text');
    if (!passInput.value) {
      wrap.classList.add('hidden');
      return;
    }
    const est = estimateStrength(passInput.value);
    wrap.classList.remove('hidden');
    fill.style.width = `${Math.min(100, (est.bits / 100) * 100)}%`;
    fill.dataset.score = String(est.score);
    text.textContent = est.warning
      ? est.warning
      : `~${est.bits} bits · ${est.label} · ${est.crackTime} to crack at 10,000 Argon2id guesses/second`;
    text.classList.toggle('warn', Boolean(est.warning) || est.score < 2);
  });

  // --- Keyboard shortcuts ---
  wireSubmitShortcut(['enc-pass', 'enc-input'], 'enc-btn');
  wireSubmitShortcut(['dec-pass', 'dec-input'], 'dec-btn');

  // --- Encrypt ---
  $('enc-btn').addEventListener('click', async () => {
    const pass = ($('enc-pass') as HTMLInputElement).value;
    const text = ($('enc-input') as HTMLTextAreaElement).value;
    if (!pass || !text) return;

    // Encode to bytes at the UI boundary — crypto layer never sees strings
    const passBytes = new TextEncoder().encode(pass);
    const plainBytes = new TextEncoder().encode(text);

    const btn = $('enc-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = 'Encrypting (32 rounds per block)…';
    try {
      lastPayload = await encrypt(plainBytes, passBytes);
      ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
      ($('enc-to-dec') as HTMLButtonElement).disabled = false;
      ($('enc-download') as HTMLButtonElement).disabled = false;
    } catch (e) {
      ($('enc-output') as HTMLTextAreaElement).value = `Error: ${e instanceof Error ? e.message : e}`;
    } finally {
      passBytes.fill(0);
      plainBytes.fill(0);
      btn.disabled = false;
      btn.textContent = 'Encrypt (full 32 rounds)';
    }
  });

  // --- Format toggle ---
  const setFormat = (fmt: 'base64' | 'hex') => {
    outputFormat = fmt;
    for (const [id, active] of [['enc-fmt-b64', fmt === 'base64'], ['enc-fmt-hex', fmt === 'hex']] as const) {
      $(id).classList.toggle('active', active);
      $(id).setAttribute('aria-pressed', String(active));
    }
    if (lastPayload) ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
  };
  $('enc-fmt-b64').addEventListener('click', () => setFormat('base64'));
  $('enc-fmt-hex').addEventListener('click', () => setFormat('hex'));

  // --- Copy ---
  $('enc-copy').addEventListener('click', () => {
    const output = ($('enc-output') as HTMLTextAreaElement).value;
    if (output) copyWithFeedback($('enc-copy') as HTMLButtonElement, output);
  });
  $('dec-copy').addEventListener('click', () => {
    const output = ($('dec-output') as HTMLTextAreaElement).value;
    if (output) copyWithFeedback($('dec-copy') as HTMLButtonElement, output);
  });

  // --- Download payload ---
  $('enc-download').addEventListener('click', () => {
    if (!lastPayload) return;
    // Always download the canonical base64 payload — that's what Decrypt accepts.
    const blob = new Blob([formatPayload(lastPayload, 'base64')], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'iron-serpent-payload.json';
    a.click();
    URL.revokeObjectURL(url);
  });

  // The tamper lab is tied to the payload that last authenticated. Any time the
  // decrypt input changes to something else, retire it until a fresh clean decrypt.
  const resetTamperLab = () => {
    lastGoodDecryptPayload = null;
    $('tamper-lab').classList.add('hidden');
  };

  // --- Load payload from file ---
  const fileInput = $('dec-file-input') as HTMLInputElement;
  $('dec-load-file').addEventListener('click', () => fileInput.click());
  fileInput.addEventListener('change', async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    ($('dec-input') as HTMLTextAreaElement).value = await file.text();
    resetTamperLab();
    fileInput.value = '';
    ($('dec-pass') as HTMLInputElement).focus();
  });

  ($('dec-input') as HTMLTextAreaElement).addEventListener('input', () => {
    // Only reset if the user is hand-editing to a payload we no longer know is good.
    if (!lastGoodDecryptPayload) return;
    const current = ($('dec-input') as HTMLTextAreaElement).value;
    if (current !== JSON.stringify(lastGoodDecryptPayload, null, 2)) resetTamperLab();
  });

  // --- Load example ---
  $('enc-example').addEventListener('click', () => {
    ($('enc-pass') as HTMLInputElement).value = 'correct horse battery staple';
    // Fire the input event so the strength meter reacts to the programmatic fill —
    // it will (correctly) flag this famous xkcd passphrase as well-known.
    $('enc-pass').dispatchEvent(new Event('input'));
    ($('enc-input') as HTMLTextAreaElement).value =
      'Serpent ran all 32 rounds to encrypt this message in your browser — no plaintext ever left this tab.';
    ($('enc-input') as HTMLTextAreaElement).focus();
  });

  // --- Send payload to Decrypt (one-click round trip) ---
  $('enc-to-dec').addEventListener('click', () => {
    if (!lastPayload) return;
    // Always hand over the canonical base64 payload — hex view is display-only.
    ($('dec-input') as HTMLTextAreaElement).value = formatPayload(lastPayload, 'base64');
    ($('dec-pass') as HTMLInputElement).value = ($('enc-pass') as HTMLInputElement).value;
    resetTamperLab();
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    $('decrypt-panel').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
    ($('dec-btn') as HTMLButtonElement).focus();
  });

  // --- Decrypt ---
  // Shared decrypt routine used by the Decrypt button AND the tamper lab, so a
  // tampered payload runs the exact same verify-then-decrypt path.
  const tamperLab = $('tamper-lab');
  async function runDecrypt(): Promise<void> {
    const pass = ($('dec-pass') as HTMLInputElement).value;
    const input = ($('dec-input') as HTMLTextAreaElement).value;
    if (!pass || !input) return;

    // Encode passphrase to bytes at the UI boundary
    const passBytes = new TextEncoder().encode(pass);

    const btn = $('dec-btn') as HTMLButtonElement;
    btn.disabled = true;
    btn.textContent = 'Decrypting (32 rounds per block)…';
    const badge = $('auth-badge');

    try {
      const payload: EncryptedPayload = JSON.parse(input);
      const resultBytes = await decrypt(payload, passBytes);
      // Decode bytes to string for display, then zero the bytes
      ($('dec-output') as HTMLTextAreaElement).value = new TextDecoder().decode(resultBytes);
      resultBytes.fill(0);
      badge.textContent = '✓ Authenticated';
      badge.className = 'badge verified';
      // A clean decrypt means this JSON is a known-good payload — offer the tamper lab.
      lastGoodDecryptPayload = payload;
      tamperLab.classList.remove('hidden');
      // The core round trip just succeeded — advance the guided tour.
      completeRoundTrip();
    } catch (e) {
      ($('dec-output') as HTMLTextAreaElement).value = '';
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.includes('tampered')) {
        badge.textContent = '✗ Authentication Failed';
        badge.className = 'badge failed';
      } else if (e instanceof SyntaxError || msg.startsWith('Invalid encrypted payload') || msg === 'Unsupported payload version') {
        badge.textContent = '✗ Invalid Payload';
        badge.className = 'badge failed';
      } else {
        badge.textContent = `Error: ${msg}`;
        badge.className = 'badge failed';
      }
    } finally {
      passBytes.fill(0);
      btn.disabled = false;
      btn.textContent = 'Decrypt (full 32 rounds)';
    }
  }
  $('dec-btn').addEventListener('click', runDecrypt);

  // --- Tamper lab: flip one bit of a known-good payload, then re-run decrypt ---
  const tamperExplain = $('tamper-explain');
  const setTamperExplain = (html: string, warn: boolean) => {
    tamperExplain.innerHTML = html;
    tamperExplain.classList.toggle('warn', warn);
  };
  // Flip a bit in one field of the last-good payload, drop it into the textarea,
  // and re-run the real verify-then-decrypt path so the badge reacts for real.
  const tamperField = async (field: 'ciphertext' | 'mac', label: string) => {
    if (!lastGoodDecryptPayload) return;
    const mutated: EncryptedPayload = { ...lastGoodDecryptPayload };
    mutated[field] = flipOneBitInBase64(lastGoodDecryptPayload[field]);
    ($('dec-input') as HTMLTextAreaElement).value = JSON.stringify(mutated, null, 2);
    setTamperExplain(
      `Flipped one bit of the <strong>${label}</strong>. The HMAC covers salt‖nonce‖ciphertext‖version, ` +
      'so the recomputed tag no longer matches — verification fails and <strong>Serpent never runs</strong>. ' +
      'This is exactly why we verify-then-decrypt.',
      true,
    );
    await runDecrypt();
  };
  $('tamper-ct').addEventListener('click', () => tamperField('ciphertext', 'ciphertext'));
  $('tamper-mac').addEventListener('click', () => tamperField('mac', 'MAC tag'));
  $('tamper-restore').addEventListener('click', async () => {
    if (!lastGoodDecryptPayload) return;
    ($('dec-input') as HTMLTextAreaElement).value = JSON.stringify(lastGoodDecryptPayload, null, 2);
    setTamperExplain(
      'Restored the intact payload — the tag matches again, so verification passes and ' +
      'Serpent decrypts it back to the original plaintext.',
      false,
    );
    await runDecrypt();
  });

  // --- Serpent round visualizer ---
  renderRoundVisualizer($('rounds-container'));

  // --- Visualization ---
  renderVisualization($('vis-container'));

  // --- Avalanche effect ---
  renderAvalanche($('avalanche-container'));

  // --- CTR mode explainer ---
  renderCtrExplainer($('ctr-container'));

  // --- Benchmark ---
  $('bench-btn').addEventListener('click', async () => {
    const btn = $('bench-btn') as HTMLButtonElement;
    const dataSizeSelect = $('bench-data-size') as HTMLSelectElement;
    const iterationsSelect = $('bench-iterations') as HTMLSelectElement;
    const dataSize = parseInt(dataSizeSelect.value, 10);
    const iterations = parseInt(iterationsSelect.value, 10);

    btn.disabled = true;
    dataSizeSelect.disabled = true;
    iterationsSelect.disabled = true;
    const progressWrap = $('bench-progress');
    const progressText = $('bench-progress-text');
    const progressFill = $('bench-progress-fill');
    const results = $('bench-results');
    progressWrap.classList.remove('hidden');
    results.classList.add('hidden');

    // warmup serpent (2) + N runs serpent + warmup aes (2) + N runs aes
    const TOTAL_STEPS = 4 + iterations * 2;
    let step = 0;
    function advance(label: string) {
      step++;
      progressText.textContent = label;
      const pct = Math.round((step / TOTAL_STEPS) * 100);
      progressFill.style.width = `${pct}%`;
      progressFill.parentElement?.setAttribute('aria-valuenow', `${pct}`);
    }

    try {
      const r = await runBenchmark((msg) => {
        advance(msg);
      }, { dataSize, iterations });

      const sizeLabel = dataSize >= 1048576
        ? `${(dataSize / 1048576).toFixed(dataSize % 1048576 === 0 ? 0 : 1)} MB`
        : `${(dataSize / 1024).toFixed(0)} KB`;

      $('bench-meta-iters').textContent = String(iterations);
      $('bench-meta-size').textContent = sizeLabel;
      $('bench-serpent').textContent = `${r.serpentMBps.toFixed(1)} MB/s`;
      $('bench-aes').textContent = `${r.aesMBps.toFixed(1)} MB/s`;
      $('bench-ratio').textContent = `AES is ${r.ratio.toFixed(1)}× faster`;
      results.classList.remove('hidden');
    } catch (e) {
      progressText.textContent = `Benchmark error: ${e instanceof Error ? e.message : e}`;
    } finally {
      btn.disabled = false;
      dataSizeSelect.disabled = false;
      iterationsSelect.disabled = false;
      progressWrap.classList.add('hidden');
    }
  });
}

init();

