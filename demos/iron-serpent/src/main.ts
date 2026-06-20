import './style.css';
import { initSerpent } from './serpent';
import { encrypt, decrypt } from './crypto';
import type { EncryptedPayload } from './crypto';
import { renderVisualization } from './visualization';
import { renderAvalanche } from './avalanche';
import { runBenchmark } from './benchmark';

let lastPayload: EncryptedPayload | null = null;
let outputFormat: 'base64' | 'hex' = 'base64';

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

  // --- Password toggle ---
  for (const prefix of ['enc', 'dec']) {
    const input = $(`${prefix}-pass`) as HTMLInputElement;
    $(`${prefix}-pass-toggle`).addEventListener('click', () => {
      input.type = input.type === 'password' ? 'text' : 'password';
    });
  }

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
  $('enc-fmt-b64').addEventListener('click', () => {
    outputFormat = 'base64';
    $('enc-fmt-b64').classList.add('active');
    $('enc-fmt-hex').classList.remove('active');
    if (lastPayload) ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
  });
  $('enc-fmt-hex').addEventListener('click', () => {
    outputFormat = 'hex';
    $('enc-fmt-hex').classList.add('active');
    $('enc-fmt-b64').classList.remove('active');
    if (lastPayload) ($('enc-output') as HTMLTextAreaElement).value = formatPayload(lastPayload, outputFormat);
  });

  // --- Copy ---
  $('enc-copy').addEventListener('click', async () => {
    const output = ($('enc-output') as HTMLTextAreaElement).value;
    if (!output) return;
    await navigator.clipboard.writeText(output);
    const btn = $('enc-copy') as HTMLButtonElement;
    const prev = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = prev; }, 1500);
  });

  // --- Load example ---
  $('enc-example').addEventListener('click', () => {
    ($('enc-pass') as HTMLInputElement).value = 'correct horse battery staple';
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
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    $('decrypt-panel').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
    ($('dec-btn') as HTMLButtonElement).focus();
  });

  // --- Decrypt ---
  $('dec-btn').addEventListener('click', async () => {
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
  });

  // --- Visualization ---
  renderVisualization($('vis-container'));

  // --- Avalanche effect ---
  renderAvalanche($('avalanche-container'));

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

