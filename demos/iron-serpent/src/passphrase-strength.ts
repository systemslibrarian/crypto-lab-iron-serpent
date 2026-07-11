/**
 * Honest passphrase strength estimate for the encrypt panel.
 *
 * Two models, and we report the weaker one:
 * - Charset model: length × log2(pool implied by the character classes used).
 * - Word model: for space-separated word passphrases, words × log2(7776)
 *   (Diceware wordlist size) — a random-character model badly overestimates
 *   "correct horse battery staple"-style passphrases.
 *
 * Crack time assumes an offline attacker with the payload who must pay full
 * Argon2id cost (t=3, 64 MiB) per guess — ~10,000 guesses/second is a
 * generous estimate for a well-funded GPU rig against this KDF.
 */

export interface StrengthEstimate {
  bits: number;
  /** 0=very weak … 4=excellent */
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  crackTime: string;
  warning?: string;
}

const GUESSES_PER_SECOND = 10_000;

/** Famous or extremely common passphrases no entropy model should flatter. */
const WELL_KNOWN = new Set([
  'password', 'password1', 'passw0rd', '123456', '12345678', '123456789',
  'qwerty', 'letmein', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon',
  'trustno1', '111111', 'abc123', 'hunter2', 'sunshine', 'princess',
  'correct horse battery staple',
]);

function charsetBits(pass: string): number {
  let pool = 0;
  if (/[a-z]/.test(pass)) pool += 26;
  if (/[A-Z]/.test(pass)) pool += 26;
  if (/[0-9]/.test(pass)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) pool += 33;
  return pass.length * Math.log2(pool || 1);
}

function wordModelBits(pass: string): number | null {
  const words = pass.trim().split(/\s+/);
  if (words.length < 3) return null;
  if (!words.every((w) => /^[a-z]+$/i.test(w))) return null;
  return words.length * Math.log2(7776);
}

function humanTime(seconds: number): string {
  if (seconds < 1) return 'instantly';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`;
  if (seconds < 86400 * 365) return `${Math.round(seconds / 86400)} days`;
  const years = seconds / (86400 * 365);
  if (years < 1000) return `${Math.round(years)} years`;
  if (years < 1e6) return `${Math.round(years / 1000)} thousand years`;
  if (years < 1e9) return `${Math.round(years / 1e6)} million years`;
  return 'longer than the age of the universe';
}

export function estimateStrength(pass: string): StrengthEstimate {
  if (pass.length === 0) {
    return { bits: 0, score: 0, label: 'empty', crackTime: 'instantly' };
  }

  if (WELL_KNOWN.has(pass.toLowerCase().trim())) {
    return {
      bits: 0,
      score: 0,
      label: 'well-known',
      crackTime: 'instantly',
      warning: 'This exact passphrase is in every cracking wordlist — Argon2id cannot save a passphrase the attacker already knows.',
    };
  }

  const wordBits = wordModelBits(pass);
  const bits = wordBits === null ? charsetBits(pass) : Math.min(charsetBits(pass), wordBits);

  // Average-case guesses = half the keyspace.
  const seconds = Math.pow(2, bits - 1) / GUESSES_PER_SECOND;
  const crackTime = humanTime(seconds);

  let score: StrengthEstimate['score'];
  let label: string;
  if (bits < 28) { score = 0; label = 'very weak'; }
  else if (bits < 45) { score = 1; label = 'weak'; }
  else if (bits < 60) { score = 2; label = 'fair'; }
  else if (bits < 80) { score = 3; label = 'strong'; }
  else { score = 4; label = 'excellent'; }

  return { bits: Math.round(bits), score, label, crackTime };
}
