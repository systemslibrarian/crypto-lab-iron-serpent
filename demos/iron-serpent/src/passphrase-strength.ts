/**
 * Guidance for a typed passphrase, not a guessability measurement.
 *
 * Length and character classes do not establish an independent, uniform
 * generation process. Neither a numeric entropy estimate nor a crack-time
 * prediction is justified by the input alone. See NIST SP 800-63B-4 Appendix A.
 */
export interface StrengthEstimate {
  characterCount: number;
  /** Explicitly unmeasured, even for strings that look random. */
  bits: null;
  score: null;
  crackTime: null;
  label: 'empty' | 'well-known' | 'not estimated';
  explanation: string;
  warning?: string;
}

/** A few public examples, not a complete breached-password blocklist. */
const WELL_KNOWN = new Set([
  'password', 'password1', 'passw0rd', '123456', '12345678', '123456789',
  'qwerty', 'letmein', 'iloveyou', 'admin', 'welcome', 'monkey', 'dragon',
  'trustno1', '111111', 'abc123', 'hunter2', 'sunshine', 'princess',
  'correct horse battery staple',
]);

const EXPLANATION = 'Typing a value does not establish independent, uniform random character or word selection. '
  + 'Repetitions, sequences and familiar phrases can be guessed early. '
  + 'Guessability and offline crack time are not measured here; Argon2id adds cost per guess but does not create password entropy.';

export function estimateStrength(pass: string): StrengthEstimate {
  // This comparison only selects a warning. Encryption still uses the exact
  // original UTF-8 input; no trimming, case folding or normalization is applied.
  const known = WELL_KNOWN.has(pass.toLowerCase().trim());
  return {
    characterCount: Array.from(pass).length,
    bits: null,
    score: null,
    crackTime: null,
    label: pass.length === 0 ? 'empty' : known ? 'well-known' : 'not estimated',
    explanation: EXPLANATION,
    ...(known ? {
      warning: 'Matches this demo’s small example list of familiar passphrases. Avoid public examples; this is not a comprehensive breached-password check.',
    } : {}),
  };
}
