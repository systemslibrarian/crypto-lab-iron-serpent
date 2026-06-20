/**
 * Automated accessibility checks (axe-core) for the static markup and the
 * dynamically-rendered panels.
 *
 * Note: jsdom does not perform layout, so the color-contrast rule cannot run
 * here — contrast is verified manually / via Lighthouse in a real browser.
 * This suite catches structural regressions: missing labels, bad ARIA roles,
 * duplicate IDs, buttons without accessible names, etc.
 *
 * @vitest-environment jsdom
 */
import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import axe from 'axe-core';
import { initSerpent } from '../serpent';
import { renderAvalanche } from '../avalanche';

const AXE_OPTIONS: axe.RunOptions = {
  // jsdom has no layout engine, so contrast cannot be measured here.
  rules: { 'color-contrast': { enabled: false } },
};

function bodyMarkup(): string {
  // vitest runs with cwd at the package root, where index.html lives.
  const html = readFileSync(resolve(process.cwd(), 'index.html'), 'utf-8');
  const match = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  if (!match) throw new Error('Could not find <body> in index.html');
  // Strip scripts — we only audit the static accessibility tree.
  return match[1].replace(/<script[\s\S]*?<\/script>/gi, '');
}

function formatViolations(violations: axe.Result[]): string {
  return violations
    .map((v) => `${v.id} (${v.impact}): ${v.help}\n  ${v.nodes.map((n) => n.html).join('\n  ')}`)
    .join('\n');
}

describe('Accessibility (axe-core)', () => {
  it('static markup has no detectable violations', async () => {
    document.body.innerHTML = bodyMarkup();
    const results = await axe.run(document.body, AXE_OPTIONS);
    expect(formatViolations(results.violations)).toBe('');
  });

  it('rendered avalanche panel has no detectable violations', async () => {
    await initSerpent();
    document.body.innerHTML = '<main></main>';
    renderAvalanche(document.querySelector('main')!);
    const results = await axe.run(document.querySelector('main')!, AXE_OPTIONS);
    expect(formatViolations(results.violations)).toBe('');
  });
});
