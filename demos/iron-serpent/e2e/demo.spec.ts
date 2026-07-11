/**
 * End-to-end tests against the production build in a real browser.
 *
 * These cover what the vitest suite structurally cannot:
 * - the real Argon2id WASM worker and Serpent WASM engine, loaded via the
 *   deployed base path
 * - axe-core WITH the color-contrast rule (jsdom has no layout engine)
 * - layout sanity on desktop and mobile viewports
 */
import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const PASSPHRASE = 'e2e passphrase with adequate length';
const MESSAGE = 'Round trip through the real UI — WASM, worker KDF and all.';

async function waitForEngine(page: Page): Promise<void> {
  await page.goto('');
  await expect(page.locator('#init-status')).toHaveText('Serpent-256 engine ready.', { timeout: 15_000 });
}

test.describe('encrypt / decrypt round trip', () => {
  test('encrypts, sends to decrypt, and authenticates', async ({ page }) => {
    await waitForEngine(page);

    await page.fill('#enc-pass', PASSPHRASE);
    await page.fill('#enc-input', MESSAGE);
    await page.click('#enc-btn');

    // Argon2id (64 MiB, t=3) takes a moment even on fast machines.
    // Note: textareas hold their content in .value, so toHaveValue, not toContainText.
    await expect(page.locator('#enc-output')).toHaveValue(/"version": "iron-serpent-v1"/, { timeout: 30_000 });

    await page.click('#enc-to-dec');
    await expect(page.locator('#dec-input')).toHaveValue(/ciphertext/);
    await page.click('#dec-btn');

    await expect(page.locator('#auth-badge')).toHaveText('✓ Authenticated', { timeout: 30_000 });
    await expect(page.locator('#dec-output')).toHaveValue(MESSAGE);
  });

  test('rejects a tampered payload with a failed-authentication badge', async ({ page }) => {
    await waitForEngine(page);

    await page.fill('#enc-pass', PASSPHRASE);
    await page.fill('#enc-input', MESSAGE);
    await page.click('#enc-btn');
    await expect(page.locator('#enc-output')).toHaveValue(/"version"/, { timeout: 30_000 });

    // Flip one base64 character of the ciphertext, keeping the payload well-formed.
    const tampered = await page.locator('#enc-output').inputValue().then((raw) => {
      const payload = JSON.parse(raw);
      const ct: string = payload.ciphertext;
      payload.ciphertext = (ct[0] === 'A' ? 'B' : 'A') + ct.slice(1);
      return JSON.stringify(payload);
    });

    await page.fill('#dec-pass', PASSPHRASE);
    await page.fill('#dec-input', tampered);
    await page.click('#dec-btn');

    await expect(page.locator('#auth-badge')).toHaveText('✗ Authentication Failed', { timeout: 30_000 });
    await expect(page.locator('#dec-output')).toHaveValue('');
  });
});

test.describe('interactive panels', () => {
  test('CTR explorer renders blocks and reacts to nonce changes', async ({ page }) => {
    await waitForEngine(page);

    // Default 24-char message → 2 counter blocks.
    await expect(page.locator('.ctr-block')).toHaveCount(2);
    await expect(page.locator('.ctr-block').first()).toContainText('Counter = nonce');
    await expect(page.locator('.ctr-block').nth(1)).toContainText('Counter = nonce + 1');

    const keystreamBefore = await page.locator('.ctr-block').first().textContent();
    await page.click('#ctr-random');
    const keystreamAfter = await page.locator('.ctr-block').first().textContent();
    expect(keystreamAfter).not.toBe(keystreamBefore);

    // Longer message grows the block count live.
    await page.fill('#ctr-message', 'x'.repeat(40));
    await expect(page.locator('.ctr-block')).toHaveCount(3);
  });

  test('avalanche panel shows ~50% diffusion', async ({ page }) => {
    await waitForEngine(page);

    await expect(page.locator('.aval-cell')).toHaveCount(128);
    const stat = await page.locator('#aval-stat').textContent();
    const changed = Number(stat?.match(/(\d+) of 128/)?.[1]);
    // SAC: a healthy single-sample result lands well inside 64 ± 25.
    expect(changed).toBeGreaterThan(39);
    expect(changed).toBeLessThan(89);
  });

  test('passphrase strength meter warns on well-known passphrases', async ({ page }) => {
    await waitForEngine(page);

    await page.click('#enc-example');
    await expect(page.locator('#pass-strength-text')).toContainText('cracking wordlist');

    await page.fill('#enc-pass', 'K9$mQ2#vX7@pL4!wN8&zR5^tB3*d');
    await expect(page.locator('#pass-strength-text')).toContainText('excellent');
  });
});

test.describe('layout and accessibility', () => {
  test('no horizontal overflow', async ({ page }) => {
    await waitForEngine(page);
    const overflow = await page.evaluate(
      () => document.documentElement.scrollWidth - document.documentElement.clientWidth
    );
    expect(overflow).toBeLessThanOrEqual(1);
  });

  for (const theme of ['dark', 'light'] as const) {
    test(`axe (including color-contrast) passes in ${theme} theme`, async ({ page }) => {
      await waitForEngine(page);
      await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);

      const results = await new AxeBuilder({ page }).analyze();
      const summary = results.violations
        .map((v) => `${v.id}: ${v.help}\n  ${v.nodes.map((n) => `${n.html}\n    ${n.any[0]?.message ?? ''}`).join('\n  ')}`)
        .join('\n');
      expect(summary).toBe('');
    });
  }

  test('capture full-page screenshot for artifact review', async ({ page }, testInfo) => {
    await waitForEngine(page);
    const shot = await page.screenshot({ fullPage: true });
    await testInfo.attach(`full-page-${testInfo.project.name}`, { body: shot, contentType: 'image/png' });
  });
});
