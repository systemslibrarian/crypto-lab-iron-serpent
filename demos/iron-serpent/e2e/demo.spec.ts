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

/**
 * The advanced exhibits (round visualizer, security margin, avalanche, CTR,
 * benchmark) start locked behind the guided tour. Do the encrypt→decrypt round
 * trip to unlock them, then reveal, so panel-level tests can reach the content.
 */
async function unlockExhibits(page: Page): Promise<void> {
  await page.fill('#enc-pass', PASSPHRASE);
  await page.fill('#enc-input', MESSAGE);
  await page.click('#enc-btn');
  await expect(page.locator('#enc-output')).toHaveValue(/"version"/, { timeout: 30_000 });
  await page.click('#enc-to-dec');
  await page.click('#dec-btn');
  await expect(page.locator('#auth-badge')).toHaveText('✓ Authenticated', { timeout: 30_000 });
  await page.click('#tour-reveal');
  await expect(page.locator('#advanced-exhibits')).toBeVisible();
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

  test('one-click tamper lab flips a byte and fires the failed badge', async ({ page }) => {
    await waitForEngine(page);

    // Round-trip to a clean authenticated decrypt so the tamper lab appears.
    await page.fill('#enc-pass', PASSPHRASE);
    await page.fill('#enc-input', MESSAGE);
    await page.click('#enc-btn');
    await expect(page.locator('#enc-output')).toHaveValue(/"version"/, { timeout: 30_000 });
    await page.click('#enc-to-dec');
    await page.click('#dec-btn');
    await expect(page.locator('#auth-badge')).toHaveText('✓ Authenticated', { timeout: 30_000 });

    // The tamper lab is now offered.
    await expect(page.locator('#tamper-lab')).toBeVisible();

    // Flip one byte of the ciphertext → HMAC catches it.
    await page.click('#tamper-ct');
    await expect(page.locator('#auth-badge')).toHaveText('✗ Authentication Failed', { timeout: 30_000 });
    await expect(page.locator('#dec-output')).toHaveValue('');

    // Restore → authenticates again and recovers the plaintext.
    await page.click('#tamper-restore');
    await expect(page.locator('#auth-badge')).toHaveText('✓ Authenticated', { timeout: 30_000 });
    await expect(page.locator('#dec-output')).toHaveValue(MESSAGE);

    // Flipping the MAC tag itself also fails authentication.
    await page.click('#tamper-mac');
    await expect(page.locator('#auth-badge')).toHaveText('✗ Authentication Failed', { timeout: 30_000 });
  });
});

test.describe('CTR nonce-reuse demo', () => {
  test('reusing a nonce shows CT1 XOR CT2 equals PT1 XOR PT2', async ({ page }) => {
    await waitForEngine(page);
    await unlockExhibits(page);

    await page.check('#ctr-reuse-on');
    await expect(page.locator('#ctr-reuse-body')).toBeVisible();
    // The panel asserts the keystream cancelled — success wording, not the error wording.
    await expect(page.locator('#ctr-reuse-stat')).toContainText('CT1 ⊕ CT2 = PT1 ⊕ PT2');
    await expect(page.locator('#ctr-reuse-rows')).toContainText('PT1 ⊕ PT2');
  });
});

test.describe('interactive panels', () => {
  test('CTR explorer renders blocks and reacts to nonce changes', async ({ page }) => {
    await waitForEngine(page);
    await unlockExhibits(page);

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
    await unlockExhibits(page);

    await expect(page.locator('.aval-cell')).toHaveCount(128);
    const stat = await page.locator('#aval-stat').textContent();
    const changed = Number(stat?.match(/(\d+) of 128/)?.[1]);
    // SAC: a healthy single-sample result lands well inside 64 ± 25.
    expect(changed).toBeGreaterThan(39);
    expect(changed).toBeLessThan(89);
  });

  test('exhibits are locked until the round trip, then the round visualizer steps 1..32', async ({ page }) => {
    await waitForEngine(page);

    // Advanced exhibits start hidden; the reveal button is disabled.
    await expect(page.locator('#advanced-exhibits')).toBeHidden();
    await expect(page.locator('#tour-reveal')).toBeDisabled();

    await unlockExhibits(page);

    // Round visualizer is now reachable and shows round 1 of 32.
    await expect(page.locator('#rounds-container .sv-counter')).toContainText('Round 1 of 32');
    // Step forward two rounds and confirm the counter advances.
    const next = page.locator('#rounds-container').getByRole('button', { name: /Next round/ });
    await next.click();
    await next.click();
    await expect(page.locator('#rounds-container .sv-counter')).toContainText('Round 3 of 32');

    // Diffusion tracker reports how far one flipped input bit has spread.
    await expect(page.locator('.sv-diffusion')).toContainText('Diffusion after round');
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

  for (const theme of ['dark'] as const) {
    test(`axe (including color-contrast) passes in ${theme} theme`, async ({ page }) => {
      await waitForEngine(page);
      // Reveal the advanced exhibits so their contrast is audited too.
      await unlockExhibits(page);
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
