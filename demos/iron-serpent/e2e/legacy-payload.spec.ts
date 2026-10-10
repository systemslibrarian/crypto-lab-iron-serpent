import {readFileSync} from 'node:fs';
import {test, expect} from '@playwright/test';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/legacy-v1-payload.json', import.meta.url), 'utf8'));

test('decrypts an actual pre-migration iron-serpent-v1 browser payload', async ({page}) => {
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('');
  await expect(page.locator('#init-status')).toHaveText('Serpent-256 engine ready.');
  await page.fill('#dec-pass', fixture.passphrase);
  await page.fill('#dec-input', JSON.stringify(fixture.payload));
  await page.click('#dec-btn');
  await expect(page.locator('#auth-badge')).toHaveText('✓ Authenticated', {timeout: 30_000});
  await expect(page.locator('#dec-output')).toHaveValue(fixture.plaintext);
  expect(errors).toEqual([]);
});

test('rejects a tampered pre-migration payload before returning plaintext', async ({page}) => {
  const payload = {...fixture.payload};
  const cipher = Buffer.from(payload.ciphertext, 'base64');
  cipher[0] ^= 1;
  payload.ciphertext = cipher.toString('base64');
  await page.goto('');
  await expect(page.locator('#init-status')).toHaveText('Serpent-256 engine ready.');
  await page.fill('#dec-pass', fixture.passphrase);
  await page.fill('#dec-input', JSON.stringify(payload));
  await page.click('#dec-btn');
  await expect(page.locator('#auth-badge')).toHaveText('✗ Authentication Failed', {timeout: 30_000});
  await expect(page.locator('#dec-output')).not.toHaveValue(fixture.plaintext);
});
