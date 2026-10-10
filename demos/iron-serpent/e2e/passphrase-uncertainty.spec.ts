import { test, expect } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`typed input never acquires a strength or crack-time promise at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const errors: string[] = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.goto('');
    await expect(page.locator('#init-status')).toHaveText('Serpent-256 engine ready.');
    for (const value of [
      'aaaaaaaaaaaaaaaaaaaa', 'passwordpasswordpassword',
      '12345678901234567890', 'qwertyqwertyqwerty',
      'Password1!Password1!', 'battery horse stapler cloud',
      'K9$mQ2#vX7@pL4!wN8&zR5^tB3*d', '🔐🔐e\u0301',
    ]) {
      await page.locator('#enc-pass').fill(value);
      await expect(page.locator('#pass-strength-text')).toContainText('Strength not estimated');
      await expect(page.locator('#pass-strength-text')).toContainText('independent, uniform random');
      await expect(page.locator('#pass-strength-text')).toContainText('not measured');
      await expect(page.locator('#pass-strength-text')).not.toContainText(value);
      await expect(page.locator('#pass-strength-text')).not.toHaveText(/excellent|to crack|million years|10,000/);
      expect(await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)).toBeLessThanOrEqual(1);
    }
    await expect(page.locator('#pass-strength-text')).toContainText('4 characters');
    await page.locator('#enc-example').click();
    await expect(page.locator('#pass-strength-text')).toContainText('small example list');
    await expect(page.locator('#pass-strength-text')).toContainText('not measured');
    await page.locator('#enc-pass').fill('');
    await expect(page.locator('#pass-strength')).toBeHidden();
    expect(errors).toEqual([]);
  });
}
