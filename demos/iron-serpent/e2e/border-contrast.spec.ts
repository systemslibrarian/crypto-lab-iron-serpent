import { expect, test, type Page } from '@playwright/test';

function luminance(rgb: number[]): number {
  const linear = rgb.map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrast(a: number[], b: number[]): number {
  const values = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (values[0] + 0.05) / (values[1] + 0.05);
}

async function fieldContrast(page: Page): Promise<number> {
  const colors = await page.locator('#enc-pass').evaluate((element) => {
    const style = getComputedStyle(element);
    const parse = (value: string) => value.match(/[\d.]+/g)!.slice(0, 3).map(Number);
    return { border: parse(style.borderTopColor), background: parse(style.backgroundColor) };
  });
  return contrast(colors.border, colors.background);
}

for (const theme of ['dark'] as const) {
  test(`load-bearing field boundary clears 3:1 in ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    await page.evaluate((value) => document.documentElement.setAttribute('data-theme', value), theme);
    expect(await fieldContrast(page)).toBeGreaterThanOrEqual(3);
  });
}
