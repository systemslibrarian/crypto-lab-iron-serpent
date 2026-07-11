import { defineConfig, devices } from '@playwright/test';

/**
 * Real-browser E2E: runs against the production build served by `vite preview`,
 * so the WASM loading, worker KDF, and base-path handling are all exercised
 * exactly as deployed to GitHub Pages.
 */
export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://localhost:4173/crypto-lab-iron-serpent/',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['iPhone 13'] } },
  ],
  webServer: {
    command: 'npm run preview',
    url: 'http://localhost:4173/crypto-lab-iron-serpent/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
