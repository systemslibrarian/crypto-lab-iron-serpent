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
    baseURL: 'http://localhost:4703/crypto-lab-iron-serpent/',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'mobile', use: { ...devices['iPhone 13'] } },
  ],
  webServer: {
    // Build first. `vite preview` serves whatever is already sitting in
    // dist/, so without this the suite tests the last bundle that built:
    // a failing build leaves the previous one in place and the gate passes
    // green against source that no longer compiles, and a mutation check is
    // meaningless because the mutation never reaches the served bundle.
    //
    // Pin the port explicitly. The bare `npm run preview` relied on vite's
    // fleet-shared default, and with reuseExistingServer that lets the suite
    // silently attach to a sibling lab's preview and test the wrong app.
    command: 'npm run build && npm run preview -- --port 4703 --strictPort',
    url: 'http://localhost:4703/crypto-lab-iron-serpent/',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
