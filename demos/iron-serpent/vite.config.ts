/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-iron-serpent/',
  test: {
    // e2e/ belongs to Playwright, not vitest.
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
  optimizeDeps: {
    exclude: ['argon2-browser'],
  },
  build: {
    rollupOptions: {
      external: [],
    },
  },
});
