import { defineConfig } from '@playwright/test';

// Runs only when QSHIELD_E2E_RPC / QSHIELD_E2E_PROGRAM / QSHIELD_E2E_RELAYER
// point at a validator with the program deployed and a running relayer
// (scripts/cli-e2e.sh). PW_CHROMIUM_PATH selects a preinstalled Chromium.
export default defineConfig({
  testDir: 'e2e',
  testMatch: '*.e2e.ts',
  timeout: 600_000,
  expect: { timeout: 120_000 },
  workers: 1,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    acceptDownloads: true,
    launchOptions: process.env.PW_CHROMIUM_PATH ? { executablePath: process.env.PW_CHROMIUM_PATH } : {},
  },
  webServer: {
    command: 'npm run build && npm run preview -- --host 127.0.0.1',
    url: 'http://127.0.0.1:4173',
    reuseExistingServer: false,
    timeout: 120_000,
  },
});
