import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/browser',
  timeout: 30_000,
  use: {
    baseURL: 'http://127.0.0.1:3210/pgroles',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'DOCS_BASE_PATH=/pgroles npm run dev -- --hostname 127.0.0.1 --port 3210',
    url: 'http://127.0.0.1:3210/pgroles/docs/explorer/',
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
})
