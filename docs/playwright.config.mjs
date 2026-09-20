import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/browser',
  timeout: 30_000,
  use: {
    baseURL: `http://127.0.0.1:3210${process.env.DOCS_TEST_BASE_PATH || '/pgroles/pr-preview/pr-236'}/`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node tests/browser/static-server.mjs',
    url: `http://127.0.0.1:3210${process.env.DOCS_TEST_BASE_PATH || '/pgroles/pr-preview/pr-236'}/docs/explorer/`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
})
