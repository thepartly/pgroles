import { defineConfig } from '@playwright/test'

const basePath = process.env.DOCS_TEST_BASE_PATH ?? '/pgroles/pr-preview/pr-236'

export default defineConfig({
  testDir: './tests/browser',
  timeout: 30_000,
  // A stray test.only must not silently narrow the CI suite.
  forbidOnly: !!process.env.CI,
  // CI uploads test-results/ and playwright-report/ when the job fails.
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:3210${basePath}/`,
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'node tests/browser/static-server.mjs',
    url: `http://127.0.0.1:3210${basePath}/docs/explorer/`,
    reuseExistingServer: false,
    timeout: 120_000,
  },
})
