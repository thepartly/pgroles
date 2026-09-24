import { expect, test } from '@playwright/test'

import { expectNoHorizontalOverflow } from './touch-profiles.mjs'

const basePath = (process.env.DOCS_TEST_BASE_PATH ?? '/pgroles/pr-preview/pr-236').replace(/\/$/, '')

test('initializes the real WASM analyzer from versioned assets and rejects malformed YAML', async ({ page }) => {
  const wasmResponses = []
  page.on('request', (request) => {
    if (request.url().includes('/wasm/')) wasmResponses.push({ url: new URL(request.url()), status: null })
  })
  page.on('response', (response) => {
    const item = wasmResponses.find((request) => request.url.href === response.url())
    if (item) item.status = response.status()
  })
  await page.goto('docs/explorer/')
  expect(wasmResponses).toEqual([])
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
  const glue = wasmResponses.find(({ url }) => url.pathname === `${basePath}/wasm/pgroles_wasm.js`)
  const binary = wasmResponses.find(({ url }) => url.pathname === `${basePath}/wasm/pgroles_wasm_bg.wasm`)
  expect(glue?.status).toBe(200)
  expect(binary?.status).toBe(200)
  // Both assets carry the same build id, so a cached glue file can never be
  // paired with a binary from another deploy.
  expect(glue.url.searchParams.get('v')).toMatch(/^[0-9a-z-]+$/)
  expect(binary.url.searchParams.get('v')).toBe(glue.url.searchParams.get('v'))
  await expect(page.getByText('Illustrative plan fingerprint')).toBeVisible()
  await expect(page.getByText(/not an approval token/i)).toBeVisible()

  await page.getByLabel('Desired YAML').fill('roles: [')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  const alert = page.locator('article').getByRole('alert')
  await expect(alert).toContainText('Analysis failed')
  await expect(alert).toHaveAttribute('data-error-kind', 'analysis')
})

test('rejects secret-bearing snapshots at the WASM boundary', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'unsafe.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ roles: { application: { password: 'must-not-enter-browser-analysis' } } })),
  })
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.locator('article').getByRole('alert')).toContainText('unknown field `password`')
})

test('sends the selected PostgreSQL version and shows the echoed analysis context', async ({ page }) => {
  await page.goto('docs/explorer/')
  const version = page.getByLabel('PostgreSQL major version')
  await expect(version).toHaveValue('16')
  expect(await version.locator('option').allTextContents()).toEqual(['PostgreSQL 15', 'PostgreSQL 16 (default)', 'PostgreSQL 17', 'PostgreSQL 18'])
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  const target = page.getByTestId('analysis-target')
  await expect(target).toContainText('PostgreSQL 16')
  await expect(target).toContainText('Complete authority graph')

  await version.selectOption('15')
  await expect(page.getByText('Execution phases')).toBeHidden()
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(target).toContainText('PostgreSQL 15')
})

test('honours the PostgreSQL version and completeness carried by an imported envelope', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'pg14-partial.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 'pgroles.explorer.v1',
      pg_major_version: 14,
      authority_graph_complete: false,
      current: { roles: { deployer: {} } },
      executor: { role: 'deployer', createrole: 'allowed' },
    })),
  })
  const version = page.getByLabel('PostgreSQL major version')
  await expect(version).toHaveValue('14')
  await expect(page.getByText('From snapshot', { exact: true }).first()).toBeVisible()
  await expect(page.getByLabel('Executor CREATEROLE')).toHaveValue('allowed')
  await expect(page.getByText(/Authority graph: partial/)).toBeVisible()
  await page.getByLabel('Desired YAML').fill('roles:\n  - name: deployer\n  - name: reader\n')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  const target = page.getByTestId('analysis-target')
  await expect(target).toContainText('PostgreSQL 14')
  await expect(target).toContainText('Partial authority graph')

  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'bare.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify({ roles: { deployer: {} } })),
  })
  await expect(version).toHaveValue('14')
  await expect(page.getByText(/Authority graph: complete/)).toBeVisible()
})

test('titles import errors separately from analysis errors', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'bad-version.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ current: {}, pg_major_version: 'sixteen' })),
  })
  const alert = page.locator('article').getByRole('alert')
  await expect(alert).toHaveAttribute('data-error-kind', 'import')
  await expect(alert).toContainText('Import failed')
  await expect(alert).toContainText('pg_major_version must be an integer')
  await expect(alert).not.toContainText('Analysis failed')
})

test('graph controls, role sheet, Escape, and stale-result clearing work', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
  await page.getByRole('button', { name: 'Resulting role graph' }).click()
  await expect(page.getByRole('img', { name: 'Resulting role and privilege graph' })).toBeVisible()
  await page.getByRole('button', { name: 'Zoom graph in' }).click()
  await expect(page.getByText('120%')).toBeVisible()
  const graphNode = page.locator('svg[aria-label="Resulting role and privilege graph"] g[role="button"]').first()
  await graphNode.focus()
  await graphNode.press('Enter')
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toBeHidden()
  await page.getByLabel('Executor role').fill('another_executor')
  await expect(page.getByText('Execution phases')).toBeHidden()
})

// Screenshots are attached to the HTML report (and kept under test-results/)
// for visual review; the assertions carry the pass/fail signal.
test('captures desktop and mobile explorer layouts for visual review', async ({ page }, testInfo) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await page.getByRole('button', { name: 'Resulting role graph' }).click()
  await expect(page.getByRole('img', { name: 'Resulting role and privilege graph' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.evaluate(() => window.scrollTo(0, 0))
  const desktop = testInfo.outputPath('explorer-desktop.png')
  await page.screenshot({ path: desktop, fullPage: true })
  await testInfo.attach('explorer-desktop', { path: desktop, contentType: 'image/png' })

  await page.setViewportSize({ width: 390, height: 844 })
  await expect(page.getByRole('img', { name: 'Resulting role and privilege graph' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.evaluate(() => window.scrollTo(0, 0))
  const mobile = testInfo.outputPath('explorer-390.png')
  await page.screenshot({ path: mobile, fullPage: true })
  await testInfo.attach('explorer-390', { path: mobile, contentType: 'image/png' })
})
