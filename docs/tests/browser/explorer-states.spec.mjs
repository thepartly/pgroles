import { expect, test } from '@playwright/test'

const basePath = (process.env.DOCS_TEST_BASE_PATH ?? '/pgroles/pr-preview/pr-236').replace(/\/$/, '')
const explorerUrl = `${basePath}/docs/explorer/`

async function analyze(page) {
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
}

test('uses snapshot superuser status for existing executors and manual status only for absent roles', async ({ page }) => {
  await page.goto(explorerUrl)
  const checkbox = page.getByRole('checkbox', { name: /Executor is a superuser/ })
  await expect(checkbox).toBeEnabled()
  await checkbox.check()

  await page.getByLabel('Executor role').fill('alice')
  await expect(checkbox).toBeDisabled()
  await expect(checkbox).not.toBeChecked()
  await expect(page.getByText('From snapshot', { exact: true })).toBeVisible()
  await analyze(page)
  await expect(page.locator('[data-severity]').filter({ hasText: 'ADMIN OPTION' }).first()).toBeVisible()

  await page.getByLabel('Executor role').fill('platform_admin')
  await expect(checkbox).toBeEnabled()
  await expect(checkbox).toBeChecked()
  await expect(page.getByText('From snapshot', { exact: true })).toBeHidden()
  await analyze(page)
  await expect(page.locator('[data-severity]').filter({ hasText: 'ADMIN OPTION' })).toHaveCount(0)
})

test('shows imported snapshot superuser status despite a conflicting executor fallback', async ({ page }) => {
  await page.goto(explorerUrl)
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'superuser.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      current: { roles: { existing_admin: { superuser: true } } },
      executor: { role: 'existing_admin', superuser: false },
    })),
  })
  const checkbox = page.getByRole('checkbox', { name: /Executor is a superuser/ })
  await expect(checkbox).toBeDisabled()
  await expect(checkbox).toBeChecked()
  await expect(page.getByText('From snapshot', { exact: true })).toBeVisible()

  await page.getByLabel('Executor role').fill('absent_admin')
  await expect(checkbox).toBeEnabled()
  await expect(checkbox).not.toBeChecked()
})

test('renders unavailable-grantor errors with severity and a visible error count', async ({ page }) => {
  await page.goto(explorerUrl)
  await page.getByLabel('Reconciliation mode').selectOption('authoritative')
  await page.getByLabel('Desired YAML').fill('roles:\n  - name: deployer\n  - name: reader\n')
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'grantor-loss.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      schema_version: 'pgroles.explorer.v1',
      current: {
        roles: { deployer: {}, reader: {} },
        grants: [{ role: 'reader', object_type: 'table', schema: 'app', name: 'orders', privileges: ['SELECT'], grantors: { owner: ['SELECT'] } }],
      },
      executor: { role: 'deployer', superuser: false },
    })),
  })
  await analyze(page)
  await expect(page.locator('[data-severity="error"]')).toContainText(/owner.*unavailable/i)
  await expect(page.getByText(/1 error/)).toBeVisible()
})

test('hides an old plan before a failed snapshot import is read', async ({ page }) => {
  await page.goto(explorerUrl)
  await analyze(page)
  await page.getByRole('button', { name: 'Resulting role graph' }).click()
  await page.locator('svg[aria-label="Resulting role and privilege graph"] g[role="button"]').first().click()
  await expect(page.getByRole('dialog')).toBeVisible()
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'broken.json',
    mimeType: 'application/json',
    buffer: Buffer.from('{'),
  })
  await expect(page.locator('article').getByRole('alert')).toContainText('Could not read snapshot')
  await expect(page.getByText('Execution phases')).toBeHidden()
  await expect(page.getByRole('dialog')).toBeHidden()
})

test('does not publish an analysis made stale while WASM is loading', async ({ page }) => {
  let releaseModule
  const moduleRequested = new Promise((resolve) => {
    page.route((url) => url.pathname.endsWith('/wasm/pgroles_wasm.js'), async (route) => {
      await new Promise((release) => { releaseModule = release; resolve() })
      await route.continue()
    })
  })
  await page.goto(explorerUrl)
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  // The analysis is now waiting on the held engine download.
  await moduleRequested
  await page.getByLabel('Executor role').fill('changed_while_loading')
  // Validation waits on the same engine promise and resumes after the stale
  // analysis in the same microtask drain, so once its result renders the stale
  // analysis has already had its chance to publish.
  await page.getByRole('button', { name: 'Validate policy' }).click()
  releaseModule()
  await expect(page.getByRole('region', { name: 'Policy authoring' })).toContainText('Policy is valid.')
  await expect(page.getByText('Execution phases')).toBeHidden()
  await expect(page.getByRole('button', { name: 'Analyze plan' })).toBeEnabled()

  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
})

for (const [asset, pathSuffix] of [['JavaScript glue', '/wasm/pgroles_wasm.js'], ['WASM binary', '/wasm/pgroles_wasm_bg.wasm']]) {
  test(`reports a failed ${asset} download and succeeds when retried`, async ({ page }) => {
    let blocked = true
    const requests = []
    await page.route((url) => url.pathname.endsWith(pathSuffix), (route) => {
      requests.push(route.request().url())
      return blocked ? route.fulfill({ status: 500, contentType: 'text/plain', body: 'unavailable' }) : route.continue()
    })
    await page.goto(explorerUrl)
    await page.getByRole('button', { name: 'Analyze plan' }).click()
    const alert = page.locator('article').getByRole('alert')
    await expect(alert).toHaveAttribute('data-error-kind', 'load')
    await expect(alert).toContainText('Analyzer unavailable')
    await expect(alert).toContainText('Could not load the WASM analyzer')
    await expect(alert).not.toContainText('Analysis failed')
    await expect(page.getByRole('button', { name: 'Analyze plan' })).toBeEnabled()

    blocked = false
    await page.getByRole('button', { name: 'Analyze plan' }).click()
    await expect(page.getByText('Execution phases')).toBeVisible()
    await expect(alert).toBeHidden()
    expect(requests).toHaveLength(2)
  })
}

test('uses compact mobile adjacency and bounds the optional graph for a larger plan', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  await page.goto(explorerUrl)
  const roles = Array.from({ length: 80 }, (_, index) => `  - name: role_${index}`).join('\n')
  await page.getByLabel('Desired YAML').fill(`roles:\n${roles}\n`)
  await page.getByLabel('Reconciliation mode').selectOption('authoritative')
  await analyze(page)
  await expect(page.getByRole('heading', { name: 'Role index' })).toBeVisible()
  await expect(page.getByRole('img', { name: 'Resulting role and privilege graph' })).toBeHidden()
  await page.getByRole('button', { name: 'Resulting role graph' }).click()
  const graph = page.getByRole('img', { name: 'Resulting role and privilege graph' })
  await expect(graph).toBeVisible()
  expect(Number(await graph.getAttribute('width'))).toBeLessThanOrEqual(1080)
  expect(Number(await graph.getAttribute('height'))).toBeLessThanOrEqual(720)
  expect(Number(await graph.getAttribute('data-node-count'))).toBeLessThanOrEqual(48)
  await expect(page.getByText(/Showing 48 of 80 nodes/)).toBeVisible()
})

test('reports the core snapshot role limit', async ({ page }) => {
  await page.goto(explorerUrl)
  const roles = Object.fromEntries(Array.from({ length: 1025 }, (_, index) => [`role_${index}`, {}]))
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'too-many-roles.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ roles })),
  })
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.locator('article').getByRole('alert')).toContainText(/roles.*1025.*1024/i)
})
