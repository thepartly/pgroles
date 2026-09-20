import { expect, test } from '@playwright/test'

test('initializes the real WASM analyzer and rejects malformed YAML', async ({ page }) => {
  const wasmResponses = []
  page.on('request', (request) => {
    if (request.url().includes('/wasm/')) wasmResponses.push({ url: request.url(), status: null })
  })
  page.on('response', (response) => {
    const item = wasmResponses.find((request) => request.url === response.url())
    if (item) item.status = response.status()
  })
  await page.goto('docs/explorer/')
  expect(wasmResponses).toEqual([])
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
  expect(wasmResponses.some(({ url, status }) => url.endsWith('/pgroles_wasm.js') && status === 200)).toBe(true)
  expect(wasmResponses.some(({ url, status }) => url.endsWith('/pgroles_wasm_bg.wasm') && status === 200)).toBe(true)
  await expect(page.getByText('Illustrative plan fingerprint')).toBeVisible()
  await expect(page.getByText(/not an approval token/i)).toBeVisible()

  await page.getByLabel('Desired YAML').fill('roles: [')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.locator('article').getByRole('alert')).toContainText('Analysis failed')
})

test('rejects secret-bearing snapshots at the WASM boundary', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.locator('input[type="file"]').setInputFiles({
    name: 'unsafe.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({ roles: { application: { password: 'must-not-enter-browser-analysis' } } })),
  })
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.locator('article').getByRole('alert')).toContainText('unknown field `password`')
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

test('captures desktop and mobile explorer layouts for visual review', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await page.getByRole('button', { name: 'Resulting role graph' }).click()
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: '/tmp/pgroles-explorer-desktop.png', fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await page.evaluate(() => window.scrollTo(0, 0))
  await page.screenshot({ path: '/tmp/pgroles-explorer-390.png', fullPage: true })
})

for (const width of [360, 390, 768]) {
  test(`keeps the phase timeline usable at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 820 })
    await page.goto('docs/explorer/')
    await page.getByRole('button', { name: 'Analyze plan' }).click()
    await expect(page.getByText('Execution phases')).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(1)
  })
}
