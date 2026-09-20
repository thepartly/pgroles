import { expect, test } from '@playwright/test'

test('recognizes exclusive in the membership guide without promising policy validation', async ({ page }) => {
  await page.goto('docs/memberships/')
  const exclusive = page.locator('.pgroles-field').filter({ hasText: /^exclusive$/ })
  await expect(exclusive).toBeVisible()
  await expect(exclusive).toHaveAttribute('title', /Additive mode skips/)
  await expect(page.locator('.pgroles-unrecognized')).toHaveCount(0)
  await expect(page.getByText('Policy field guide', { exact: true }).first()).toBeVisible()
})

test('labels incremental policy and serves the complete ownership policy under the preview path', async ({ page }) => {
  await page.goto('docs/postgresql-ownership/')
  await expect(page.getByText('Policy fragment', { exact: true })).toBeVisible()
  const link = page.getByRole('link', { name: 'Download the complete policy after this chapter' })
  const href = await link.getAttribute('href')
  expect(href).toContain('/examples/acme-policy/chapter-4.yaml')
  const response = await page.request.get(href)
  expect(response.status()).toBe(200)
  const policy = await response.text()
  expect(policy).toContain('name: bob')
  expect(policy).toContain('name: reporting_app')
  expect(policy).toContain('privileges: [SELECT]')
  expect(policy).toContain('role: app_owner')
})

for (const width of [360, 390, 768]) {
  test(`explains per-run reset and verifies the granted access in one run at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 820 })
    await page.goto('docs/postgresql-access-model/')
    await expect(page.getByText('Every Run starts from this step’s prepared database. Changes from previous runs are discarded.', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: 'Open the table gate — and get the rows', exact: true }).click()
    await page.getByRole('button', { name: 'Run SQL', exact: true }).click()
    await expect(page.getByText('What changed', { exact: true })).toBeVisible()
    await expect(page.getByRole('region', { name: 'Execution identity' })).toContainText(/After SQL.*session_user postgres.*current_user alice/s)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
  })
}
