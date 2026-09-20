import { expect, test } from '@playwright/test'

const rlsUrl = 'docs/postgresql-row-security/'

async function runStep(page, title) {
  if (title) await page.getByRole('button', { name: title, exact: true }).click()
  await page.getByRole('button', { name: 'Run SQL', exact: true }).click()
  await expect(page.getByText('What changed', { exact: true })).toBeVisible()
}

test('shows default deny with actor identity, table SELECT, and active row security', async ({ page }) => {
  await page.goto(rlsUrl)
  await expect(page.getByRole('heading', { name: 'Enable RLS without a policy' })).toBeVisible()
  await runStep(page)

  const identity = page.getByRole('region', { name: 'Execution identity' })
  await expect(identity).toContainText(/Before SQL.*session_user acme_app.*current_user acme_app/s)
  await expect(identity).toContainText(/After SQL.*session_user acme_app.*current_user acme_app/s)
  await expect(identity).toContainText(/Table SELECT.*allowed/s)
  await expect(identity).toContainText(/Row security active.*yes/s)
  await expect(page.getByText('(0 rows)', { exact: true })).toBeVisible()
})

test('shows each tenant only its own rows under the shared policy', async ({ page }) => {
  await page.goto(rlsUrl)

  await runStep(page, 'Query as Acme')
  await expect(page.getByRole('cell', { name: 'Acme', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Globex', exact: true })).toBeHidden()

  await runStep(page, 'Query as Globex')
  await expect(page.getByRole('cell', { name: 'Globex', exact: true })).toBeVisible()
  await expect(page.getByRole('cell', { name: 'Acme', exact: true })).toBeHidden()
})

test('keeps a valid write and rejects a cross-tenant value', async ({ page }) => {
  await page.goto(rlsUrl)
  await runStep(page, 'Separate existing rows from proposed values')

  await expect(page.getByText(/new row violates row-level security policy/i)).toBeVisible()
  await expect(page.getByText('accepted', { exact: true })).toBeVisible()
  await expect(page.getByText('rejected', { exact: true })).toBeVisible()
  const identity = page.getByRole('region', { name: 'Execution identity' })
  await expect(identity).toContainText(/session_user acme_app.*current_user acme_app/s)
})

test('distinguishes owner FORCE behavior and explicit bypass identities', async ({ page }) => {
  await page.goto(rlsUrl)

  await runStep(page, 'Force the owner through RLS')
  await expect(page.getByText('2 rows', { exact: true })).toBeVisible()
  await expect(page.getByText('0 rows', { exact: true })).toBeVisible()
  const ownerIdentity = page.getByRole('region', { name: 'Execution identity' })
  await expect(ownerIdentity).toContainText(/Before SQL.*current_user app_owner/s)
  await expect(ownerIdentity).toContainText(/After SQL.*current_user app_owner/s)

  await runStep(page, 'Prove the remaining bypasses')
  const bypassIdentity = page.getByRole('region', { name: 'Execution identity' })
  await expect(bypassIdentity).toContainText(/Before SQL.*session_user postgres.*current_user postgres/s)
  await expect(bypassIdentity).toContainText(/After SQL.*session_user rls_bypass.*current_user rls_bypass/s)
  await expect(bypassIdentity).toContainText(/Row security active.*no/s)
})

for (const width of [360, 390, 768]) {
  test(`keeps the live RLS lesson usable at ${width}px`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 820 })
    await page.goto(rlsUrl)
    await runStep(page)
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(1)
    await expect(page.getByRole('region', { name: 'Execution identity' })).toBeVisible()
    await page.screenshot({ path: testInfo.outputPath(`rls-${width}.png`), fullPage: true })
  })
}
