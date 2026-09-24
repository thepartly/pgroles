import { expect, test } from '@playwright/test'

import { expectNoHorizontalOverflow, touchProfiles } from './touch-profiles.mjs'

test('validates and compiles without usable snapshot or executor facts', async ({ page, request }) => {
  const metadataResponse = await request.get('generated/manifest-metadata.json')
  expect(metadataResponse.ok()).toBe(true)
  expect((await metadataResponse.json()).schema_version).toBe('pgroles.manifest-metadata.v1')
  await page.goto('docs/explorer/')
  await page.getByLabel('Executor role').fill('')
  await page.getByLabel('Sanitized snapshot file').setInputFiles({
    name: 'invalid.json', mimeType: 'application/json', buffer: Buffer.from('{"unexpected":true}'),
  })
  await page.getByLabel('Desired YAML').fill('roles:\n  - name: application\n    login: true\n    password:\n      from_env: NEVER_RESOLVE_THIS\n')
  await page.getByRole('button', { name: 'Validate policy' }).click()
  const authoring = page.getByRole('region', { name: 'Policy authoring' })
  await expect(authoring).toContainText('Policy is valid.')
  await page.getByRole('button', { name: 'Inspect expansion' }).click()
  await expect(authoring.getByRole('heading', { name: 'Compiled policy' })).toBeVisible()
  await expect(authoring.getByRole('list', { name: 'Expanded role names' })).toContainText('application')
  await authoring.getByText('Expanded policy and desired graph').click()
  await expect(authoring.locator('pre')).toContainText('NEVER_RESOLVE_THIS')
  await page.getByLabel('Desired YAML').fill('roles: [')
  await expect(authoring.getByRole('heading', { name: 'Compiled policy' })).toBeHidden()
  await page.getByRole('button', { name: 'Validate policy' }).click()
  await expect(authoring).toContainText('invalid_yaml')
})

test('reports a structural field that is invalid in its semantic context', async ({ page }) => {
  await page.goto('docs/explorer/')
  await page.getByLabel('Desired YAML').fill('roles:\n  - name: ordinary\nmemberships:\n  - role: ordinary\n    exclusive: true\n    members: []\n')
  await page.getByRole('button', { name: 'Inspect expansion' }).click()
  const authoring = page.getByRole('region', { name: 'Policy authoring' })
  await expect(authoring).toContainText('exclusive_membership_on_managed_role')
  await expect(authoring).toContainText('memberships')
  await expect(authoring.getByRole('heading', { name: 'Compiled policy' })).toBeHidden()
})

test.describe('on a 360px touch screen', () => {
  test.use(touchProfiles[0].use)

  test('keeps expanded policy readable', async ({ page }, testInfo) => {
    await page.goto('docs/explorer/')
    await page.getByRole('button', { name: 'Inspect expansion' }).tap()
    const authoring = page.getByRole('region', { name: 'Policy authoring' })
    await authoring.getByText('Expanded policy and desired graph').tap()
    await expect(authoring.locator('pre')).toBeVisible()
    await expectNoHorizontalOverflow(page)
    const screenshot = testInfo.outputPath('policy-authoring-360.png')
    await authoring.screenshot({ path: screenshot })
    await testInfo.attach('policy-authoring-360', { path: screenshot, contentType: 'image/png' })
  })
})

test('reports a failed WASM download as a loading error and recovers on retry', async ({ page }) => {
  let blocked = true
  await page.route((url) => url.pathname.endsWith('/wasm/pgroles_wasm_bg.wasm'), (route) => (blocked ? route.fulfill({ status: 500, body: 'unavailable' }) : route.continue()))
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Validate policy' }).click()
  const authoring = page.getByRole('region', { name: 'Policy authoring' })
  await expect(authoring.getByRole('alert')).toContainText('Could not load policy tools')
  blocked = false
  await page.getByRole('button', { name: 'Validate policy' }).click()
  await expect(authoring).toContainText('Policy is valid.')
  await expect(authoring.getByRole('alert')).toBeHidden()
})

test('discards validation when the policy changes while WASM is loading', async ({ page }) => {
  let releaseModule
  const moduleRequested = new Promise((resolve) => {
    page.route((url) => url.pathname.endsWith('/wasm/pgroles_wasm.js'), async (route) => {
      await new Promise((release) => { releaseModule = release; resolve() })
      await route.continue()
    })
  })
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Validate policy' }).click()
  await moduleRequested
  await page.getByLabel('Desired YAML').fill('roles: [')
  releaseModule()
  await page.getByRole('button', { name: 'Validate policy' }).click()
  const authoring = page.getByRole('region', { name: 'Policy authoring' })
  await expect(authoring).toContainText('invalid_yaml')
  await expect(authoring).not.toContainText('Policy is valid.')
})
