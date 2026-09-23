import { expect, test } from '@playwright/test'

import { expectNoHorizontalOverflow, expectWithinViewport, touchProfiles } from './touch-profiles.mjs'

async function analyzeByTouch(page) {
  await page.goto('docs/explorer/')
  await page.getByRole('button', { name: 'Analyze plan' }).tap()
  await expect(page.getByText('Execution phases')).toBeVisible()
}

async function expectRoleSheet(page) {
  const sheet = page.getByRole('dialog')
  await expect(sheet).toBeVisible()
  await expect(sheet.getByRole('heading')).toBeInViewport()
  await expect(sheet.getByText('Login', { exact: true })).toBeInViewport()
  await expect(sheet.getByText('Connections', { exact: true })).toBeInViewport()
  const close = sheet.getByRole('button', { name: 'Close role details' })
  await expect(close).toBeInViewport()
  await expectWithinViewport(page, sheet)
  await expectNoHorizontalOverflow(page)
  await close.tap()
  await expect(sheet).toBeHidden()
}

for (const profile of touchProfiles) {
  test.describe(`on ${profile.name} with touch`, () => {
    test.use(profile.use)

    test('keeps the phase timeline usable', async ({ page }) => {
      await analyzeByTouch(page)
      expect(await page.evaluate(() => navigator.maxTouchPoints)).toBeGreaterThan(0)
      await expect(page.getByRole('heading', { name: 'Execution phases' })).toBeVisible()
      await expectNoHorizontalOverflow(page)
    })

    test('opens the role-detail sheet from the role index', async ({ page }) => {
      await analyzeByTouch(page)
      const roleIndex = page.getByRole('heading', { name: 'Role index' }).locator('..')
      const firstRole = roleIndex.getByRole('button').first()
      const roleName = (await firstRole.locator('span').first().textContent()).trim()
      await firstRole.tap()
      await expect(page.getByRole('dialog').getByRole('heading', { name: roleName })).toBeVisible()
      await expectRoleSheet(page)
    })

    test('scrolls the graph inside its frame and opens a node sheet', async ({ page }) => {
      await analyzeByTouch(page)
      await page.getByRole('button', { name: 'Resulting role graph' }).tap()
      const graph = page.getByRole('img', { name: 'Resulting role and privilege graph' })
      await expect(graph).toBeVisible()
      await expectNoHorizontalOverflow(page)
      await page.getByRole('button', { name: 'Zoom graph in' }).tap()
      await expect(page.getByText('120%')).toBeVisible()
      await expectNoHorizontalOverflow(page)
      const frame = graph.locator('..')
      const { scrollWidth, clientWidth } = await frame.evaluate((element) => ({ scrollWidth: element.scrollWidth, clientWidth: element.clientWidth }))
      expect(scrollWidth).toBeGreaterThanOrEqual(clientWidth)
      await graph.locator('g[role="button"]').last().tap()
      await expectRoleSheet(page)
    })
  })
}
