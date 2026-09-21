import { expect, test } from '@playwright/test'

const basePath = process.env.DOCS_TEST_BASE_PATH ?? '/pgroles/pr-preview/pr-236'

async function search(page, query) {
  await page
    .getByRole('searchbox', { name: 'Search docs and courses' })
    .fill(query)
  await expect(page.getByRole('dialog').getByRole('status')).toHaveText(
    /\d+ results/
  )
  return page.getByRole('list', { name: 'Search results' }).getByRole('link')
}

async function resultPaths(links) {
  return links.evaluateAll((elements) =>
    elements.map((element) => new URL(element.href).pathname)
  )
}

for (const [query, expected] of [
  ['exclusive', ['manifest-reference', 'memberships']],
  ['approval pending', ['operator-troubleshooting', 'operator-plan-approval']],
  ['review-out', ['recorded-reviews', 'cli']],
  ['RLS', ['postgresql-row-security', 'limitations']],
  ['permission denied', ['executor-privileges', 'operator-troubleshooting']],
]) {
  test(`finds the relevant documentation for ${query}`, async ({ page }) => {
    await page.goto('docs/quick-start/')
    await page
      .getByRole('button', { name: 'Search documentation', exact: true })
      .click()
    const links = await search(page, query)
    const paths = await resultPaths(links)
    if (query === 'exclusive' || query === 'approval pending') {
      expect(paths.slice(0, 3)).toContain(`${basePath}/docs/${expected[0]}/`)
    } else {
      expect(paths[0]).toBe(`${basePath}/docs/${expected[0]}/`)
    }
    expect(paths.slice(0, query === 'RLS' ? 5 : 3)).toContain(
      `${basePath}/docs/${expected[1]}/`
    )
    if (query === 'exclusive')
      await expect(
        links.filter({ hasText: 'Manifest reference' })
      ).toHaveAttribute('href', /#exclusive$/)
    if (query === 'RLS') {
      const results = page.getByRole('list', { name: 'Search results' })
      await expect(results.getByRole('listitem').first()).toContainText(
        'Course · Learn PostgreSQL'
      )
      await expect(
        results
          .getByRole('listitem')
          .filter({ has: page.getByRole('link', { name: /Limitations/ }) })
      ).toContainText('Reference · Docs')
    }
    if (query === 'review-out') {
      expect(await resultPaths(await search(page, '--review-out'))).toEqual(
        paths
      )
    }
  })
}

test('search is global from a course and filters are explicit', async ({
  page,
}) => {
  await page.goto('docs/quick-start/')
  await page
    .getByRole('button', { name: 'Search documentation', exact: true })
    .click()
  const productResults = await resultPaths(await search(page, 'exclusive'))
  await page.keyboard.press('Escape')
  await page.goto('docs/postgresql-row-security/')
  await page
    .getByRole('button', { name: 'Search documentation', exact: true })
    .click()
  expect(await resultPaths(await search(page, 'exclusive'))).toEqual(
    productResults
  )
  await page
    .getByLabel('Content type', { exact: true })
    .selectOption('Reference')
  const results = page
    .getByRole('list', { name: 'Search results' })
    .getByRole('listitem')
  await expect(page.getByRole('dialog').getByRole('status')).toHaveText(
    /\d+ results/
  )
  for (const item of await results.all())
    await expect(item).toContainText('Reference · Docs')
  await page
    .getByLabel('Destination', { exact: true })
    .selectOption('Learn PostgreSQL')
  await expect(page.getByRole('dialog').getByRole('status')).toContainText(
    'No results'
  )
  await page.getByLabel('Content type', { exact: true }).selectOption('')
  await search(page, 'RLS')
  for (const item of await results.all())
    await expect(item).toContainText('Course · Learn PostgreSQL')
})

test('keyboard search works at 320px and follows an anchored preview-safe result', async ({
  page,
}) => {
  await page.setViewportSize({ width: 320, height: 820 })
  await page.goto('docs/quick-start/')
  const trigger = page.getByRole('button', {
    name: 'Search documentation',
    exact: true,
  })
  await trigger.focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('searchbox')).toBeFocused()
  const links = await search(page, 'exclusive')
  const dialog = page.getByRole('dialog')
  expect(
    await dialog.evaluate(
      (element) => element.scrollWidth - element.clientWidth
    )
  ).toBeLessThanOrEqual(1)
  await page.keyboard.press('ArrowDown')
  await expect(links.first()).toBeFocused()
  await page.keyboard.press('ArrowDown')
  await expect(links.nth(1)).toBeFocused()
  await page.keyboard.press('ArrowUp')
  await expect(links.first()).toBeFocused()
  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect(trigger).toBeFocused()
  await page.keyboard.press('Control+k')
  await search(page, 'exclusive')
  await links.filter({ hasText: 'Manifest reference' }).focus()
  await page.keyboard.press('Enter')
  await expect(page).toHaveURL(
    `${
      page.url().split(basePath + '/docs/')[0]
    }${basePath}/docs/manifest-reference/#exclusive`
  )
  await expect(page.locator('#exclusive')).toBeInViewport()
  await expect(dialog).toBeHidden()
})

test('handles empty results, clearing, pagination, and rapid query changes', async ({
  page,
}) => {
  await page.goto('docs/quick-start/')
  await page
    .getByRole('button', { name: 'Search documentation', exact: true })
    .click()
  const input = page.getByRole('searchbox')
  await input.fill('zzzzunfindable')
  await expect(page.getByRole('dialog').getByRole('status')).toContainText(
    'No results'
  )
  await input.fill('')
  await expect(page.getByRole('dialog').getByRole('status')).toContainText(
    'Search across'
  )
  await search(page, 'roles')
  const items = page
    .getByRole('list', { name: 'Search results' })
    .getByRole('listitem')
  await expect(items).toHaveCount(10)
  await page.getByRole('button', { name: 'Show more results' }).click()
  await expect(items).toHaveCount(20)
  await input.fill('permission denied')
  await input.fill('review-out')
  await expect(items.first()).toContainText('Recorded reviews')
})

for (const failedAsset of [
  '**/pagefind/pagefind.js*',
  '**/pagefind/fragment/*',
]) {
  test(`retries successfully after failing to load ${failedAsset}`, async ({
    page,
  }) => {
    await page.route(failedAsset, (route) => route.abort())
    await page.goto('docs/quick-start/')
    await page
      .getByRole('button', { name: 'Search documentation', exact: true })
      .click()
    await page.getByRole('searchbox').fill('exclusive')
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText(
      'Search could not load'
    )
    await page.unroute(failedAsset)
    await page.getByRole('button', { name: 'Retry search' }).click()
    await expect(page.getByRole('dialog').getByRole('status')).toHaveText(
      /\d+ results/
    )
  })
}

test('index omits sidebar, contents disclosure, build footer, and interactive lab controls', async ({
  page,
}) => {
  await page.goto('docs/quick-start/')
  const resultCounts = await page.evaluate(async (prefix) => {
    const pagefind = await import(`${prefix}/pagefind/pagefind.js`)
    const counts = {}
    for (const query of [
      '"On this page"',
      '"Development docs"',
      '"Run the report the way the application does"',
    ]) {
      counts[query] = (await pagefind.search(query)).results.length
    }
    return counts
  }, basePath)
  expect(Object.values(resultCounts)).toEqual([1, 0, 0])
})
