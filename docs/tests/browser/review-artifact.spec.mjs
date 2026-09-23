import { expect, test } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import { touchProfiles } from './touch-profiles.mjs'

const fixturePath = resolve(import.meta.dirname, '../fixtures/recorded-review.json')
const fixtureVersion = JSON.parse(readFileSync(fixturePath, 'utf8')).schema_version

// The explorer opens only the current artifact version; a stale fixture has to
// be regenerated from the CLI rather than silently exercising the rejection path.
test.skip(fixtureVersion !== 'pgroles.review-artifact.v2' && !process.env.CI, `${fixturePath} is ${fixtureVersion}; regenerate it as pgroles.review-artifact.v2`)

async function uploadReview(page, body, name = 'review.json') {
  const buffer = Buffer.isBuffer(body)
    ? body
    : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body))
  await page.getByLabel('Recorded review file').setInputFiles({
    name,
    mimeType: 'application/json',
    buffer,
  })
}

test('opens the CLI-generated recorded review without loading WASM', async ({ page }) => {
  const wasmRequests = []
  page.on('request', (browserRequest) => {
    if (browserRequest.url().includes('/wasm/')) wasmRequests.push(browserRequest.url())
  })
  await page.goto('docs/explorer/')
  await uploadReview(page, await readFile(fixturePath), 'recorded-review.json')

  const review = page.getByRole('region', { name: 'Recorded plan review' })
  await expect(review).toBeVisible()
  await expect(review.getByText('Recorded review', { exact: true })).toBeVisible()
  await expect(review.getByRole('heading', { name: 'Local PostgreSQL review fixture' })).toBeVisible()
  await expect(review.getByText('Recorded changes', { exact: true })).toBeVisible()
  await expect(review.getByText('Create role', { exact: true }).first()).toBeVisible()
  await expect(review.getByText(/Executor authority · postgres/)).toBeVisible()
  const intendedExecutorEvidence = review.getByText(/Executor authority · review_deployer/).locator('..')
  await expect(intendedExecutorEvidence).toContainText('Not run')
  await expect(review.getByText('SQL preview', { exact: true })).toBeVisible()
  await expect(review.getByText(/CREATE ROLE "review_app" LOGIN/)).toBeVisible()
  await expect(review.getByText(/not an approval token/i)).toBeVisible()
  await expect(review.getByText(/Hypothetical variation unavailable/i)).toBeVisible()

  // Later phases record only reachability deltas; the viewer folds them so each
  // phase still shows the executor's full access after it.
  const phases = review.getByRole('heading', { name: 'Recorded phases' }).locator('..').locator('ol > li')
  await expect(phases).toHaveCount(2)
  await expect(phases.nth(1)).toContainText('Membership add')
  await expect(phases.nth(1)).toContainText('Add member · review_app to review_app_reader')
  await expect(phases.nth(1)).toContainText(/review_deployer\s*Reachable/)
  await expect(phases.nth(1)).not.toContainText('No role paths')
  expect(wasmRequests).toEqual([])
})

for (const profile of touchProfiles) {
  test.describe(`on ${profile.name} with touch`, () => {
    test.use(profile.use)

    test('renders recorded review text safely without overflow and opens a role sheet', async ({ page }) => {
      const artifact = JSON.parse(await readFile(fixturePath, 'utf8'))
      artifact.provenance.target_label = '<img src=x onerror=window.__reviewInjected=true>'
      if (artifact.recorded.sql_preview.status === 'available') {
        artifact.recorded.sql_preview.sql = '<script>window.__reviewInjected=true</script>\nSELECT 1;'
      }
      await page.goto('docs/explorer/')
      await uploadReview(page, artifact)
      const review = page.getByRole('region', { name: 'Recorded plan review' })
      await expect(review.getByText('<img src=x onerror=window.__reviewInjected=true>', { exact: true })).toBeVisible()
      expect(await page.evaluate(() => window.__reviewInjected)).toBeUndefined()
      const overflow = await review.evaluate((element) => element.scrollWidth > element.clientWidth + 1)
      expect(overflow).toBeFalsy()
      expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)

      await review.getByRole('heading', { name: 'Role index' }).locator('..').getByRole('button').first().tap()
      const sheet = page.getByRole('dialog')
      await expect(sheet.getByRole('heading')).toBeInViewport()
      await expect(sheet.getByText('Connections', { exact: true })).toBeInViewport()
      await sheet.getByRole('button', { name: 'Close role details' }).tap()
      await expect(sheet).toBeHidden()
    })
  })
}

for (const [name, mutate, error] of [
  ['null preflight', (artifact) => { artifact.preflight = [null] }, 'preflight evidence'],
  ['false recorded omissions', (artifact) => { artifact.recorded.omissions = false }, 'omissions'],
  ['zero change omissions', (artifact) => { artifact.recorded.changes[0].omissions = 0 }, 'changes'],
  ['empty-string change omissions', (artifact) => { artifact.recorded.changes[0].omissions = '' }, 'changes'],
  ['missing drop-role name', (artifact) => { artifact.recorded.changes[0].change = { kind: 'drop_role' } }, 'changes'],
  ['repeated phase index', (artifact) => { artifact.recorded.phases[0].change_indices.push(0) }, 'phases'],
  ['missing phases', (artifact) => { artifact.recorded.phases = [] }, 'phases'],
]) {
  test(`rejects ${name}, clears the previous review, and recovers`, async ({ page }) => {
    const valid = await readFile(fixturePath)
    const artifact = JSON.parse(valid)
    await page.goto('docs/explorer/')
    await uploadReview(page, valid)
    await expect(page.getByRole('region', { name: 'Recorded plan review' })).toBeVisible()

    mutate(artifact)
    await uploadReview(page, artifact, 'malformed-review.json')
    await expect(page.getByRole('region', { name: 'Recorded plan review' })).toBeHidden()
    await expect(page.locator('article').getByRole('alert')).toContainText(`review artifact ${error} ${error === 'preflight evidence' ? 'is' : 'are'} malformed`)

    await uploadReview(page, valid, 'recorded-review.json')
    await expect(page.getByRole('region', { name: 'Recorded plan review' })).toBeVisible()
  })
}

for (const [name, mutate, message] of [
  ['a retired v1 artifact', (artifact) => { artifact.schema_version = 'pgroles.review-artifact.v1' }, 're-export the review with the current pgroles CLI'],
  ['a smuggled top-level field', (artifact) => { artifact.notes = 'x' }, 'unknown field "notes" at $'],
  ['a smuggled change field', (artifact) => { artifact.recorded.changes[0].change.comment = 'db pass: hunter2' }, 'unknown field "comment" at $.recorded.changes[0].change'],
  ['a credential-like field', (artifact) => { artifact.recorded.visual.nodes[0].database_url = 'postgres://x' }, 'credential-like field "database_url"'],
  ['a malformed reachability delta', (artifact) => { artifact.recorded.phases[1].executor_usage_delta.removed = ['never_present'] }, 'phase 2 reachability delta is malformed'],
]) {
  test(`reports ${name} as an import error`, async ({ page }) => {
    const artifact = JSON.parse(await readFile(fixturePath, 'utf8'))
    mutate(artifact)
    await page.goto('docs/explorer/')
    await uploadReview(page, artifact)
    const alert = page.locator('article').getByRole('alert')
    await expect(alert).toHaveAttribute('data-error-kind', 'import')
    await expect(alert).toContainText('Import failed')
    await expect(alert).toContainText(message)
    await expect(page.getByRole('region', { name: 'Recorded plan review' })).toBeHidden()
  })
}
