import { expect, test } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

const fixturePath = resolve(import.meta.dirname, '../fixtures/recorded-review.json')

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
  expect(wasmRequests).toEqual([])
})

for (const width of [360, 390, 768]) {
  test(`renders recorded review text safely without overflow at ${width}px`, async ({ page }) => {
    const artifact = JSON.parse(await readFile(fixturePath, 'utf8'))
    artifact.provenance.target_label = '<img src=x onerror=window.__reviewInjected=true>'
    if (artifact.recorded.sql_preview.status === 'available') {
      artifact.recorded.sql_preview.sql = '<script>window.__reviewInjected=true</script>\nSELECT 1;'
    }
    await page.setViewportSize({ width, height: 800 })
    await page.goto('docs/explorer/')
    await uploadReview(page, artifact)
    const review = page.getByRole('region', { name: 'Recorded plan review' })
    await expect(review.getByText('<img src=x onerror=window.__reviewInjected=true>', { exact: true })).toBeVisible()
    expect(await page.evaluate(() => window.__reviewInjected)).toBeUndefined()
    const overflow = await review.evaluate((element) => element.scrollWidth > element.clientWidth + 1)
    expect(overflow).toBeFalsy()
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
