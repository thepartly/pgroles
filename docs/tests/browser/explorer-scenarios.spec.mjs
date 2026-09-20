import { expect, test } from '@playwright/test'

const scenarios = [
  ['acme-adoption', 'Adopt Acme safely'],
  ['acme-membership-bridge', 'Cross a membership bridge'],
  ['acme-executor-authority', 'Change the executor facts'],
  ['acme-default-privileges', 'Lose authority between phases'],
  ['acme-profile-binding', 'Expand a profile binding'],
]

function expectScenarioOnlyUrl(page, scenario) {
  const url = new URL(page.url())
  expect([...url.searchParams.keys()]).toEqual(['scenario'])
  expect(url.searchParams.get('scenario')).toBe(scenario)
}

test('uses the additive adoption scenario by default and compares authoritative mode', async ({ page }) => {
  await page.goto('docs/explorer/')

  await expect(page.getByRole('heading', { name: 'Adopt Acme safely' })).toBeVisible()
  await expect(page.getByLabel('Load bundled scenario')).toHaveValue('acme-adoption')
  await expect(page.getByLabel('Reconciliation mode')).toHaveValue('additive')

  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Execution phases')).toBeVisible()
  await expect(page.getByText(/Add member.*orders_reader/i)).toBeVisible()
  await expect(page.getByText(/Drop role.*bob/i)).toBeHidden()

  await page.getByLabel('Reconciliation mode').selectOption('authoritative')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Drop Role · bob', { exact: true })).toBeVisible()
})

test('loads bundled deep links and preserves selector transitions in browser history', async ({ page }) => {
  await page.goto('docs/explorer/?scenario=acme-membership-bridge')
  await expect(page.getByRole('heading', { name: 'Cross a membership bridge' })).toBeVisible()
  expectScenarioOnlyUrl(page, 'acme-membership-bridge')

  await page.getByLabel('Load bundled scenario').selectOption('acme-profile-binding')
  await expect(page.getByRole('heading', { name: 'Expand a profile binding' })).toBeVisible()
  expectScenarioOnlyUrl(page, 'acme-profile-binding')

  await page.goBack()
  await expect(page.getByRole('heading', { name: 'Cross a membership bridge' })).toBeVisible()
  await expect(page.getByLabel('Load bundled scenario')).toHaveValue('acme-membership-bridge')

  await page.goForward()
  await expect(page.getByRole('heading', { name: 'Expand a profile binding' })).toBeVisible()
  await expect(page.getByLabel('Load bundled scenario')).toHaveValue('acme-profile-binding')
})

test('falls back safely for an unknown scenario id', async ({ page }) => {
  await page.goto('docs/explorer/?scenario=not-a-bundled-scenario')

  await expect(page.getByRole('status')).toContainText('Unknown scenario “not-a-bundled-scenario”. Showing Adopt Acme safely.')
  await expect(page.getByLabel('Load bundled scenario')).toHaveValue('acme-adoption')
  await expect(page.getByLabel('Reconciliation mode')).toHaveValue('additive')
  expectScenarioOnlyUrl(page, 'not-a-bundled-scenario')
})

test('manual policy and executor edits never enter the URL', async ({ page }) => {
  await page.goto('docs/explorer/?scenario=acme-profile-binding')
  await page.getByLabel('Desired YAML').fill('roles:\n  - name: private_marker_role\n')
  await page.getByLabel('Executor role').fill('private_marker_executor')
  await page.getByLabel('Reconciliation mode').selectOption('adopt')

  expectScenarioOnlyUrl(page, 'acme-profile-binding')
  expect(page.url()).not.toContain('private_marker')
})

test('guide cards use preview-safe scenario links without loading WASM', async ({ page }) => {
  const wasmRequests = []
  page.on('request', (request) => {
    if (request.url().includes('/wasm/')) wasmRequests.push(request.url())
  })

  const guides = [
    ['docs/adoption/', 'acme-adoption', 'Adopt Acme safely'],
    ['docs/memberships/', 'acme-membership-bridge', 'Cross a membership bridge'],
    ['docs/executor-privileges/', 'acme-executor-authority', 'Change the executor facts'],
    ['docs/default-privileges/', 'acme-default-privileges', 'Lose authority between phases'],
    ['docs/profiles/', 'acme-profile-binding', 'Expand a profile binding'],
  ]

  for (const [guide, scenario, title] of guides) {
    await page.goto(guide)
    const card = page.getByRole('heading', { name: title }).locator('..')
    const link = card.getByRole('link', { name: 'Open in explorer' })
    await expect(link).toHaveAttribute('href', new RegExp(`/docs/explorer/\\?scenario=${scenario}$`))
  }
  expect(wasmRequests).toEqual([])

  await page.goto('docs/adoption/')
  await page.getByRole('link', { name: 'Open in explorer' }).click()
  await expect(page.getByRole('heading', { name: 'Adopt Acme safely' })).toBeVisible()
  expectScenarioOnlyUrl(page, 'acme-adoption')
})

test('each bundled scenario produces its distinguishing analysis result', async ({ page }) => {
  test.slow()
  const expectations = {
    'acme-adoption': /Add member.*orders_reader/i,
    'acme-membership-bridge': /team_lead/i,
    'acme-executor-authority': /app_owner/i,
    'acme-default-privileges': /loses access|app_owner/i,
    'acme-profile-binding': /Create role.*app-reader/i,
  }

  for (const [scenario] of scenarios) {
    await page.goto(`docs/explorer/?scenario=${scenario}`)
    await page.getByRole('button', { name: 'Analyze plan' }).click()
    await expect(page.getByText('Execution phases')).toBeVisible()
    await expect(page.getByText(expectations[scenario]).first()).toBeVisible()
    expectScenarioOnlyUrl(page, scenario)
  }
})

test('compares executor authority facts without changing the planned default privilege', async ({ page }) => {
  await page.goto('docs/explorer/?scenario=acme-executor-authority')

  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Set Default Privilege · app_owner', { exact: true })).toBeVisible()
  await expect(page.locator('[data-severity="warning"]').filter({ hasText: 'app_owner' })).toBeVisible()

  await page.getByLabel('Executor facts variant').selectOption('inherited')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Set Default Privilege · app_owner', { exact: true })).toBeVisible()
  await expect(page.locator('[data-severity]').filter({ hasText: 'app_owner' })).toHaveCount(0)

  await page.getByLabel('Executor facts variant').selectOption('denied')
  await page.getByRole('button', { name: 'Analyze plan' }).click()
  await expect(page.getByText('Set Default Privilege · app_owner', { exact: true })).toBeVisible()
  await expect(page.locator('[data-severity="error"]').filter({ hasText: 'app_owner' })).toBeVisible()

  await page.getByLabel('Executor role').fill('custom_executor')
  await expect(page.getByLabel('Executor facts variant')).toHaveValue('custom')

  await page.getByLabel('Executor facts variant').selectOption('inherited')
  await expect(page.getByLabel('Executor facts variant')).toHaveValue('inherited')
  await expect(page.getByLabel('Executor role')).toHaveValue('deploy')

  await page.locator('input[type="file"]').setInputFiles({
    name: 'custom-executor.json',
    mimeType: 'application/json',
    buffer: Buffer.from(JSON.stringify({
      current: { roles: { imported_executor: { login: true } } },
      executor: { role: 'imported_executor', superuser: false },
    })),
  })
  await expect(page.getByLabel('Executor facts variant')).toHaveValue('custom')
  await expect(page.getByLabel('Executor role')).toHaveValue('imported_executor')
})

test('opens the focused membership boundary with lost inherited authority', async ({ page }) => {
  await page.goto('docs/explorer/?scenario=acme-default-privileges')
  await page.getByRole('button', { name: 'Analyze plan' }).click()

  const membershipPhase = page.getByRole('heading', { name: 'Membership remove', exact: true }).locator('../..')
  const accessDetails = membershipPhase.locator('details')
  await expect(accessDetails).toHaveAttribute('open', '')
  await expect(accessDetails).toContainText('Inherited usage')
  await expect(accessDetails).toContainText(/app_owner\s*Unreachable/i)
})
