import { devices, expect } from '@playwright/test'

// Only Chromium is installed in CI, so keep each descriptor's viewport, touch,
// and mobile emulation but not its preferred browser engine.
function chromiumProfile({ defaultBrowserType: _engine, ...descriptor }) {
  return descriptor
}

const android = chromiumProfile(devices['Pixel 5'])

export const touchProfiles = [
  { name: '360px Android', use: { ...android, viewport: { width: 360, height: 740 }, screen: { width: 360, height: 800 } } },
  { name: 'iPhone 12 (390px)', use: chromiumProfile(devices['iPhone 12']) },
  { name: 'Pixel 5 (393px)', use: android },
  { name: '768px tablet', use: { ...android, viewport: { width: 768, height: 1024 }, screen: { width: 768, height: 1024 }, deviceScaleFactor: 2 } },
]

export async function expectNoHorizontalOverflow(page) {
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow).toBeLessThanOrEqual(1)
}

export async function expectWithinViewport(page, locator) {
  const box = await locator.boundingBox()
  const viewport = page.viewportSize()
  expect(box).not.toBeNull()
  expect(box.x).toBeGreaterThanOrEqual(-1)
  expect(box.y).toBeGreaterThanOrEqual(-1)
  expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1)
  expect(box.y + box.height).toBeLessThanOrEqual(viewport.height + 1)
}
