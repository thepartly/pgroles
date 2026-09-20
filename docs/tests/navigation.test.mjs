import assert from 'node:assert/strict'
import { readdir } from 'node:fs/promises'
import { basename, extname } from 'node:path'
import test from 'node:test'

import {
  COURSE_READING_SEQUENCE,
  DESTINATIONS,
  QUICK_START_NEXT_STEPS,
  getNavigation,
  getReadingLinks,
  navigationByDestination,
  pageRegistry,
  resolvePage,
} from '../src/lib/navigation.mjs'

const pagesDirectory = new URL('../src/pages/docs/', import.meta.url)

async function discoverPageRoutes(directory = pagesDirectory, prefix = '/docs') {
  const entries = await readdir(directory, { withFileTypes: true })
  const routes = await Promise.all(
    entries.map(async (entry) => {
      if (entry.isDirectory()) {
        return discoverPageRoutes(
          new URL(`${entry.name}/`, directory),
          `${prefix}/${entry.name}`
        )
      }

      const extension = extname(entry.name)
      if (!['.md', '.jsx'].includes(extension)) return []
      return [`${prefix}/${basename(entry.name, extension)}`]
    })
  )
  return routes.flat()
}

function navigationLinks() {
  return Object.values(navigationByDestination).flatMap((sections) =>
    sections.flatMap((section) => [
      ...(section.links ?? []),
      ...(section.groups ?? []).flatMap((group) => group.links),
    ])
  )
}

test('every page route has one canonical registry entry', async () => {
  const existingRoutes = await discoverPageRoutes()
  const expectedRoutes = ['/', ...existingRoutes]

  assert.deepEqual(
    Object.keys(pageRegistry).sort(),
    [...new Set(expectedRoutes)].sort()
  )
})

test('navigation contains each visible route once', () => {
  const hrefs = navigationLinks().map((link) => link.href)
  assert.equal(new Set(hrefs).size, hrefs.length)
  assert.equal(
    hrefs.filter((href) => href === '/docs/operator-quick-start').length,
    1
  )
})

test('the three destinations resolve to their own navigation', () => {
  assert.deepEqual(
    DESTINATIONS.map((destination) => destination.id),
    ['docs', 'learn', 'explorer']
  )
  assert.equal(resolvePage('/docs/postgresql-row-security').destination, 'learn')
  assert.equal(resolvePage('/docs/explorer').destination, 'explorer')
  assert.equal(resolvePage('/docs/operator').destination, 'docs')
  assert.equal(
    getNavigation('/docs/postgresql-row-security'),
    navigationByDestination.learn
  )
  assert.equal(getNavigation('/docs/explorer'), navigationByDestination.explorer)
})

test('generated references inherit the canonical Reference location', () => {
  const page = resolvePage(
    '/docs/reference/postgrespolicycandidate-v1alpha1/?field=spec#status'
  )
  assert.equal(page.section, 'Reference')
  assert.equal(page.navigationParent, '/docs/operator-api-reference')
})

test('course reading order is explicit and independent of sidebar order', () => {
  assert.equal(COURSE_READING_SEQUENCE.length, 11)
  assert.deepEqual(getReadingLinks('/docs/postgresql-access-model'), {
    previous: pageRegistry['/docs/learn-postgresql'],
    next: pageRegistry['/docs/postgresql-capability-roles'],
  })
  assert.deepEqual(getReadingLinks('/docs/postgresql-security-review'), {
    previous: pageRegistry['/docs/postgresql-row-security'],
    next: pageRegistry['/docs/postgresql-playground'],
  })
  assert.deepEqual(getReadingLinks('/docs/postgresql-playground'), {
    previous: pageRegistry['/docs/postgresql-security-review'],
    next: undefined,
  })
})

test('course reading order matches the interactive lesson next links', async () => {
  const storyModule = await import('../src/components/AcmeStoryData.mjs')
  const chapterNextHrefs = [
    storyModule.chapters.gates.next.href,
    storyModule.chapters.capabilities.next.href,
    storyModule.chapters.drift.next.href,
    storyModule.chapters.ownership.next.href,
    storyModule.chapters.defaults.next.href,
    storyModule.chapters.offboarding.next.href,
    storyModule.chapters.mechanics.next.href,
    storyModule.chapters.rls.next.href,
    storyModule.chapters.security.next.href,
  ]

  assert.deepEqual(chapterNextHrefs, COURSE_READING_SEQUENCE.slice(2))
})

test('quick starts have deliberate next steps and reference pages have no pager', () => {
  assert.deepEqual(QUICK_START_NEXT_STEPS, {
    '/docs/quick-start': '/docs/manifest-format',
    '/docs/operator-quick-start': '/docs/operator',
  })
  assert.equal(
    getReadingLinks('/docs/operator-quick-start').next,
    pageRegistry['/docs/operator']
  )
  assert.deepEqual(getReadingLinks('/docs/manifest-reference'), {
    previous: undefined,
    next: undefined,
  })
})

test('the course uses clear navigation labels and excludes the explorer', () => {
  const learnLinks = navigationByDestination.learn.flatMap((section) =>
    section.links.map((link) => link)
  )
  assert.equal(
    learnLinks.find((link) => link.href === '/docs/postgresql-row-security').title,
    '8. Row-level security'
  )
  assert.equal(
    learnLinks.find((link) => link.href === '/docs/postgresql-playground').title,
    'Open the playground'
  )
  assert.ok(!learnLinks.some((link) => link.href === '/docs/explorer'))
})
