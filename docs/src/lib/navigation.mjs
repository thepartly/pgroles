export const DESTINATIONS = Object.freeze([
  { id: 'docs', label: 'Docs', href: '/' },
  { id: 'learn', label: 'Learn PostgreSQL', href: '/docs/learn-postgresql' },
  { id: 'explorer', label: 'Explorer', href: '/docs/explorer' },
])

const docsNavigation = [
  {
    title: 'Get started',
    links: [
      { title: 'Overview', href: '/' },
      { title: 'Install the CLI', href: '/docs/installation' },
      { title: 'CLI quick start', href: '/docs/quick-start' },
      { title: 'Operator quick start', href: '/docs/operator-quick-start' },
    ],
  },
  {
    title: 'Write policy',
    links: [
      { title: 'Policy guide', href: '/docs/manifest-format' },
      { title: 'Profiles and schemas', href: '/docs/profiles' },
      { title: 'Grants', href: '/docs/grants' },
      { title: 'Memberships', href: '/docs/memberships' },
      { title: 'Default privileges', href: '/docs/default-privileges' },
      { title: 'Bundle composition', href: '/docs/bundle-composition' },
      { title: 'Application access patterns', href: '/docs/tooling' },
    ],
  },
  {
    title: 'Connect and adopt',
    links: [
      { title: 'Executor privileges', href: '/docs/executor-privileges' },
      { title: 'Adopt an existing database', href: '/docs/adoption' },
      { title: 'Google Cloud SQL', href: '/docs/google-cloud-sql' },
      { title: 'AWS RDS and Aurora', href: '/docs/aws-rds' },
    ],
  },
  {
    title: 'Plan and review',
    links: [
      { title: 'Plan a change', href: '/docs/planning' },
      { title: 'Review a recorded plan', href: '/docs/recorded-reviews' },
      { title: 'CI/CD workflows', href: '/docs/ci-cd' },
    ],
  },
  {
    title: 'Kubernetes operator',
    links: [{ title: 'Operator overview', href: '/docs/operator' }],
    groups: [
      {
        title: 'Setup',
        links: [
          { title: 'Install the operator', href: '/docs/operator-install' },
          { title: 'PostgresPolicy resource', href: '/docs/operator-postgrespolicy' },
          { title: 'Database connections', href: '/docs/operator-connections' },
        ],
      },
      {
        title: 'Access workflows',
        links: [
          { title: 'Plan approval', href: '/docs/operator-plan-approval' },
          { title: 'Candidates and promotion', href: '/docs/operator-candidates' },
          { title: 'Ephemeral access', href: '/docs/ephemeral-access' },
        ],
      },
      {
        title: 'Operations',
        links: [
          { title: 'Running the operator', href: '/docs/operator-operations' },
          { title: 'Status and telemetry', href: '/docs/operator-status' },
          { title: 'Monitoring', href: '/docs/operator-monitoring' },
          { title: 'Troubleshooting', href: '/docs/operator-troubleshooting' },
          { title: 'Upgrading', href: '/docs/operator-upgrades' },
        ],
      },
      {
        title: 'Security and internals',
        links: [
          { title: 'RBAC and security', href: '/docs/operator-security' },
          { title: 'Securing ephemeral access', href: '/docs/ephemeral-access-security' },
          { title: 'Production readiness', href: '/docs/operator-production-status' },
          { title: 'Operator architecture', href: '/docs/operator-architecture' },
        ],
      },
    ],
  },
  {
    title: 'Reference',
    links: [
      { title: 'CLI commands', href: '/docs/cli' },
      { title: 'Manifest fields', href: '/docs/manifest-reference' },
      { title: 'CRD API', href: '/docs/operator-api-reference' },
      { title: 'Limitations', href: '/docs/limitations' },
      { title: 'Architecture', href: '/docs/architecture' },
      { title: 'Related tools', href: '/docs/alternatives' },
    ],
  },
]

const learnNavigation = [
  {
    title: 'Learn PostgreSQL roles',
    links: [{ title: 'Course overview', href: '/docs/learn-postgresql' }],
  },
  {
    title: 'Core',
    links: [
      { title: '1. The permission chain', href: '/docs/postgresql-access-model' },
      { title: '2. Capability roles', href: '/docs/postgresql-capability-roles' },
      { title: '3. Access drift', href: '/docs/postgresql-access-drift' },
      { title: '4. Ownership', href: '/docs/postgresql-ownership' },
      { title: '5. Future objects', href: '/docs/postgresql-default-privileges' },
      { title: '6. Offboarding an owner', href: '/docs/postgresql-offboarding' },
    ],
  },
  {
    title: 'Advanced',
    links: [
      { title: '7. Membership mechanics', href: '/docs/postgresql-role-hierarchy' },
      { title: '8. Row-level security', href: '/docs/postgresql-row-security' },
      { title: '9. The security review', href: '/docs/postgresql-security-review' },
    ],
  },
  {
    title: 'SQL playground',
    links: [{ title: 'Open the playground', href: '/docs/postgresql-playground' }],
  },
]

const explorerNavigation = [
  {
    title: 'Explorer',
    links: [
      { title: 'Plan explorer', href: '/docs/explorer' },
      { title: 'Snapshot format', href: '/docs/explorer-snapshots' },
    ],
  },
]

export const navigationByDestination = Object.freeze({
  docs: docsNavigation,
  learn: learnNavigation,
  explorer: explorerNavigation,
})

function linksInSection(section) {
  return [
    ...(section.links ?? []),
    ...(section.groups ?? []).flatMap((group) => group.links),
  ]
}

const navigationPages = Object.entries(navigationByDestination).flatMap(
  ([destination, sections]) =>
    sections.flatMap((section) =>
      linksInSection(section).map((link) => ({
        ...link,
        navigationTitle: link.title,
        destination,
        section: section.title,
      }))
    )
)

const generatedCrdPages = [
  ['PostgresPolicy', '/docs/reference/postgrespolicy-v1alpha1'],
  ['PostgresPolicyPlan', '/docs/reference/postgrespolicyplan-v1alpha1'],
  ['PostgresPolicyCandidate', '/docs/reference/postgrespolicycandidate-v1alpha1'],
  ['EphemeralAccessPolicy', '/docs/reference/ephemeralaccesspolicy-v1alpha1'],
  ['EphemeralAccessRequest', '/docs/reference/ephemeralaccessrequest-v1alpha1'],
].map(([title, href]) => ({
  title,
  navigationTitle: title,
  href,
  destination: 'docs',
  section: 'Reference',
  navigationParent: '/docs/operator-api-reference',
}))

function buildPageRegistry(pages) {
  const registry = {}

  for (const page of pages) {
    if (registry[page.href]) {
      throw new Error(`Duplicate canonical page route: ${page.href}`)
    }
    registry[page.href] = Object.freeze({
      ...page,
      contentType:
        page.destination === 'learn'
          ? 'Course'
          : page.section === 'Reference'
          ? 'Reference'
          : 'Guide',
    })
  }

  return Object.freeze(registry)
}

export const pageRegistry = buildPageRegistry([
  ...navigationPages,
  ...generatedCrdPages,
])

export const COURSE_READING_SEQUENCE = Object.freeze([
  '/docs/learn-postgresql',
  '/docs/postgresql-access-model',
  '/docs/postgresql-capability-roles',
  '/docs/postgresql-access-drift',
  '/docs/postgresql-ownership',
  '/docs/postgresql-default-privileges',
  '/docs/postgresql-offboarding',
  '/docs/postgresql-role-hierarchy',
  '/docs/postgresql-row-security',
  '/docs/postgresql-security-review',
  '/docs/postgresql-playground',
])

export const QUICK_START_NEXT_STEPS = Object.freeze({
  '/docs/quick-start': '/docs/manifest-format',
  '/docs/operator-quick-start': '/docs/operator',
})

function normalizePathname(pathname) {
  if (typeof pathname !== 'string') return '/'

  const pathWithoutQueryOrHash = pathname.split(/[?#]/, 1)[0] || '/'
  if (pathWithoutQueryOrHash === '/') return '/'
  return pathWithoutQueryOrHash.replace(/\/+$/, '')
}

export function resolvePage(pathname) {
  return pageRegistry[normalizePathname(pathname)]
}

export function getNavigation(pathnameOrDestination) {
  if (navigationByDestination[pathnameOrDestination]) {
    return navigationByDestination[pathnameOrDestination]
  }

  const page = resolvePage(pathnameOrDestination)
  return navigationByDestination[page?.destination ?? 'docs']
}

/**
 * Destination, section, and page labels for the breadcrumb, with a level
 * dropped when it repeats the one above it (the Explorer destination's only
 * section is also called Explorer).
 */
export function getBreadcrumbs(pathname) {
  const page = resolvePage(pathname)
  const destination = DESTINATIONS.find(
    (item) => item.id === (page?.destination ?? 'docs')
  )
  const parent = page?.navigationParent && resolvePage(page.navigationParent)
  const trail = [
    {
      label: destination.label,
      current: false,
      ...(page?.href !== destination.href && { href: destination.href }),
    },
    { label: page?.section ?? destination.label, current: false },
    ...(parent
      ? [{ label: parent.navigationTitle, current: false, href: parent.href }]
      : []),
    ...(page ? [{ label: page.navigationTitle, current: true }] : []),
  ]
  return trail.filter(
    (crumb, index) =>
      index === 0 ||
      crumb.label.toLowerCase() !== trail[index - 1].label.toLowerCase()
  )
}

function readingLink(href) {
  if (!href) return undefined
  return pageRegistry[href]
}

export function getReadingLinks(pathname) {
  const normalizedPathname = normalizePathname(pathname)
  const courseIndex = COURSE_READING_SEQUENCE.indexOf(normalizedPathname)

  if (courseIndex !== -1) {
    return {
      previous: readingLink(COURSE_READING_SEQUENCE[courseIndex - 1]),
      next: readingLink(COURSE_READING_SEQUENCE[courseIndex + 1]),
    }
  }

  return {
    previous: undefined,
    next: readingLink(QUICK_START_NEXT_STEPS[normalizedPathname]),
  }
}
