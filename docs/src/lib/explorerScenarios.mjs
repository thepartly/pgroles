const schemaVersion = 'pgroles.explorer.v1'

const executor = (role, overrides = {}) => ({
  role,
  superuser: false,
  memberships: [],
  new_membership_set_role: 'allowed',
  new_role_set_role: 'unknown',
  new_role_inherit: 'unknown',
  new_role_admin_option: 'unknown',
  ...overrides,
})

export const explorerScenarios = [
  {
    id: 'acme-adoption',
    title: 'Adopt Acme safely',
    description: 'Layer Acme’s orders_reader policy onto a database that already has direct access and drift.',
    explanation: 'Additive mode is the safe first look: it adds declared access while retaining Alice’s direct grant, Bob’s undeclared membership, and undeclared roles in this managed snapshot. Compare adopt and authoritative modes before tightening control.',
    relatedDocs: [
      { href: '/docs/adoption', label: 'Staged adoption' },
      { href: '/docs/postgresql-access-drift', label: 'Acme’s access drift story' },
    ],
    request: {
      schema_version: schemaVersion,
      current: {
        roles: { priya: { login: true }, alice: { login: true }, bob: { login: true }, reporting_app: { login: true }, orders_reader: {} },
        schemas: { app: { owner: 'priya' } },
        grants: [
          { role: 'alice', object_type: 'schema', name: 'app', privileges: ['USAGE'] },
          { role: 'alice', object_type: 'table', schema: 'app', name: 'orders', privileges: ['SELECT'] },
          { role: 'orders_reader', object_type: 'schema', name: 'app', privileges: ['USAGE'] },
          { role: 'orders_reader', object_type: 'table', schema: 'app', name: 'orders', privileges: ['SELECT'] },
        ],
        memberships: [
          { role: 'orders_reader', member: 'alice', inherit: true, admin: false },
          { role: 'orders_reader', member: 'bob', inherit: true, admin: false },
        ],
      },
      desired_yaml: `default_owner: priya

roles:
  - name: priya
    external: true
  - name: alice
    login: true
  - name: reporting_app
    login: true
  - name: orders_reader

grants:
  - role: orders_reader
    privileges: [USAGE]
    object: { type: schema, name: app }
  - role: orders_reader
    privileges: [SELECT]
    object: { type: table, schema: app, name: "*" }

memberships:
  - role: orders_reader
    members:
      - name: alice
      - name: reporting_app
`,
      mode: 'additive',
      executor: executor('postgres', { superuser: true }),
    },
    expected: { changes: [{ kind: 'AddMember', role: 'orders_reader', member: 'reporting_app' }], absentChanges: ['Revoke', 'RemoveMember', 'DropRole', 'AlterRole'] },
    cases: [
      { id: 'adopt', requestOverrides: { mode: 'adopt' }, expected: { changes: [{ kind: 'Revoke', role: 'alice' }, { kind: 'RemoveMember', role: 'orders_reader', member: 'bob' }], absentChanges: ['DropRole'] } },
      { id: 'authoritative', requestOverrides: { mode: 'authoritative' }, expected: { changes: [{ kind: 'Revoke', role: 'alice' }, { kind: 'RemoveMember', role: 'orders_reader', member: 'bob' }, { kind: 'DropRole', name: 'bob' }] } },
    ],
  },
  {
    id: 'acme-membership-bridge',
    title: 'Cross a membership bridge',
    description: 'Inspect INHERIT, SET ROLE, and ADMIN OPTION as separate facts on Bob’s path to analyst.',
    explanation: 'The existing edge was granted by team_lead. Changing it requires pgroles to remove that grantor-attributed edge and add the declared edge, while executor authority is evaluated independently from Bob’s ability to inherit or SET ROLE.',
    relatedDocs: [
      { href: '/docs/postgresql-role-hierarchy', label: 'PostgreSQL role hierarchy' },
      { href: '/docs/memberships', label: 'Memberships reference' },
    ],
    request: {
      schema_version: schemaVersion,
      current: {
        roles: { analyst: {}, bob: { login: true }, team_lead: { login: true }, orders_reader: {} },
        memberships: [
          { role: 'orders_reader', member: 'analyst', inherit: true, admin: false, grantors: ['postgres'] },
          { role: 'analyst', member: 'bob', inherit: false, admin: true, grantors: ['team_lead'] },
        ],
      },
      desired_yaml: `roles:
  - name: analyst
  - name: bob
    login: true
  - name: team_lead
    login: true
  - name: orders_reader

memberships:
  - role: orders_reader
    members:
      - name: analyst
  - role: analyst
    members:
      - name: bob
        inherit: true
        admin: false
`,
      mode: 'authoritative',
      executor: executor('deploy', {
        memberships: [{ role: 'team_lead', member: 'deploy', set_role: 'allowed', inherit: 'denied', admin_option: 'denied' }],
      }),
    },
    focusPhase: 'membership_remove',
    expected: {
      changes: [{ kind: 'RemoveMember', role: 'analyst', member: 'bob', grantor: 'team_lead' }],
      findings: [{ kind: 'required_role_unavailable', phase: 'membership_remove', role: 'team_lead' }],
    },
  },
  {
    id: 'acme-executor-authority',
    title: 'Change the executor facts',
    description: 'Keep Acme’s snapshot and policy fixed, then vary only whether deploy can use app_owner.',
    explanation: 'The planned default privilege is identical in every case. Only the supplied executor facts change whether the browser can establish that deploy may act with app_owner’s authority.',
    relatedDocs: [
      { href: '/docs/default-privileges', label: 'Default privileges' },
      { href: '/docs/executor-privileges', label: 'Executor privileges' },
    ],
    request: {
      schema_version: schemaVersion,
      current: { roles: { app_owner: {}, deploy: { login: true }, orders_reader: {} }, schemas: { app: { owner: 'app_owner' } } },
      desired_yaml: `roles:
  - name: app_owner
  - name: deploy
    login: true
  - name: orders_reader

default_privileges:
  - owner: app_owner
    schema: app
    grant:
      - role: orders_reader
        privileges: [SELECT]
        on_type: table
`,
      mode: 'authoritative',
      executor: executor('deploy', {
        memberships: [{ role: 'app_owner', member: 'deploy', set_role: 'denied', inherit: 'unknown', admin_option: 'denied' }],
      }),
    },
    focusPhase: 'grant',
    expected: { findings: [{ kind: 'required_role_reachability_unknown', phase: 'grant', role: 'app_owner' }] },
    cases: [
      {
        id: 'inherited',
        title: 'INHERIT allowed, SET ROLE denied',
        description: 'deploy inherits app_owner authority, which is enough for ALTER DEFAULT PRIVILEGES even though deploy cannot SET ROLE app_owner.',
        requestOverrides: { executor: executor('deploy', { memberships: [{ role: 'app_owner', member: 'deploy', set_role: 'denied', inherit: 'allowed', admin_option: 'denied' }] }) },
        expected: { absentFindings: [{ kind: 'required_role_unavailable', role: 'app_owner' }, { kind: 'required_role_reachability_unknown', role: 'app_owner' }] },
      },
      {
        id: 'denied',
        title: 'INHERIT denied, SET ROLE allowed',
        description: 'SET ROLE reachability alone does not authorize ALTER DEFAULT PRIVILEGES, because that statement runs without switching roles.',
        requestOverrides: { executor: executor('deploy', { memberships: [{ role: 'app_owner', member: 'deploy', set_role: 'allowed', inherit: 'denied', admin_option: 'denied' }] }) },
        expected: { findings: [{ kind: 'required_role_unavailable', phase: 'grant', role: 'app_owner' }] },
      },
    ],
  },
  {
    id: 'acme-default-privileges',
    title: 'Lose authority between phases',
    description: 'Remove deploy’s inherited app_owner authority before a later default-privilege revoke.',
    explanation: 'Phase simulation matters here: the membership removal changes what deploy can do before the default-privilege revocation runs. Expand the focused boundary to inspect inherited usage separately from SET ROLE.',
    relatedDocs: [
      { href: '/docs/default-privileges', label: 'Default privileges' },
      { href: '/docs/executor-privileges', label: 'Executor privileges' },
    ],
    request: {
      schema_version: schemaVersion,
      current: {
        roles: { app_owner: {}, deploy: { login: true }, orders_reader: {} },
        schemas: { app: { owner: 'app_owner' } },
        default_privileges: [{ owner: 'app_owner', schema: 'app', on_type: 'table', grantee: 'orders_reader', privileges: ['SELECT'] }],
        memberships: [{ role: 'app_owner', member: 'deploy', inherit: true, admin: false, grantors: ['team_lead'] }],
      },
      desired_yaml: `roles:
  - name: app_owner
  - name: deploy
    login: true
  - name: orders_reader
`,
      mode: 'authoritative',
      executor: executor('deploy', {
        memberships: [
          { role: 'team_lead', member: 'deploy', set_role: 'denied', inherit: 'allowed', admin_option: 'denied' },
          { role: 'app_owner', member: 'team_lead', set_role: 'denied', inherit: 'denied', admin_option: 'allowed' },
          { role: 'app_owner', member: 'deploy', set_role: 'allowed', inherit: 'allowed', admin_option: 'denied' },
        ],
      }),
    },
    focusPhase: 'membership_remove',
    expected: {
      findings: [
        { kind: 'executor_loses_access', phase: 'membership_remove', role: 'app_owner' },
        { kind: 'required_role_unavailable', phase: 'default_privilege_revoke', role: 'app_owner' },
      ],
      absentFindings: [{ kind: 'required_role_unavailable', phase: 'membership_remove', role: 'team_lead' }],
      phaseReachability: [{ phase: 'membership_remove', role: 'app_owner', authority: 'usage', status: 'unreachable' }],
    },
  },
  {
    id: 'acme-profile-binding',
    title: 'Expand a profile binding',
    description: 'Turn Acme’s repeated reader pattern into concrete roles, grants, and future-object defaults.',
    explanation: 'A single reader profile bound to app and analytics expands inside pgroles-core. The plan shows the concrete roles and grants that PostgreSQL will receive.',
    relatedDocs: [
      { href: '/docs/profiles', label: 'Profiles and schemas' },
      { href: '/docs/manifest-reference', label: 'Manifest reference' },
    ],
    request: {
      schema_version: schemaVersion,
      current: { roles: { app_owner: {} }, schemas: { app: { owner: 'app_owner' }, analytics: { owner: 'app_owner' } } },
      desired_yaml: `default_owner: app_owner

roles:
  - name: app_owner
  - name: reporting_app
    login: true

profiles:
  reader:
    grants:
      - privileges: [USAGE]
        object: { type: schema }
      - privileges: [SELECT]
        object: { type: table, name: "*" }
    default_privileges:
      - privileges: [SELECT]
        on_type: table

schemas:
  - name: app
    profiles: [reader]
  - name: analytics
    profiles: [reader]

memberships:
  - role: app-reader
    members:
      - name: reporting_app
`,
      mode: 'authoritative',
      executor: executor('postgres', { superuser: true }),
    },
    expected: { changes: [{ kind: 'CreateRole', name: 'app-reader' }, { kind: 'CreateRole', name: 'analytics-reader' }, { kind: 'AddMember', role: 'app-reader', member: 'reporting_app' }] },
  },
]

export function getExplorerScenario(id) {
  return explorerScenarios.find((scenario) => scenario.id === id)
}
