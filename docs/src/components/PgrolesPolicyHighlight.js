import { isMap, isScalar, isSeq, parseDocument } from 'yaml'

const topLevelFields = new Set([
  'default_owner',
  'role_pattern',
  'auth_providers',
  'profiles',
  'schemas',
  'roles',
  'grants',
  'default_privileges',
  'memberships',
  'retirements',
])

const fieldsByPath = new Map([
  [
    'profiles.$profile',
    new Set(['login', 'inherit', 'grants', 'default_privileges', 'config']),
  ],
  [
    'profiles.$profile.grants.*',
    new Set(['privileges', 'object', 'on', 'ensure']),
  ],
  ['profiles.$profile.grants.*.object', new Set(['type', 'name'])],
  ['profiles.$profile.grants.*.on', new Set(['type', 'name'])],
  [
    'profiles.$profile.default_privileges.*',
    new Set(['privileges', 'on_type', 'ensure']),
  ],
  ['schemas.*', new Set(['name', 'profiles', 'role_pattern', 'owner'])],
  [
    'roles.*',
    new Set([
      'name',
      'external',
      'preserve_undeclared_grants',
      'login',
      'superuser',
      'createdb',
      'createrole',
      'inherit',
      'replication',
      'bypassrls',
      'connection_limit',
      'comment',
      'password',
      'password_valid_until',
      'config',
    ]),
  ],
  ['roles.*.password', new Set(['from_env'])],
  ['grants.*', new Set(['role', 'ensure', 'privileges', 'object', 'on'])],
  ['grants.*.object', new Set(['type', 'schema', 'name'])],
  ['grants.*.on', new Set(['type', 'schema', 'name'])],
  ['default_privileges.*', new Set(['owner', 'schema', 'scope', 'grant'])],
  ['default_privileges.*.scope', new Set(['type', 'schema'])],
  [
    'default_privileges.*.grant.*',
    new Set(['role', 'ensure', 'privileges', 'on_type']),
  ],
  ['memberships.*', new Set(['role', 'members', 'exclusive'])],
  ['memberships.*.members.*', new Set(['name', 'inherit', 'admin'])],
  [
    'retirements.*',
    new Set(['role', 'reassign_owned_to', 'drop_owned', 'terminate_sessions']),
  ],
])

const authProviderFields = new Map([
  ['cloud_sql_iam', new Set(['type', 'project'])],
  ['alloydb_iam', new Set(['type', 'project', 'cluster'])],
  ['rds_iam', new Set(['type', 'region'])],
  ['azure_ad', new Set(['type', 'tenant_id'])],
  ['supabase', new Set(['type', 'project_ref'])],
  ['planet_scale', new Set(['type', 'organization'])],
])

const roleReferenceFields = new Set([
  'default_owner',
  'role_pattern',
  'owner',
  'role',
  'reassign_owned_to',
])

const fieldHelp = {
  role_pattern: 'Naming pattern inherited by schema profile bindings, unless overridden.',
  default_owner: 'Role used when a default privilege omits its owner.',
  roles: 'Roles whose lifecycle and supported attributes pgroles manages.',
  grants: 'Object privileges granted to a named role.',
  memberships: 'Directed role-membership edges.',
  role: 'The role receiving privileges or being granted to members.',
  members: 'Roles that become members of the granted role.',
  exclusive:
    'For predefined or external roles, assert the ordinary-member list is complete. Additive mode skips revocations; cloud-provider roles are not exempt.',
  preserve_undeclared_grants:
    'Preserve undeclared in-scope object grants. Explicit ensure: absent rules still revoke; memberships and default privileges are unaffected.',
  privileges: 'PostgreSQL privileges applied to the target object.',
  ensure: 'Whether this privilege must be present or absent.',
  scope: 'The schema or global scope for a default privilege.',
  object: 'The database object targeted by this grant.',
  login: 'Whether PostgreSQL allows this role to log in.',
  inherit: 'Whether ordinary privileges flow automatically across this edge.',
  admin: 'Whether the member may administer membership in the granted role.',
}

function addRange(ranges, node, className, title) {
  if (!node?.range) return
  ranges.push({
    start: node.range[0],
    end: node.range[1],
    className,
    title,
  })
}

function isDynamicKey(path) {
  const currentPath = normalizedPath(path)
  return (
    currentPath === 'profiles' ||
    currentPath === 'profiles.$profile.config' ||
    currentPath === 'roles.*.config'
  )
}

function normalizedPath(path) {
  const normalized = [...path]
  if (normalized[0] === 'profiles' && normalized.length > 1) {
    normalized[1] = '$profile'
  }
  return normalized.join('.')
}

function isAllowedField(key, path, parent) {
  if (normalizedPath(path) === 'auth_providers.*' && isMap(parent)) {
    const providerType = parent.items.find(
      (pair) => isScalar(pair.key) && pair.key.value === 'type'
    )?.value?.value
    return (
      authProviderFields.get(String(providerType))?.has(key) || key === 'type'
    )
  }

  return fieldsByPath.get(normalizedPath(path))?.has(key) || false
}

function keyDecoration(key, path, parent) {
  if (path.length === 0 && topLevelFields.has(key)) {
    return {
      className: 'pgroles-section',
      title: fieldHelp[key] || `pgroles policy section: ${key}`,
      recognized: true,
    }
  }

  if (isDynamicKey(path)) {
    // `profiles.$profile.config` keys are configuration parameters too, so
    // decide by the `.config` suffix rather than the first path segment.
    return {
      className: 'pgroles-identifier',
      title: normalizedPath(path).endsWith('.config')
        ? 'PostgreSQL configuration parameter.'
        : 'Reusable pgroles profile name.',
      recognized: true,
    }
  }

  if (key === 'on' && isAllowedField(key, path, parent)) {
    return {
      className: 'pgroles-deprecated',
      title: 'Legacy alias. Prefer the canonical object field.',
      recognized: true,
    }
  }

  if (isAllowedField(key, path, parent)) {
    return {
      className: 'pgroles-field',
      title: fieldHelp[key] || `Recognized pgroles field: ${key}`,
      recognized: true,
    }
  }

  return {
    className: 'pgroles-unrecognized',
    title: 'Unrecognized field. pgroles currently ignores unknown YAML keys.',
    recognized: false,
  }
}

function valueDecoration(key, path) {
  if (key === 'privileges') {
    return {
      className: 'pgroles-privilege',
      title: 'PostgreSQL privilege managed by this policy.',
    }
  }
  if (key === 'type' || key === 'on_type' || key === 'ensure') {
    return {
      className: 'pgroles-enum',
      title: 'pgroles object or provider type.',
    }
  }
  if (roleReferenceFields.has(key)) {
    return {
      className: 'pgroles-role-ref',
      title: 'PostgreSQL role reference.',
    }
  }
  if (key === 'schema') {
    return {
      className: 'pgroles-schema-ref',
      title: 'PostgreSQL schema reference.',
    }
  }
  if (key === 'profiles') {
    return {
      className: 'pgroles-profile-ref',
      title: 'Reusable pgroles profile reference.',
    }
  }

  if (key === 'name') {
    if (path[0] === 'roles' || path[0] === 'memberships') {
      return {
        className: 'pgroles-role-ref',
        title: 'PostgreSQL role name.',
      }
    }
    if (path[0] === 'schemas') {
      return {
        className: 'pgroles-schema-ref',
        title: 'PostgreSQL schema name.',
      }
    }
    if (
      path[0] === 'grants' ||
      (path[0] === 'profiles' && path.includes('object'))
    ) {
      return {
        className: 'pgroles-object-ref',
        title: 'PostgreSQL object name.',
      }
    }
  }

  return null
}

function addScalarValues(ranges, node, decoration) {
  if (!decoration || !node) return
  if (isScalar(node)) {
    addRange(ranges, node, decoration.className, decoration.title)
    return
  }
  if (isSeq(node)) {
    node.items.forEach((item) => addScalarValues(ranges, item, decoration))
  }
}

function walkNode(ranges, node, path = []) {
  if (isMap(node)) {
    node.items.forEach((pair) => {
      const key = isScalar(pair.key) ? String(pair.key.value) : null
      if (!key) return

      const keyStyle = keyDecoration(key, path, node)
      addRange(ranges, pair.key, keyStyle.className, keyStyle.title)
      if (keyStyle.recognized) {
        addScalarValues(ranges, pair.value, valueDecoration(key, path))
      }
      walkNode(ranges, pair.value, [...path, key])
    })
    return
  }

  if (isSeq(node)) {
    node.items.forEach((item) => walkNode(ranges, item, [...path, '*']))
  }
}

export function getPgrolesSemanticRanges(code) {
  const document = parseDocument(code, { keepSourceTokens: true })
  const ranges = []

  if (document.contents) walkNode(ranges, document.contents)

  return {
    ranges: ranges.sort((left, right) => left.start - right.start),
    errors: document.errors.map((error) => error.message),
  }
}

export function splitSemanticToken(token, start, ranges) {
  const end = start + token.content.length
  const overlaps = ranges.filter(
    (range) => range.start < end && range.end > start
  )
  if (overlaps.length === 0) return [{ token, start }]

  const boundaries = new Set([start, end])
  overlaps.forEach((range) => {
    boundaries.add(Math.max(start, range.start))
    boundaries.add(Math.min(end, range.end))
  })
  const ordered = [...boundaries].sort((left, right) => left - right)

  return ordered.slice(0, -1).map((pieceStart, index) => {
    const pieceEnd = ordered[index + 1]
    const semantic = overlaps.find(
      (range) => range.start <= pieceStart && range.end >= pieceEnd
    )

    return {
      start: pieceStart,
      token: {
        ...token,
        content: token.content.slice(pieceStart - start, pieceEnd - start),
        semanticClassName: semantic?.className,
        semanticTitle: semantic?.title,
      },
    }
  })
}
