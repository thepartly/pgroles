const SCHEMA_VERSION = 'pgroles.explorer.v1'
const REVIEW_SCHEMA_VERSION = 'pgroles.review-artifact.v2'
const RETIRED_REVIEW_SCHEMA_VERSIONS = ['pgroles.review-artifact.v1']
export const MAX_SNAPSHOT_FILE_BYTES = 4_194_304
export const DEFAULT_PG_MAJOR_VERSION = 16
export const PG_MAJOR_VERSION_CHOICES = Object.freeze([15, 16, 17, 18])

// Inlined by next.config.js from the WASM asset contents so a deploy can never
// pair cached JavaScript glue with a different binary. Empty outside Next.
export const WASM_BUILD_ID = (typeof process !== 'undefined' && process.env.NEXT_PUBLIC_PGROLES_BUILD_ID) || ''

let enginePromise
let failedEngineLoads = 0

export function wasmAssetUrls(basePath = '', buildId = WASM_BUILD_ID) {
  const version = buildId ? `?v=${encodeURIComponent(buildId)}` : ''
  return {
    module: `${basePath}/wasm/pgroles_wasm.js${version}`,
    binary: `${basePath}/wasm/pgroles_wasm_bg.wasm${version}`,
  }
}

export function wasmModuleUrl(basePath = '', buildId = WASM_BUILD_ID) {
  return wasmAssetUrls(basePath, buildId).module
}

function retryableModuleUrl(url, attempt) {
  // Browsers cache a failed module fetch for the lifetime of the document, so
  // a retry after a network failure must import a distinct URL.
  if (attempt === 0) return url
  return `${url}${url.includes('?') ? '&' : '?'}retry=${attempt}`
}

export function loadPolicyEngine(basePath = '', importer = (url) => import(/* webpackIgnore: true */ url), buildId = WASM_BUILD_ID) {
  if (!enginePromise) {
    const urls = wasmAssetUrls(basePath, buildId)
    enginePromise = importer(retryableModuleUrl(urls.module, failedEngineLoads))
      .then(async (module) => {
        // wasm-bindgen resolves its default binary with new URL(..., import.meta.url),
        // which drops the version query, so pass the versioned binary explicitly.
        await module.default({ module_or_path: urls.binary })
        return module
      })
      .catch((error) => {
        enginePromise = undefined
        failedEngineLoads += 1
        throw error
      })
  }
  return enginePromise
}

export async function loadAnalyzer(basePath = '', importer, buildId) {
  return (await loadPolicyEngine(basePath, importer, buildId)).analyze
}

export function policyRequest(desiredYaml) {
  return { schema_version: 'pgroles.policy.v1', desired_yaml: desiredYaml }
}

export function resetAnalyzerForTests() {
  enginePromise = undefined
  failedEngineLoads = 0
}

export function analyzeRequest({
  current,
  desiredYaml,
  mode,
  pgMajorVersion = DEFAULT_PG_MAJOR_VERSION,
  authorityGraphComplete = true,
  executorRole,
  executorSuperuser = false,
  executorCreaterole = 'unknown',
  executorMemberships = [],
  newMembershipSetRole = 'unknown',
  newRoleSetRole = 'unknown',
  newRoleInherit = 'unknown',
  newRoleAdminOption = 'unknown',
}) {
  return {
    schema_version: SCHEMA_VERSION,
    current,
    desired_yaml: desiredYaml,
    mode,
    pg_major_version: pgMajorVersion,
    authority_graph_complete: authorityGraphComplete,
    executor: {
      role: executorRole,
      superuser: executorSuperuser,
      createrole: executorCreaterole,
      memberships: executorMemberships,
      new_membership_set_role: newMembershipSetRole,
      new_role_set_role: newRoleSetRole,
      new_role_inherit: newRoleInherit,
      new_role_admin_option: newRoleAdminOption,
    },
  }
}

export function readableWasmError(error) {
  if (typeof error === 'string') return error
  if (error instanceof Error && error.message) return error.message
  return String(error)
}

export function explorerImport(value) {
  if (value?.schema_version && value.schema_version !== SCHEMA_VERSION) {
    throw new Error(`unsupported explorer schema version: ${value.schema_version}`)
  }
  const envelope = value && typeof value === 'object' && !Array.isArray(value) && Object.hasOwn(value, 'current')
  const imported = { current: envelope ? value.current : value, executor: envelope ? value.executor : undefined }
  if (envelope && value.pg_major_version != null) {
    if (!Number.isSafeInteger(value.pg_major_version)) {
      throw new Error('snapshot pg_major_version must be an integer PostgreSQL major version')
    }
    imported.pgMajorVersion = value.pg_major_version
  }
  if (envelope && value.authority_graph_complete != null) {
    if (typeof value.authority_graph_complete !== 'boolean') {
      throw new Error('snapshot authority_graph_complete must be true or false')
    }
    imported.authorityGraphComplete = value.authority_graph_complete
  }
  return imported
}

export function validateSnapshotFileSize(size) {
  if (size > MAX_SNAPSHOT_FILE_BYTES) {
    throw new Error(`snapshot file is ${size} bytes; limit is ${MAX_SNAPSHOT_FILE_BYTES} bytes`)
  }
}

export function validateReviewArtifactFileSize(size) {
  if (size > MAX_SNAPSHOT_FILE_BYTES) {
    throw new Error(`review artifact file is ${size} bytes; limit is ${MAX_SNAPSHOT_FILE_BYTES} bytes`)
  }
}

// ---------------------------------------------------------------------------
// Change labels shared by live analysis ({ Grant: {...} }) and recorded
// reviews ({ kind: 'grant', ... }).
// ---------------------------------------------------------------------------

function snakeCase(value) {
  return String(value).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()
}

function sentence(value) {
  const words = snakeCase(value).replaceAll('_', ' ').trim()
  return words.replace(/^./, (letter) => letter.toUpperCase())
}

function text(value) {
  return value == null ? '' : String(value)
}

function objectLabel({ object_type: objectType, schema, name }) {
  const type = text(objectType).replaceAll('_', ' ')
  if (objectType === 'schema') return `schema ${text(name ?? schema)}`
  if (objectType === 'database') return `database ${text(name)}`
  if (name === '*' && schema != null) return `all ${type}s in ${text(schema)}`
  const qualified = schema != null && name != null ? `${text(schema)}.${text(name)}` : text(name ?? schema)
  return `${type} ${qualified}`.trim()
}

function defaultPrivilegeLabel({ owner, scope, on_type: onType, grantee }) {
  const location = scope?.type === 'schema' ? ` in ${text(scope.schema)}` : ''
  return `${text(owner)} ${text(onType).replaceAll('_', ' ')}s${location} → ${text(grantee)}`
}

export function changeParts(change) {
  if (change && typeof change === 'object' && typeof change.kind === 'string') return [change.kind, change]
  const [kind, detail] = Object.entries(change ?? {})[0] ?? ['change', {}]
  return [snakeCase(kind), detail && typeof detail === 'object' ? detail : {}]
}

export function describeChange(change) {
  const [kind, detail] = changeParts(change)
  const title = sentence(kind)
  const subject = (() => {
    switch (kind) {
      case 'create_schema': return detail.owner ? `${text(detail.name)} owned by ${text(detail.owner)}` : text(detail.name)
      case 'alter_schema_owner': return `${text(detail.name)} → ${text(detail.owner)}`
      case 'ensure_schema_owner_privileges': return `${text(detail.name)} for ${text(detail.owner)}`
      case 'grant':
      case 'revoke': return `${objectLabel(detail)} → ${text(detail.role)}`
      case 'set_default_privilege':
      case 'revoke_default_privilege': return defaultPrivilegeLabel(detail)
      case 'add_member': return `${text(detail.member)} to ${text(detail.role)}`
      case 'remove_member': return `${text(detail.member)} from ${text(detail.role)}`
      case 'reassign_owned': return `${text(detail.from_role)} → ${text(detail.to_role)}`
      case 'drop_owned':
      case 'terminate_sessions': return text(detail.role)
      default: return text(detail.name ?? detail.role ?? detail.owner)
    }
  })()
  return subject ? `${title} · ${subject}` : title
}

// ---------------------------------------------------------------------------
// Recorded review artifacts (pgroles.review-artifact.v2)
// ---------------------------------------------------------------------------

const MODES = ['authoritative', 'additive', 'adopt']
const PREFLIGHT_CHECKS = ['executor_authority', 'role_drop_safety', 'server_compatibility']
const EVIDENCE_CHECKS = ['default_privilege_owner', 'predefined_role_membership', 'grantor_reachability', 'revoke_acl_ownership', 'plan_order_authority', 'drop_role_safety']
const EVIDENCE_STATUSES = ['passed', 'failed', 'not_run', 'unknown']
const COVERAGE_KINDS = ['complete', 'targeted']
const PRIORITIES = ['High', 'Review', 'Informational']
const PHASES = ['create', 'alter', 'grant', 'membership_remove', 'membership_add', 'revoke', 'default_privilege_revoke', 'retire']
const REACHABILITY_STATUSES = ['reachable', 'unreachable', 'unknown']
const FINDING_SEVERITIES = ['info', 'warning', 'error']
const OBJECT_TYPES = ['table', 'view', 'materialized_view', 'sequence', 'function', 'schema', 'database', 'type']
const PRIVILEGES = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'EXECUTE', 'USAGE', 'CREATE', 'CONNECT', 'TEMPORARY']
const ROLE_FLAGS = ['login', 'superuser', 'createdb', 'createrole', 'inherit', 'replication', 'bypassrls']
const NODE_KINDS = ['role', 'external_principal', 'grant_target', 'default_privilege_target']
const EDGE_KINDS = ['membership', 'grant', 'default_privilege']
const VISUAL_SOURCES = ['desired', 'current']
const VISUAL_COUNTS = ['role_count', 'grant_count', 'default_privilege_count', 'membership_count']

// Closed key sets. `fields` maps each permitted key to the shape of its value
// (null for scalars and scalar lists); `tag` shapes are internally tagged enums.
const scalar = null
const fields = (entries) => Object.freeze({ fields: Object.freeze(entries) })
const list = (item) => Object.freeze({ list: item })
const tagged = (tag, variants) => Object.freeze({ tag, variants: Object.freeze(variants) })
const keys = (...names) => Object.fromEntries(names.map((name) => [name, scalar]))

const identityShape = fields(keys('role', 'superuser'))
const managedScopeShape = fields({ roles: scalar, schemas: list(fields(keys('name', 'owner', 'bindings'))) })
const scopeShape = tagged('type', { global: {}, schema: keys('schema') })
const roleStateShape = fields(keys(...ROLE_FLAGS, 'connection_limit', 'comment_present', 'password_valid_until', 'config_parameters'))
const roleAttributeShape = tagged('kind', {
  ...Object.fromEntries(ROLE_FLAGS.map((flag) => [flag, keys('value')])),
  connection_limit: keys('value'),
  valid_until: keys('value'),
  set_config: keys('parameter'),
  reset_config: keys('parameter'),
})
const privilegeTarget = keys('role', 'privileges', 'object_type', 'schema', 'name')
const defaultPrivilegeTarget = { ...keys('owner', 'on_type', 'grantee', 'privileges'), scope: scopeShape }
const reviewChangeShape = tagged('kind', {
  create_role: { name: scalar, state: roleStateShape },
  create_schema: keys('name', 'owner'),
  alter_schema_owner: keys('name', 'owner'),
  ensure_schema_owner_privileges: keys('name', 'owner', 'privileges'),
  alter_role: { name: scalar, attributes: list(roleAttributeShape) },
  set_comment: keys('name', 'comment_present'),
  grant: privilegeTarget,
  revoke: { ...privilegeTarget, grantor: scalar },
  set_default_privilege: defaultPrivilegeTarget,
  revoke_default_privilege: defaultPrivilegeTarget,
  add_member: keys('role', 'member', 'inherit', 'admin'),
  remove_member: keys('role', 'member', 'grantor'),
  reassign_owned: keys('from_role', 'to_role'),
  drop_owned: keys('role'),
  terminate_sessions: keys('role'),
  set_password: keys('name'),
  drop_role: keys('name'),
})
const managedKeyShape = tagged('kind', {
  role: keys('name'),
  schema_facet: keys('schema', 'facet'),
  grant: keys('role', 'object_type', 'schema', 'name'),
  default_privilege: { ...keys('owner', 'on_type', 'grantee'), scope: scopeShape },
  membership: keys('role', 'member'),
})
const omissionShape = fields(keys('field', 'reason'))
const reachabilityDeltaShape = fields({ changed: list(fields(keys('role', 'status'))), removed: scalar })

export const REVIEW_ARTIFACT_SHAPE = fields({
  schema_version: scalar,
  provenance: fields({ ...keys('tool_version', 'captured_at', 'target_label', 'pg_major_version'), policy: fields(keys('content_digest', 'commit')) }),
  context: fields({ ...keys('mode', 'authority_graph_complete'), managed_scope: managedScopeShape, inspector: identityShape, intended_executor: identityShape }),
  preflight: list(fields({
    ...keys('check', 'status', 'actor_role', 'issue_count'),
    issues: list(fields(keys('code', 'message', 'role'))),
    coverage: fields(keys('kind', 'checks_performed', 'checked_change_indices', 'unchecked_change_indices')),
  })),
  recorded: fields({
    changes: list(fields({ ...keys('index', 'priority'), source: fields({ document: scalar, managed_key: managedKeyShape }), change: reviewChangeShape, omissions: list(omissionShape) })),
    phases: list(fields({ ...keys('phase', 'change_indices'), executor_reachability_delta: reachabilityDeltaShape, executor_usage_delta: reachabilityDeltaShape })),
    findings: list(fields(keys('kind', 'severity', 'phase', 'change_index', 'change_indices', 'role', 'message'))),
    // Visual nodes never carry comments in an export: role comments can hold credentials.
    visual: fields({
      schema_version: scalar,
      meta: fields({ ...keys('source', 'role_count', 'grant_count', 'default_privilege_count', 'membership_count', 'collapsed'), managed_scope: managedScopeShape }),
      nodes: list(fields(keys('id', 'label', 'kind', 'managed', 'login', 'privileges'))),
      edges: list(fields(keys('source', 'target', 'kind', 'label'))),
    }),
    sql_preview: tagged('status', { available: keys('sql'), omitted: keys('reason', 'sensitive_change_indices') }),
    omissions: list(omissionShape),
    review_fingerprint: scalar,
  }),
  exploration: tagged('status', { omitted: keys('reason') }),
})

export const REVIEW_ARTIFACT_ENUMS = Object.freeze({
  modes: MODES,
  changeKinds: Object.keys(reviewChangeShape.variants),
  preflightChecks: PREFLIGHT_CHECKS,
  evidenceChecks: EVIDENCE_CHECKS,
  evidenceStatuses: EVIDENCE_STATUSES,
  coverageKinds: COVERAGE_KINDS,
  priorities: PRIORITIES,
  phases: PHASES,
  reachabilityStatuses: REACHABILITY_STATUSES,
  findingSeverities: FINDING_SEVERITIES,
  objectTypes: OBJECT_TYPES,
  privileges: PRIVILEGES,
  nodeKinds: NODE_KINDS,
  edgeKinds: EDGE_KINDS,
  visualSources: VISUAL_SOURCES,
})

const FORBIDDEN_FIELD_NAMES = new Set(['password', 'database_url', 'url'])
const FORBIDDEN_FIELD_PATTERN = /secret|token|verifier/i

function displayKey(key) {
  return JSON.stringify(key.length > 64 ? `${key.slice(0, 61)}...` : key)
}

function isObject(candidate) {
  return candidate !== null && typeof candidate === 'object' && !Array.isArray(candidate)
}

// Iterative so a deeply nested file cannot exhaust the call stack.
function rejectCredentialFields(value) {
  const pending = [[value, '$']]
  while (pending.length > 0) {
    const [node, path] = pending.pop()
    if (Array.isArray(node)) {
      node.forEach((item, index) => pending.push([item, `${path}[${index}]`]))
    } else if (isObject(node)) {
      for (const [key, child] of Object.entries(node)) {
        if (FORBIDDEN_FIELD_NAMES.has(key.toLowerCase()) || FORBIDDEN_FIELD_PATTERN.test(key)) {
          throw new Error(`review artifact contains credential-like field ${displayKey(key)} at ${path}; recorded reviews must not carry secrets`)
        }
        pending.push([child, `${path}.${key}`])
      }
    }
  }
}

function rejectUnknownFields(value, shape, path) {
  if (shape === scalar || value == null) return
  if (shape.list) {
    if (Array.isArray(value)) value.forEach((item, index) => rejectUnknownFields(item, shape.list, `${path}[${index}]`))
    return
  }
  if (!isObject(value)) return
  let permitted = shape.fields
  if (shape.tag) {
    const variant = value[shape.tag]
    // An unknown tag is rejected by the structural checks with a clearer message.
    if (typeof variant !== 'string' || !Object.hasOwn(shape.variants, variant)) return
    permitted = { [shape.tag]: scalar, ...shape.variants[variant] }
  }
  for (const [key, child] of Object.entries(value)) {
    if (!Object.hasOwn(permitted, key)) {
      throw new Error(`review artifact has unknown field ${displayKey(key)} at ${path}`)
    }
    rejectUnknownFields(child, permitted[key], `${path}.${key}`)
  }
}

const utf8 = new TextEncoder()

// Rust orders role names by their UTF-8 bytes, which differs from JavaScript's
// UTF-16 comparison outside the Basic Multilingual Plane.
function compareUtf8(left, right) {
  const a = utf8.encode(left)
  const b = utf8.encode(right)
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index]
  }
  return a.length - b.length
}

const strictlyAscending = (roles) => roles.every((role, index) => index === 0 || compareUtf8(roles[index - 1], role) < 0)

// Mirrors the CLI's parse_review_artifact: both lists are sorted, unique, and
// disjoint; `removed` names only roles present before the phase; and `changed`
// never repeats a role's previous status.
function foldDelta(state, delta) {
  if (!isObject(delta) || !Array.isArray(delta.changed) || !Array.isArray(delta.removed)) return null
  const changed = delta.changed.map((entry) => (isObject(entry) && typeof entry.role === 'string' && REACHABILITY_STATUSES.includes(entry.status) ? entry : null))
  if (changed.includes(null) || !delta.removed.every((role) => typeof role === 'string')) return null
  if (!strictlyAscending(changed.map((entry) => entry.role)) || !strictlyAscending(delta.removed)) return null
  const changedRoles = new Set(changed.map((entry) => entry.role))
  if (delta.removed.some((role) => changedRoles.has(role) || !state.has(role))) return null
  if (changed.some((entry) => state.get(entry.role) === entry.status)) return null
  const next = new Map(state)
  for (const role of delta.removed) next.delete(role)
  for (const entry of changed) next.set(entry.role, entry.status)
  return next
}

function sortedEntries(state) {
  return [...state].sort(([left], [right]) => compareUtf8(left, right)).map(([role, status]) => ({ role, status }))
}

/**
 * Rebuilds each phase's full executor reachability (SET ROLE) and usage
 * (inherited privileges) from the recorded deltas. The state before the first
 * phase is empty. Throws when a delta is malformed or removes an absent role.
 */
export function foldRecordedPhaseReachability(phases) {
  let reachability = new Map()
  let usage = new Map()
  return phases.map((phase, index) => {
    reachability = foldDelta(reachability, phase?.executor_reachability_delta)
    usage = foldDelta(usage, phase?.executor_usage_delta)
    if (!reachability || !usage) {
      throw new Error(`review artifact phase ${index + 1} reachability delta is malformed`)
    }
    return { executor_reachability: sortedEntries(reachability), executor_usage: sortedEntries(usage) }
  })
}

export function reviewArtifactImport(value) {
  const isString = (candidate) => typeof candidate === 'string'
  const isOneOf = (candidate, allowed) => isString(candidate) && allowed.includes(candidate)
  const isBoolean = (candidate) => typeof candidate === 'boolean'
  const hashPattern = /^sha256:[0-9a-f]{64}$/
  if (!isObject(value)) {
    throw new Error('review artifact must be a JSON object')
  }
  if (RETIRED_REVIEW_SCHEMA_VERSIONS.includes(value.schema_version)) {
    throw new Error(`review artifact schema version ${value.schema_version} is no longer supported; re-export the review with the current pgroles CLI to produce ${REVIEW_SCHEMA_VERSION}`)
  }
  if (value.schema_version !== REVIEW_SCHEMA_VERSION) {
    throw new Error(`unsupported review artifact schema version: ${value.schema_version ?? 'missing'}`)
  }
  rejectCredentialFields(value)
  // Checked before the closed-key pass so an available preview that also names
  // sensitive changes is reported as the contradiction it is.
  const preview = value.recorded?.sql_preview
  const sensitiveChanges = (Array.isArray(value.recorded?.changes) ? value.recorded.changes : [])
    .filter((entry) => Array.isArray(entry?.omissions) && entry.omissions.length > 0)
    .map((entry) => entry.index)
  if (isObject(preview) && preview.status === 'available' && (sensitiveChanges.length > 0 || (Array.isArray(preview.sensitive_change_indices) && preview.sensitive_change_indices.length > 0))) {
    throw new Error('review artifact SQL preview is available although changes omit sensitive values')
  }
  rejectUnknownFields(value, REVIEW_ARTIFACT_SHAPE, '$')
  if (!isObject(value.provenance) || !isObject(value.context) || !isObject(value.recorded) || !isObject(value.exploration)) {
    throw new Error('review artifact is missing provenance, context, recorded, or exploration data')
  }
  if (!isString(value.provenance.tool_version) || !isString(value.provenance.captured_at) || !isString(value.provenance.target_label) || !Number.isSafeInteger(value.provenance.pg_major_version) || !isObject(value.provenance.policy) || !hashPattern.test(value.provenance.policy.content_digest)) {
    throw new Error('review artifact provenance is malformed')
  }
  if (value.provenance.policy.commit != null && !isString(value.provenance.policy.commit)) {
    throw new Error('review artifact policy provenance is malformed')
  }
  if (!isOneOf(value.context.mode, MODES) || !isBoolean(value.context.authority_graph_complete) || !isObject(value.context.inspector) || !isString(value.context.inspector.role) || !isObject(value.context.intended_executor) || !isString(value.context.intended_executor.role)) {
    throw new Error('review artifact execution context is malformed')
  }
  if (![value.context.inspector.superuser, value.context.intended_executor.superuser].every((entry) => entry == null || isBoolean(entry))) {
    throw new Error('review artifact execution identity is malformed')
  }
  const isStringList = (candidate) => Array.isArray(candidate) && candidate.every(isString)
  const isManagedScope = (scope) => isObject(scope) && isStringList(scope.roles) && Array.isArray(scope.schemas) && scope.schemas.every((schema) => isObject(schema) && isString(schema.name) && isBoolean(schema.owner) && isBoolean(schema.bindings))
  if (value.context.managed_scope != null && !isManagedScope(value.context.managed_scope)) {
    throw new Error('review artifact managed scope is malformed')
  }
  if (!Array.isArray(value.preflight) || !Array.isArray(value.recorded.changes) || !Array.isArray(value.recorded.phases) || !Array.isArray(value.recorded.findings)) {
    throw new Error('review artifact recorded collections are malformed')
  }
  const isPreflightIssue = (issue) => isObject(issue) && isString(issue.code) && isString(issue.message) && (issue.role == null || isString(issue.role))
  const isPreflight = (item) => isObject(item)
    && isOneOf(item.check, PREFLIGHT_CHECKS)
    && isOneOf(item.status, EVIDENCE_STATUSES)
    && (item.actor_role == null || isString(item.actor_role))
    && Number.isSafeInteger(item.issue_count) && item.issue_count >= 0
    && (item.issues == null ? item.issue_count === 0 : Array.isArray(item.issues) && item.issues.length === item.issue_count && item.issues.every(isPreflightIssue))
    && isObject(item.coverage)
    && isOneOf(item.coverage.kind, COVERAGE_KINDS)
    && Array.isArray(item.coverage.checks_performed) && item.coverage.checks_performed.every((check) => isOneOf(check, EVIDENCE_CHECKS))
    && Array.isArray(item.coverage.checked_change_indices)
    && Array.isArray(item.coverage.unchecked_change_indices)
    && !(item.check === 'executor_authority' && item.coverage.kind === 'targeted' && item.status === 'passed')
  if (!value.preflight.every(isPreflight)) {
    throw new Error('review artifact preflight evidence is malformed')
  }
  if (value.preflight.some((item) => item.check === 'executor_authority' && item.coverage.kind === 'complete' && item.coverage.checks_performed.length === 0)) {
    throw new Error('review artifact claims complete executor authority coverage without any recorded checks')
  }
  const isOptionalString = (candidate) => candidate == null || isString(candidate)
  const isPrivileges = (candidate) => Array.isArray(candidate) && candidate.every((privilege) => isOneOf(privilege, PRIVILEGES))
  const isRoleState = (state) => isObject(state)
    && [...ROLE_FLAGS, 'comment_present'].every((field) => isBoolean(state[field]))
    && Number.isSafeInteger(state.connection_limit)
    && isOptionalString(state.password_valid_until)
    && isStringList(state.config_parameters)
  const isRoleAttribute = (attribute) => {
    if (!isObject(attribute) || !isString(attribute.kind)) return false
    if (ROLE_FLAGS.includes(attribute.kind)) return isBoolean(attribute.value)
    if (attribute.kind === 'connection_limit') return Number.isSafeInteger(attribute.value)
    if (attribute.kind === 'valid_until') return isOptionalString(attribute.value)
    return ['set_config', 'reset_config'].includes(attribute.kind) && isString(attribute.parameter)
  }
  const isScope = (scope) => isObject(scope) && (scope.type === 'global' || (scope.type === 'schema' && isString(scope.schema)))
  const isReviewChange = (change) => {
    if (!isObject(change) || !isString(change.kind)) return false
    const named = () => isString(change.name)
    const privilegeChange = () => isString(change.role) && isPrivileges(change.privileges) && isOneOf(change.object_type, OBJECT_TYPES) && isOptionalString(change.schema) && isOptionalString(change.name)
    const defaultPrivilege = () => isString(change.owner) && isScope(change.scope) && isOneOf(change.on_type, OBJECT_TYPES) && isString(change.grantee) && isPrivileges(change.privileges)
    switch (change.kind) {
      case 'create_role': return named() && isRoleState(change.state)
      case 'create_schema': return named() && isOptionalString(change.owner)
      case 'alter_schema_owner': return named() && isString(change.owner)
      case 'ensure_schema_owner_privileges': return named() && isString(change.owner) && isPrivileges(change.privileges)
      case 'alter_role': return named() && Array.isArray(change.attributes) && change.attributes.every(isRoleAttribute)
      case 'set_comment': return named() && isBoolean(change.comment_present)
      case 'grant': return privilegeChange()
      case 'revoke': return privilegeChange() && isOptionalString(change.grantor)
      case 'set_default_privilege':
      case 'revoke_default_privilege': return defaultPrivilege()
      case 'add_member': return isString(change.role) && isString(change.member) && isBoolean(change.inherit) && isBoolean(change.admin)
      case 'remove_member': return isString(change.role) && isString(change.member) && isOptionalString(change.grantor)
      case 'reassign_owned': return isString(change.from_role) && isString(change.to_role)
      case 'drop_owned':
      case 'terminate_sessions': return isString(change.role)
      case 'set_password':
      case 'drop_role': return named()
      default: return false
    }
  }
  const isSource = (source) => {
    if (!isObject(source) || !isString(source.document) || !isObject(source.managed_key)) return false
    const key = source.managed_key
    if (key.kind === 'role') return isString(key.name)
    if (key.kind === 'schema_facet') return isString(key.schema) && isOneOf(key.facet, ['owner', 'bindings'])
    if (key.kind === 'grant') return isString(key.role) && isOneOf(key.object_type, OBJECT_TYPES) && isOptionalString(key.schema) && isOptionalString(key.name)
    if (key.kind === 'default_privilege') return isString(key.owner) && isScope(key.scope) && isOneOf(key.on_type, OBJECT_TYPES) && isString(key.grantee)
    return key.kind === 'membership' && isString(key.role) && isString(key.member)
  }
  const isOmission = (omission) => isObject(omission) && isString(omission.field) && omission.reason === 'sensitive_value'
  if (!value.recorded.changes.every((entry) => isObject(entry) && Number.isSafeInteger(entry.index) && entry.index >= 0 && isOneOf(entry.priority, PRIORITIES) && isReviewChange(entry.change) && (entry.source == null || isSource(entry.source)) && (entry.omissions == null || (Array.isArray(entry.omissions) && entry.omissions.every(isOmission))))) {
    throw new Error('review artifact changes are malformed')
  }
  const changeIndices = new Set(value.recorded.changes.map((entry) => entry.index))
  const contiguousIndices = value.recorded.changes.every((entry, index) => entry.index === index)
  const isCoverage = (coverage) => {
    const checked = coverage.checked_change_indices
    const unchecked = coverage.unchecked_change_indices
    const all = [...checked, ...unchecked]
    return all.length === value.recorded.changes.length
      && new Set(all).size === all.length
      && all.every((index) => changeIndices.has(index))
      && new Set(coverage.checks_performed).size === coverage.checks_performed.length
      && (coverage.kind !== 'complete' || unchecked.length === 0)
  }
  if (!value.preflight.every((item) => isCoverage(item.coverage))) {
    throw new Error('review artifact preflight coverage is malformed')
  }
  const orderedPhaseIndices = value.recorded.phases.flatMap((phase) => (Array.isArray(phase?.change_indices) ? phase.change_indices : []))
  const phasePartition = orderedPhaseIndices.length === value.recorded.changes.length && orderedPhaseIndices.every((index, position) => index === position)
  if (!contiguousIndices || changeIndices.size !== value.recorded.changes.length || (value.recorded.changes.length > 0 && value.recorded.phases.length === 0) || !phasePartition || !value.recorded.phases.every((phase) => isObject(phase) && isOneOf(phase.phase, PHASES) && Array.isArray(phase.change_indices) && phase.change_indices.length > 0 && phase.change_indices.every((index) => Number.isSafeInteger(index) && changeIndices.has(index)))) {
    throw new Error('review artifact phases are malformed')
  }
  foldRecordedPhaseReachability(value.recorded.phases)
  // Aggregated findings list every affected change; change_index stays the first of them.
  const isFindingChanges = (finding) => finding.change_indices == null || (
    Array.isArray(finding.change_indices)
    && finding.change_indices.length > 0
    && finding.change_indices.every((index) => changeIndices.has(index))
    && new Set(finding.change_indices).size === finding.change_indices.length
    && (finding.change_index == null || finding.change_index === finding.change_indices[0])
  )
  if (!value.recorded.findings.every((finding) => isObject(finding) && isString(finding.kind) && isOneOf(finding.severity, FINDING_SEVERITIES) && isString(finding.message) && (finding.phase == null || isOneOf(finding.phase, PHASES)) && (finding.change_index == null || changeIndices.has(finding.change_index)) && isFindingChanges(finding) && isOptionalString(finding.role))) {
    throw new Error('review artifact findings are malformed')
  }
  // The closed-key pass admits only schema keys; the viewer also relies on
  // the kinds, flags, and counts having the schema's types.
  const visual = value.recorded.visual
  if (!isObject(visual) || !isString(visual.schema_version) || !isObject(visual.meta) || !Array.isArray(visual.nodes) || !Array.isArray(visual.edges)) {
    throw new Error('review artifact visual graph is malformed')
  }
  const isCount = (candidate) => Number.isSafeInteger(candidate) && candidate >= 0
  const isOptionalBoolean = (candidate) => candidate == null || isBoolean(candidate)
  if (!isOneOf(visual.meta.source, VISUAL_SOURCES) || !VISUAL_COUNTS.every((field) => isCount(visual.meta[field])) || !isBoolean(visual.meta.collapsed) || (visual.meta.managed_scope != null && !isManagedScope(visual.meta.managed_scope))) {
    throw new Error('review artifact visual metadata is malformed')
  }
  const isVisualNode = (node) => isObject(node) && isString(node.id) && isOneOf(node.kind, NODE_KINDS) && isString(node.label) && isOptionalBoolean(node.managed) && isOptionalBoolean(node.login) && (node.privileges == null || isStringList(node.privileges))
  const isVisualEdge = (edge) => isObject(edge) && isString(edge.source) && isString(edge.target) && isOneOf(edge.kind, EDGE_KINDS) && isString(edge.label)
  if (!visual.nodes.every(isVisualNode) || !visual.edges.every(isVisualEdge)) {
    throw new Error('review artifact visual graph entries are malformed')
  }
  if (!hashPattern.test(value.recorded.review_fingerprint)) {
    throw new Error('review artifact fingerprint is malformed')
  }
  if (value.recorded.omissions != null && (!Array.isArray(value.recorded.omissions) || !value.recorded.omissions.every((omission) => isObject(omission) && isString(omission.field) && isString(omission.reason)))) {
    throw new Error('review artifact omissions are malformed')
  }
  if (!isObject(preview) || !['available', 'omitted'].includes(preview.status)) {
    throw new Error('review artifact SQL preview is malformed')
  }
  if ((preview.status === 'available' && !isString(preview.sql)) || (preview.status === 'omitted' && (preview.reason !== 'sensitive_changes' || !Array.isArray(preview.sensitive_change_indices) || !preview.sensitive_change_indices.every((index) => changeIndices.has(index))))) {
    throw new Error('review artifact SQL preview content is malformed')
  }
  if (preview.status === 'omitted' && (new Set(preview.sensitive_change_indices).size !== preview.sensitive_change_indices.length || preview.sensitive_change_indices.length !== sensitiveChanges.length || !sensitiveChanges.every((index) => preview.sensitive_change_indices.includes(index)))) {
    throw new Error('review artifact SQL preview sensitive changes do not match the recorded omissions')
  }
  if (value.exploration.status !== 'omitted' || !['recorded_only_export', 'sensitive_inputs_removed'].includes(value.exploration.reason)) {
    throw new Error('review artifact exploration status is malformed')
  }
  return value
}
