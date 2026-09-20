const SCHEMA_VERSION = 'pgroles.explorer.v1'
const REVIEW_SCHEMA_VERSION = 'pgroles.review-artifact.v1'
export const MAX_SNAPSHOT_FILE_BYTES = 4_194_304

let enginePromise

export function wasmModuleUrl(basePath = '') {
  return `${basePath}/wasm/pgroles_wasm.js`
}

export function loadPolicyEngine(basePath = '', importer = (url) => import(/* webpackIgnore: true */ url)) {
  enginePromise ??= importer(wasmModuleUrl(basePath))
    .then(async (module) => {
      await module.default()
      return module
    })
    .catch((error) => {
      enginePromise = undefined
      throw error
    })
  return enginePromise
}

export async function loadAnalyzer(basePath = '', importer) {
  return (await loadPolicyEngine(basePath, importer)).analyze
}

export function policyRequest(desiredYaml) {
  return { schema_version: 'pgroles.policy.v1', desired_yaml: desiredYaml }
}

export function resetAnalyzerForTests() {
  enginePromise = undefined
}

export function analyzeRequest({
  current,
  desiredYaml,
  mode,
  executorRole,
  executorSuperuser = false,
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
    executor: {
      role: executorRole,
      superuser: executorSuperuser,
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
  return { current: value?.current ?? value, executor: value?.executor }
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

export function reviewArtifactImport(value) {
  const isObject = (candidate) => candidate && typeof candidate === 'object' && !Array.isArray(candidate)
  const isString = (candidate) => typeof candidate === 'string'
  const isOneOf = (candidate, allowed) => isString(candidate) && allowed.includes(candidate)
  const hashPattern = /^sha256:[0-9a-f]{64}$/
  const modes = ['authoritative', 'additive', 'adopt']
  const checks = ['executor_authority', 'role_drop_safety', 'server_compatibility']
  const evidenceChecks = ['default_privilege_owner', 'predefined_role_membership', 'grantor_reachability', 'revoke_acl_ownership', 'plan_order_authority', 'drop_role_safety']
  const evidenceStatuses = ['passed', 'failed', 'not_run', 'unknown']
  const priorities = ['High', 'Review', 'Informational']
  const phases = ['create', 'alter', 'grant', 'membership_remove', 'membership_add', 'revoke', 'default_privilege_revoke', 'retire']
  const reachabilityStatuses = ['reachable', 'unreachable', 'unknown']
  const findingSeverities = ['info', 'warning', 'error']
  const objectTypes = ['table', 'view', 'materialized_view', 'sequence', 'function', 'schema', 'database', 'type']
  const privileges = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'EXECUTE', 'USAGE', 'CREATE', 'CONNECT', 'TEMPORARY']
  if (!isObject(value)) {
    throw new Error('review artifact must be a JSON object')
  }
  if (value.schema_version !== REVIEW_SCHEMA_VERSION) {
    throw new Error(`unsupported review artifact schema version: ${value.schema_version ?? 'missing'}`)
  }
  if (!value.provenance || !value.context || !value.recorded || !value.exploration) {
    throw new Error('review artifact is missing provenance, context, recorded, or exploration data')
  }
  if (typeof value.provenance.tool_version !== 'string' || typeof value.provenance.captured_at !== 'string' || typeof value.provenance.target_label !== 'string' || !Number.isSafeInteger(value.provenance.pg_major_version) || !hashPattern.test(value.provenance.policy?.content_digest)) {
    throw new Error('review artifact provenance is malformed')
  }
  if (value.provenance.policy.commit != null && !isString(value.provenance.policy.commit)) {
    throw new Error('review artifact policy provenance is malformed')
  }
  if (!isOneOf(value.context.mode, modes) || typeof value.context.authority_graph_complete !== 'boolean' || typeof value.context.inspector?.role !== 'string' || typeof value.context.intended_executor?.role !== 'string') {
    throw new Error('review artifact execution context is malformed')
  }
  if (![value.context.inspector.superuser, value.context.intended_executor.superuser].every((entry) => entry == null || typeof entry === 'boolean')) {
    throw new Error('review artifact execution identity is malformed')
  }
  if (!Array.isArray(value.preflight) || !Array.isArray(value.recorded.changes) || !Array.isArray(value.recorded.phases) || !Array.isArray(value.recorded.findings)) {
    throw new Error('review artifact recorded collections are malformed')
  }
  const isPreflightIssue = (issue) => isObject(issue) && isString(issue.code) && isString(issue.message) && (issue.role == null || isString(issue.role))
  const isPreflight = (item) => isObject(item)
    && isOneOf(item.check, checks)
    && isOneOf(item.status, evidenceStatuses)
    && (item.actor_role == null || isString(item.actor_role))
    && Number.isSafeInteger(item.issue_count) && item.issue_count >= 0
    && (item.issues == null ? item.issue_count === 0 : Array.isArray(item.issues) && item.issues.length === item.issue_count && item.issues.every(isPreflightIssue))
    && isObject(item.coverage)
    && isOneOf(item.coverage.kind, ['complete', 'targeted'])
    && Array.isArray(item.coverage.checks_performed) && item.coverage.checks_performed.every((check) => isOneOf(check, evidenceChecks))
    && Array.isArray(item.coverage.checked_change_indices)
    && Array.isArray(item.coverage.unchecked_change_indices)
    && !(item.check === 'executor_authority' && item.coverage.kind === 'targeted' && item.status === 'passed')
  if (!value.preflight.every(isPreflight)) {
    throw new Error('review artifact preflight evidence is malformed')
  }
  const isOptionalString = (candidate) => candidate == null || isString(candidate)
  const isStringList = (candidate) => Array.isArray(candidate) && candidate.every(isString)
  const isPrivileges = (candidate) => Array.isArray(candidate) && candidate.every((privilege) => isOneOf(privilege, privileges))
  const isRoleState = (state) => isObject(state)
    && ['login', 'superuser', 'createdb', 'createrole', 'inherit', 'replication', 'bypassrls', 'comment_present'].every((field) => typeof state[field] === 'boolean')
    && Number.isSafeInteger(state.connection_limit)
    && isOptionalString(state.password_valid_until)
    && isStringList(state.config_parameters)
  const isRoleAttribute = (attribute) => {
    if (!isObject(attribute) || !isString(attribute.kind)) return false
    if (['login', 'superuser', 'createdb', 'createrole', 'inherit', 'replication', 'bypassrls'].includes(attribute.kind)) return typeof attribute.value === 'boolean'
    if (attribute.kind === 'connection_limit') return Number.isSafeInteger(attribute.value)
    if (attribute.kind === 'valid_until') return isOptionalString(attribute.value)
    return ['set_config', 'reset_config'].includes(attribute.kind) && isString(attribute.parameter)
  }
  const isScope = (scope) => isObject(scope) && ((scope.type === 'global' && Object.keys(scope).length === 1) || (scope.type === 'schema' && isString(scope.schema)))
  const isReviewChange = (change) => {
    if (!isObject(change) || !isString(change.kind)) return false
    const named = () => isString(change.name)
    const privilegeChange = () => isString(change.role) && isPrivileges(change.privileges) && isOneOf(change.object_type, objectTypes) && isOptionalString(change.schema) && isOptionalString(change.name)
    const defaultPrivilege = () => isString(change.owner) && isScope(change.scope) && isOneOf(change.on_type, objectTypes) && isString(change.grantee) && isPrivileges(change.privileges)
    switch (change.kind) {
      case 'create_role': return named() && isRoleState(change.state)
      case 'create_schema': return named() && isOptionalString(change.owner)
      case 'alter_schema_owner': return named() && isString(change.owner)
      case 'ensure_schema_owner_privileges': return named() && isString(change.owner) && isPrivileges(change.privileges)
      case 'alter_role': return named() && Array.isArray(change.attributes) && change.attributes.every(isRoleAttribute)
      case 'set_comment': return named() && typeof change.comment_present === 'boolean'
      case 'grant': return privilegeChange()
      case 'revoke': return privilegeChange() && isOptionalString(change.grantor)
      case 'set_default_privilege':
      case 'revoke_default_privilege': return defaultPrivilege()
      case 'add_member': return isString(change.role) && isString(change.member) && typeof change.inherit === 'boolean' && typeof change.admin === 'boolean'
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
    if (key.kind === 'grant') return isString(key.role) && isOneOf(key.object_type, objectTypes) && isOptionalString(key.schema) && isOptionalString(key.name)
    if (key.kind === 'default_privilege') return isString(key.owner) && isScope(key.scope) && isOneOf(key.on_type, objectTypes) && isString(key.grantee)
    return key.kind === 'membership' && isString(key.role) && isString(key.member)
  }
  const isOmission = (omission) => isObject(omission) && isString(omission.field) && omission.reason === 'sensitive_value'
  if (!value.recorded.changes.every((entry) => isObject(entry) && Number.isSafeInteger(entry.index) && entry.index >= 0 && isOneOf(entry.priority, priorities) && isReviewChange(entry.change) && (entry.source == null || isSource(entry.source)) && (entry.omissions == null || (Array.isArray(entry.omissions) && entry.omissions.every(isOmission))))) {
    throw new Error('review artifact changes are malformed')
  }
  const changeIndices = new Set(value.recorded.changes.map((entry) => entry.index))
  const contiguousIndices = value.recorded.changes.every((entry, index) => entry.index === index)
  const isReachability = (entry) => isObject(entry) && isString(entry.role) && isOneOf(entry.status, reachabilityStatuses)
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
  const orderedPhaseIndices = value.recorded.phases.flatMap((phase) => Array.isArray(phase?.change_indices) ? phase.change_indices : [])
  const phasePartition = orderedPhaseIndices.length === value.recorded.changes.length && orderedPhaseIndices.every((index, position) => index === position)
  if (!contiguousIndices || changeIndices.size !== value.recorded.changes.length || (value.recorded.changes.length > 0 && value.recorded.phases.length === 0) || !phasePartition || !value.recorded.phases.every((phase) => isObject(phase) && isOneOf(phase.phase, phases) && Array.isArray(phase.change_indices) && phase.change_indices.every((index) => Number.isSafeInteger(index) && changeIndices.has(index)) && Array.isArray(phase.executor_reachability) && phase.executor_reachability.every(isReachability) && Array.isArray(phase.executor_usage) && phase.executor_usage.every(isReachability))) {
    throw new Error('review artifact phases are malformed')
  }
  if (!value.recorded.findings.every((finding) => isObject(finding) && isString(finding.kind) && isOneOf(finding.severity, findingSeverities) && isString(finding.message) && (finding.phase == null || isOneOf(finding.phase, phases)) && (finding.change_index == null || changeIndices.has(finding.change_index)))) {
    throw new Error('review artifact findings are malformed')
  }
  if (!value.recorded.visual || !Array.isArray(value.recorded.visual.nodes) || !Array.isArray(value.recorded.visual.edges)) {
    throw new Error('review artifact visual graph is malformed')
  }
  if (!value.recorded.visual.nodes.every((node) => isObject(node) && isString(node.id) && isString(node.kind) && isString(node.label)) || !value.recorded.visual.edges.every((edge) => isObject(edge) && isString(edge.source) && isString(edge.target) && isString(edge.kind) && isString(edge.label))) {
    throw new Error('review artifact visual graph entries are malformed')
  }
  if (!hashPattern.test(value.recorded.review_fingerprint)) {
    throw new Error('review artifact fingerprint is malformed')
  }
  if (value.recorded.omissions != null && (!Array.isArray(value.recorded.omissions) || !value.recorded.omissions.every((omission) => isObject(omission) && isString(omission.field) && isString(omission.reason)))) {
    throw new Error('review artifact omissions are malformed')
  }
  if (!value.recorded.sql_preview || !['available', 'omitted'].includes(value.recorded.sql_preview.status)) {
    throw new Error('review artifact SQL preview is malformed')
  }
  if ((value.recorded.sql_preview.status === 'available' && !isString(value.recorded.sql_preview.sql)) || (value.recorded.sql_preview.status === 'omitted' && (value.recorded.sql_preview.reason !== 'sensitive_changes' || !Array.isArray(value.recorded.sql_preview.sensitive_change_indices) || !value.recorded.sql_preview.sensitive_change_indices.every((index) => changeIndices.has(index))))) {
    throw new Error('review artifact SQL preview content is malformed')
  }
  if (value.exploration.status !== 'omitted' || !['recorded_only_export', 'sensitive_inputs_removed'].includes(value.exploration.reason)) {
    throw new Error('review artifact exploration status is malformed')
  }
  return value
}
